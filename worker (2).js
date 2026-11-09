/**
 * ============================================================================
 * Free SERP API — v2.0.0 — Cloudflare Worker (search proxy)
 * ============================================================================
 *
 * ENDPOINT
 *   POST /api/v1/            (also accepts POST /api/v1 — trailing slash optional)
 *   OPTIONS /api/v1/         CORS preflight (browser clients)
 *
 * REQUEST BODY (application/json) — see OpenAPI 3.1 schema in project spec:
 *   {
 *     "request":        "quantum computing",        // required, 1..400 chars
 *     "lang":           "es",                        // optional, BCP-47-ish code
 *     "key":            "your-api-key",              // optional; only checked when REQUIRE_KEY=true
 *     "include_favicon": false,                      // optional, boolean, default false
 *     "result_number":  10                           // optional, integer 1..100, default 10
 *   }
 *   Unknown fields are ignored (open-world schema).
 *   Tolerated coercions (documented, deliberate): "result_number" given as a
 *   numeric string ("10") and "include_favicon" given as "true"/"false".
 *
 * RESPONSE 200 (application/json) — conforms to the OpenAPI schema:
 *   {
 *     "query": "...",                  // original query (trimmed)
 *     "translated_query": "...",       // only present when `lang` was sent
 *     "total_results": 50900,          // parsed from Bing "sb_count"
 *     "response_time_ms": 245,
 *     "request_id": "uuid",            // additive extension (ops correlation)
 *     "url_tree": [ { "category": "wikipedia.org", "subcategories": ["/wiki"] } ],
 *     "latency_info": {
 *       "inflight_time_ms": 210,       // queue wait + upstream fetch time
 *       "search_execution_ms": 180,    // upstream fetch time only
 *       "queue_wait_ms": 30,           // additive: time waiting for a concurrency slot
 *       "pages_fetched": 1,            // additive: Bing pages fetched (pagination)
 *       "parsing_ms": 4,               // additive: HTML parsing time
 *       "queue_depth": 0               // additive: requests currently queued (this isolate)
 *     },
 *     "results": [
 *       {
 *         "title": "...",
 *         "url": "https://en.wikipedia.org/wiki/Quantum_computing",  // decoded from /ck/a
 *         "snippet": "...",
 *         "favicon": "https://icons.duckduckgo.com/ip3/en.wikipedia.org.ico", // if include_favicon
 *         "quality": "Best"            // heuristic tier: Best|Better|Good|Mild|Subpar|Poor|Unknown
 *       }
 *     ]
 *   }
 *
 * ERROR ENVELOPE (all non-200):
 *   { "error": "<machine_code>", "message": "<human readable>", "details"?: {...} }
 *   400 invalid_body | invalid_json | missing_query | invalid_query | invalid_lang |
 *        invalid_key | invalid_include_favicon | invalid_result_number | out_of_range_result_number
 *   401 unauthorized                     — REQUIRE_KEY=true and key missing/invalid
 *   404 not_found                        — unknown route
 *   405 method_not_allowed               — non-POST/OPTIONS on /api/v1/
 *   413 payload_too_large                — body > MAX_BODY_BYTES
 *   415 unsupported_media_type           — Content-Type not JSON
 *   429 rate_limited                     — per-isolate per-IP limiter (disabled by default)
 *   500 server_misconfigured | internal_error
 *   502 upstream_error | upstream_empty  — Bing returned HTTP error
 *   502 upstream_changed                 — Bing layout changed (no results container)
 *   504 upstream_timeout | queue_timeout — fetch timeout / concurrency queue timeout
 *
 * ARCHITECTURE
 *   1. Router            — path + method + CORS preflight handling.
 *   2. Body & payload    — size/type guards, JSON parse, strict-but-tolerant validation.
 *   3. Auth              — REQUIRE_KEY flag (wrangler var, default "false" = OPEN endpoint)
 *                          + API_KEYS secret (comma-separated), SHA-256 constant-time compare.
 *   4. Concurrency queue — a module-scope FIFO semaphore admits at most
 *                          BING_MAX_CONCURRENCY (default 6) in-flight outbound GETs to Bing.
 *                          Excess POST requests wait in the queue (QUEUE_WAIT_TIMEOUT_MS)
 *                          and fail with 504 queue_timeout rather than thundering Bing.
 *                          NOTE (Workers execution model): module state is per-isolate.
 *                          The 6-slot guarantee holds per isolate; for a hard global
 *                          cap across isolates, wrap the same FairSemaphore in a
 *                          Durable Object (fetch() → this.limiter) — drop-in upgrade,
 *                          see "SCALING" note at the bottom of this file.
 *   5. Upstream client   — always requests https://www.bing.com/search?q=<q>&webscp=1
 *                          (+ setlang/mkt for localization, + first= for pagination),
 *                          with a CLEAN allowlisted header set: inbound Cloudflare
 *                          proxy headers (cf-*, x-forwarded-*, cdn-loop, true-client-ip,
 *                          cookie, ...) are never forwarded — they are stripped by
 *                          construction. Per-page timeout + one retry on 429/5xx.
 *   6. Parser            — layout-resilient, tiered strategies (see parseSerp):
 *                          tier A: <li class="b_algo"> blocks (primary, current Bing);
 *                          tier B: h2-anchor harvest anywhere (layout drift fallback);
 *                          tier C: container-missing => 502 upstream_changed (fails loud
 *                          instead of silently returning empty results).
 *                          Bing /ck/a tracking redirects are always decoded
 *                          (u=a1<base64url> -> clean destination URL).
 *
 * QUALITY HEURISTIC (documented, deterministic; enum per OpenAPI):
 *   position 1 -> Best, 2-3 -> Better, 4-6 -> Good, 7-10 -> Mild, >10 -> Subpar
 *   +1 tier for .gov/.edu/.mil/.int domains (cap Best)
 *   -1 tier for plain http:// (floor Poor) and for deep pagination pages (floor Poor)
 *   no snippet -> "Unknown"
 *
 * ============================================================================
 */

// ---------------------------------------------------------------------------
// Configuration & constants
// ---------------------------------------------------------------------------

const VERSION = "2.0.0";

const BING_ORIGIN = "https://www.bing.com";
const BING_SEARCH_PATH = "/search";

const LIMITS = {
  queryMaxChars: 400,
  keyMaxChars: 256,
  resultNumberMin: 1,
  resultNumberMax: 100,
  maxPagesHardCap: 10,        // never fetch more Bing pages than this per request
  minResultsPerPageGuess: 5,  // used to bound the pagination loop
  retryStatuses: [429, 500, 502, 503, 504],
  maxFetchAttempts: 2,        // 1 attempt + 1 retry
};

const QUALITY_TIERS = ["Poor", "Subpar", "Mild", "Good", "Better", "Best"];

/**
 * Outbound header allowlist. Everything else (in particular all Cloudflare /
 * proxy headers attached to the inbound request) is stripped by construction:
 * the outbound Headers object is built from this map only.
 * `Accept-Encoding` is deliberately NOT set — the Workers runtime negotiates
 * compression itself and transparently decompresses `res.text()`.
 * `Sec-Fetch-*` headers are deliberately omitted: they are runtime-restricted
 * on some fetch implementations and provide little scraping benefit.
 */
const OUTBOUND_HEADER_ALLOWLIST = {
  "user-agent":
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  accept:
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
  "cache-control": "no-cache",
  pragma: "no-cache",
  dnt: "1",
  "upgrade-insecure-requests": "1",
};

/** Never read (except the rate-limit key), never echoed, never forwarded. */
const STRIP_INBOUND = [
  "cf-connecting-ip", "cf-ipcountry", "cf-ray", "cf-visitor", "cf-worker",
  "cf-access-client-id", "x-forwarded-for", "x-forwarded-proto",
  "x-forwarded-host", "x-real-ip", "true-client-ip", "cdn-loop",
  "cookie", "authorization",
];

/** Defensive check: these must never appear in the outbound header map. */
const FORBIDDEN_OUTBOUND = [
  ...STRIP_INBOUND, "host", "content-length", "transfer-encoding",
  "connection", "accept-encoding", "sec-fetch-site", "sec-fetch-mode",
];

/** Common language code -> Bing market (improves localization of results). */
const LANG_TO_MKT = {
  en: "en-US", es: "es-ES", fr: "fr-FR", de: "de-DE", it: "it-IT",
  pt: "pt-PT", nl: "nl-NL", ru: "ru-RU", ja: "ja-JP", ko: "ko-KR",
  zh: "zh-CN", ar: "ar-SA", hi: "hi-IN", bn: "bn-BD", tr: "tr-TR",
  pl: "pl-PL", sv: "sv-SE", da: "da-DK", fi: "fi-FI", no: "nb-NO",
  nb: "nb-NO", cs: "cs-CZ", el: "el-GR", he: "he-IL", th: "th-TH",
  vi: "vi-VN", id: "id-ID", uk: "uk-UA", ro: "ro-RO", hu: "hu-HU",
  ms: "ms-MY", fa: "fa-IR", ur: "ur-PK",
};

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

const utf8Encoder = new TextEncoder();
const utf8Decoder = new TextDecoder("utf-8");

const nowMs = () => Date.now();
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Parse a wrangler var (always a string) into an integer with a default. */
function intVal(value, fallback) {
  const n = parseInt(String(value ?? "").trim(), 10);
  return Number.isFinite(n) ? n : fallback;
}

/** Interpret wrangler vars as booleans ("true"/"1", case-insensitive). */
function isTruthy(value) {
  return value === true || /^(true|1)$/i.test(String(value ?? "").trim());
}

function newRequestId() {
  try {
    return crypto.randomUUID();
  } catch {
    return `rid-${Math.random().toString(36).slice(2)}${Date.now().toString(36)}`;
  }
}

/** JSON response with security + CORS headers (never echoes upstream headers). */
function jsonResponse(status, body, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      ...extraHeaders,
    },
  });
}

/** Controlled, schema-shaped error. Thrown anywhere, mapped once in the router. */
class HttpError extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.name = "HttpError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

// ---------------------------------------------------------------------------
// HTML helpers (entities, tags, base64url)
// ---------------------------------------------------------------------------

const NAMED_ENTITIES = {
  amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: "\u00A0",
};

/** Minimal, dependency-free HTML entity decoder (&amp; &lt; &#39; &#x27; ...). */
function decodeEntities(str) {
  if (!str) return "";
  return str.replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]*);/g, (all, entity) => {
    if (entity[0] === "#") {
      const code =
        entity[1] === "x" || entity[1] === "X"
          ? parseInt(entity.slice(2), 16)
          : parseInt(entity.slice(1), 10);
      return Number.isInteger(code) && code > 0 && code <= 0x10ffff
        ? String.fromCodePoint(code)
        : all;
    }
    const name = entity.toLowerCase();
    return Object.prototype.hasOwnProperty.call(NAMED_ENTITIES, name)
      ? NAMED_ENTITIES[name]
      : all;
  });
}

/** Remove tags, then decode entities, then collapse whitespace. */
function stripTags(html) {
  if (!html) return "";
  return decodeEntities(String(html).replace(/<[^>]*>/g, " "))
    .replace(/\s+/g, " ")
    .trim();
}

/** base64url -> UTF-8 string (Workers + Node compatible). */
function b64urlDecode(input) {
  let b64 = input.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) b64 += "=";
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return utf8Decoder.decode(bytes);
}

/** Extract a double- or single-quoted attribute value from a tag string. */
function attrValue(tag, name) {
  const m = new RegExp(`\\b${name}\\s*=\\s*"([^"]*)"`, "i").exec(tag) ||
    new RegExp(`\\b${name}\\s*=\\s*'([^']*)'`, "i").exec(tag);
  return m ? m[1] : null;
}

// ---------------------------------------------------------------------------
// Bing tracking-redirect decoding (/ck/a?...&u=a1<base64url> -> clean URL)
// ---------------------------------------------------------------------------

/**
 * Decode Bing tracking links of the shape
 *   https://www.bing.com/ck/a?!&&p=...&u=a1aHR0cHM6Ly9leGFtcGxlLmNvbS8...&ntb=1
 * into their clean destination URL. The `u` parameter is a version prefix
 * ("a1") followed by the base64url-encoded target URL.
 *
 * Failure policy: NEVER throw — if anything is undecodable the original href
 * is returned so callers can still filter/skip it downstream.
 */
function decodeBingRedirect(href) {
  if (!href || typeof href !== "string") return "";
  let h = href.trim().replace(/&amp;/g, "&");
  if (!/\/ck\/[a-z]\?/i.test(h)) return h; // not a tracking redirect
  try {
    const u = new URL(h, BING_ORIGIN);
    const raw = u.searchParams.get("u") || "";
    const m = /^a\d(.+)$/s.exec(raw);
    if (!m) return h;
    let decoded = b64urlDecode(m[1]);
    if (/^https?%3a%2f%2f/i.test(decoded)) {
      try { decoded = decodeURIComponent(decoded); } catch { /* keep as-is */ }
    }
    if (/^https?:\/\//i.test(decoded)) return decoded;
    return h; // decoded to something unexpected — keep original
  } catch {
    return h;
  }
}

// ---------------------------------------------------------------------------
// CORS
// ---------------------------------------------------------------------------

/**
 * CORS policy.
 *   ALLOWED_ORIGINS = "*"  -> Access-Control-Allow-Origin: * (default; the
 *                             endpoint is open, REQUIRE_KEY defaults to off)
 *   ALLOWED_ORIGINS = "https://a.com,https://b.com" -> echo only listed origins.
 * Origins not on the list receive no ACAO header (browsers block; server-side
 * clients are unaffected).
 */
function corsHeaders(env, request) {
  const conf = String(env.ALLOWED_ORIGINS || "*").trim();
  const headers = {
    "access-control-allow-methods": "POST, OPTIONS",
    "access-control-allow-headers": "Content-Type",
    "access-control-max-age": "86400",
  };
  if (conf === "*") {
    headers["access-control-allow-origin"] = "*";
  } else {
    const list = conf.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
    const origin = (request?.headers?.get("origin") || "").trim();
    if (origin && list.includes(origin.toLowerCase())) {
      headers["access-control-allow-origin"] = origin;
      headers["vary"] = "Origin";
    }
  }
  return headers;
}

// ---------------------------------------------------------------------------
// Authentication (REQUIRE_KEY flag + API_KEYS secret)
// ---------------------------------------------------------------------------

/**
 * Constant-time-ish string comparison: hash both sides with SHA-256 first so
 * the compared byte strings always have equal length, then XOR-accumulate.
 * Works identically on Workers and Node.
 */
async function safeEqualStrings(a, b) {
  const subtle = globalThis.crypto?.subtle;
  const toHex = async (s) => {
    const digest = await subtle.digest("SHA-256", utf8Encoder.encode(s));
    return [...new Uint8Array(digest)]
      .map((x) => x.toString(16).padStart(2, "0"))
      .join("");
  };
  if (subtle) {
    const [ha, hb] = await Promise.all([toHex(a), toHex(b)]);
    let diff = 0;
    for (let i = 0; i < ha.length; i++) diff |= ha.charCodeAt(i) ^ hb.charCodeAt(i);
    return diff === 0;
  }
  // Fallback (should not be reachable on Workers/Node >= 18)
  const ea = utf8Encoder.encode(a), eb = utf8Encoder.encode(b);
  if (ea.length !== eb.length) return false;
  let diff = 0;
  for (let i = 0; i < ea.length; i++) diff |= ea[i] ^ eb[i];
  return diff === 0;
}

/**
 * Enforce authentication when REQUIRE_KEY is truthy ("true"/"1" — wrangler
 * [vars] are strings). Keys live in the API_KEYS secret, comma-separated:
 *   wrangler secret put API_KEYS     ->  "alpha-key,beta-key"
 */
async function checkAuth(env, key) {
  if (!isTruthy(env.REQUIRE_KEY)) return; // open endpoint (default)
  const validKeys = String(env.API_KEYS || "")
    .split(",").map((s) => s.trim()).filter(Boolean);
  if (validKeys.length === 0) {
    throw new HttpError(
      500, "server_misconfigured",
      "REQUIRE_KEY is enabled but no API_KEYS secret is configured. Run: wrangler secret put API_KEYS"
    );
  }
  if (!key) {
    throw new HttpError(401, "unauthorized",
      "Missing API key. Provide it in the 'key' field of the JSON request body.");
  }
  let ok = false;
  for (const candidate of validKeys) {
    if (await safeEqualStrings(candidate, key)) { ok = true; break; }
  }
  if (!ok) throw new HttpError(401, "unauthorized", "Invalid API key.");
}

// ---------------------------------------------------------------------------
// Optional per-isolate rate limiting (disabled by default: RATE_LIMIT_PER_MINUTE=0)
// ---------------------------------------------------------------------------

const rateBuckets = new Map(); // clientIp -> { windowStart, count }

function checkRateLimit(env, request) {
  const perMinute = intVal(env.RATE_LIMIT_PER_MINUTE, 0);
  if (perMinute <= 0) return;
  const ip = (request.headers.get("cf-connecting-ip") || "unknown").slice(0, 64);
  const windowMs = 60_000;
  const now = nowMs();
  let bucket = rateBuckets.get(ip);
  if (!bucket || now - bucket.windowStart >= windowMs) {
    bucket = { windowStart: now, count: 0 };
  }
  bucket.count += 1;
  rateBuckets.set(ip, bucket);
  if (rateBuckets.size > 10_000) { // crude memory guard: evict expired buckets
    for (const [k, v] of rateBuckets) {
      if (now - v.windowStart >= windowMs) rateBuckets.delete(k);
    }
  }
  if (bucket.count > perMinute) {
    throw new HttpError(429, "rate_limited",
      `Rate limit exceeded (${perMinute} requests/minute). Retry shortly.`);
  }
}

// ---------------------------------------------------------------------------
// Concurrency queue — at most BING_MAX_CONCURRENCY (6) in-flight Bing GETs
// ---------------------------------------------------------------------------

/**
 * FIFO semaphore. `acquire()` resolves as soon as a slot is free; requests
 * beyond the limit wait in strict arrival order. Waiters can be cancelled:
 *   - parentSignal aborted  (client disconnected)  -> rejects AbortError
 *   - timeoutMs elapsed                          -> rejects HttpError(504, queue_timeout)
 * A released slot is handed directly to the head of the queue (no lock convoys).
 */
class FairSemaphore {
  constructor(limit) {
    if (!Number.isInteger(limit) || limit < 1) {
      throw new Error(`FairSemaphore: limit must be a positive integer, got ${limit}`);
    }
    this.limit = limit;
    this.active = 0;
    this.waiters = [];
  }

  depth() {
    return this.waiters.length;
  }

  acquire(parentSignal, timeoutMs) {
    if (this.active < this.limit) {
      this.active += 1;
      return Promise.resolve(this._makeHandle());
    }
    return new Promise((resolve, reject) => {
      const waiter = { resolve, reject, done: false, timer: null, onAbort: null, parentSignal: parentSignal || null };
      const settle = (fn, value) => {
        if (waiter.done) return;
        waiter.done = true;
        if (waiter.timer) clearTimeout(waiter.timer);
        if (waiter.onAbort && parentSignal) {
          parentSignal.removeEventListener("abort", waiter.onAbort);
        }
        fn(value);
      };
      if (timeoutMs > 0) {
        waiter.timer = setTimeout(() => {
          const idx = this.waiters.indexOf(waiter);
          if (idx >= 0) this.waiters.splice(idx, 1);
          settle(reject, new HttpError(
            504, "queue_timeout",
            `Search queue is at capacity (${this.limit} concurrent upstream requests). Retry shortly.`
          ));
        }, timeoutMs);
      }
      if (parentSignal) {
        waiter.onAbort = () => {
          const idx = this.waiters.indexOf(waiter);
          if (idx >= 0) this.waiters.splice(idx, 1);
          const err = new Error("Client aborted while queued");
          err.name = "AbortError";
          settle(reject, err);
        };
        if (parentSignal.aborted) { waiter.onAbort(); return; }
        parentSignal.addEventListener("abort", waiter.onAbort, { once: true });
      }
      this.waiters.push(waiter);
    });
  }

  _detachWaiter(waiter) {
    if (waiter.timer) clearTimeout(waiter.timer);
    if (waiter.onAbort && waiter.parentSignal) {
      waiter.parentSignal.removeEventListener("abort", waiter.onAbort);
    }
    waiter.onAbort = null;
  }

  _makeHandle() {
    let released = false;
    return {
      release: () => {
        if (released) return;
        released = true;
        this._release();
      },
    };
  }

  _release() {
    const waiter = this.waiters.shift();
    if (waiter) {
      if (waiter.done) { this._release(); return; } // stale waiter (raced abort)
      waiter.done = true;
      this._detachWaiter(waiter);
      waiter.resolve(this._makeHandle()); // hand the slot straight over
      return;
    }
    this.active = Math.max(0, this.active - 1);
  }
}

/** One semaphore per configured limit (module scope = per-isolate lifetime). */
const limiterRegistry = new Map();

function getLimiter(limit) {
  const n = Math.max(1, Math.min(64, limit));
  let sem = limiterRegistry.get(n);
  if (!sem) {
    sem = new FairSemaphore(n);
    limiterRegistry.set(n, sem);
  }
  return sem;
}

// ---------------------------------------------------------------------------
// Bing request construction (URL + clean outbound headers)
// ---------------------------------------------------------------------------

function langToMkt(lang) {
  if (!lang) return null;
  if (/-/.test(lang)) return lang; // already market-shaped, e.g. "pt-BR"
  return LANG_TO_MKT[lang.toLowerCase()] || null;
}

function toAcceptLanguage(lang) {
  if (!lang) return "en-US,en;q=0.9";
  const mkt = langToMkt(lang);
  const primary = lang.split("-")[0].toLowerCase();
  return mkt ? `${mkt},${primary};q=0.9,en;q=0.5` : `${lang},${primary};q=0.9,en;q=0.5`;
}

/**
 * Build the upstream Bing SERP URL.
 *   https://www.bing.com/search?q={encoded query}&webscp=1[&setlang=..&mkt=..][&first=N]
 * `webscp=1` is ALWAYS appended (hard requirement of this spec).
 * `first` is the 1-based offset used for pagination when result_number > page size.
 */
function buildBingUrl(query, { lang, first } = {}) {
  const u = new URL(BING_ORIGIN + BING_SEARCH_PATH);
  u.searchParams.set("q", query);
  u.searchParams.set("webscp", "1");
  if (lang) {
    u.searchParams.set("setlang", lang);
    const mkt = langToMkt(lang);
    if (mkt) u.searchParams.set("mkt", mkt);
  }
  if (Number.isInteger(first) && first > 1) u.searchParams.set("first", String(first));
  return u.toString();
}

/**
 * Build the clean outbound header map. Built from scratch from an allowlist —
 * inbound proxy headers are stripped by construction. A defensive assertion
 * guarantees no forbidden header sneaks in.
 */
function buildBingHeaders(lang) {
  const headers = {
    ...OUTBOUND_HEADER_ALLOWLIST,
    "accept-language": toAcceptLanguage(lang),
    referer: BING_ORIGIN + "/",
  };
  for (const key of Object.keys(headers)) {
    if (FORBIDDEN_OUTBOUND.includes(key)) {
      throw new Error(`Refusing to send forbidden upstream header: ${key}`);
    }
  }
  return headers;
}

// ---------------------------------------------------------------------------
// Upstream client (slot acquisition + timeout + one retry)
// ---------------------------------------------------------------------------

/**
 * Fetch one Bing SERP page through the concurrency semaphore.
 * Returns { html, status, queueMs }.
 * Throws HttpError: 504 upstream_timeout | 502 upstream_error | 502 upstream_empty
 * (plus queue_timeout / AbortError propagated from acquire()).
 */
async function fetchBingPage(url, headers, parentSignal, env, limiter) {
  const fetchTimeoutMs = intVal(env.BING_FETCH_TIMEOUT_MS, 8000);
  const queueTimeoutMs = intVal(env.QUEUE_WAIT_TIMEOUT_MS, 10000);
  let attempt = 0;

  for (;;) {
    attempt += 1;
    const tAcquire = nowMs();
    const slot = await limiter.acquire(parentSignal, queueTimeoutMs);
    const queueMs = nowMs() - tAcquire;
    const tFetch = nowMs();
    let response;
    try {
      const controller = new AbortController();
      let timedOut = false;
      const timer = setTimeout(() => { timedOut = true; controller.abort(); }, fetchTimeoutMs);
      let onParentAbort = null;
      if (parentSignal) {
        if (parentSignal.aborted) controller.abort();
        else {
          onParentAbort = () => controller.abort();
          parentSignal.addEventListener("abort", onParentAbort, { once: true });
        }
      }
      try {
        response = await fetch(url, {
          method: "GET",
          headers,
          redirect: "follow",
          cache: "no-store",
          signal: controller.signal,
        });
        if (response.ok) {
          const html = await response.text();
          if (!html || html.length < 200) {
            throw new HttpError(502, "upstream_empty",
              "Bing returned an empty or truncated response body.");
          }
          return {
            html,
            status: response.status,
            queueMs,
            fetchMs: nowMs() - tFetch,
          };
        }
      } catch (err) {
        if (err instanceof HttpError) throw err;
        if (timedOut) {
          throw new HttpError(504, "upstream_timeout",
            `Bing request timed out after ${fetchTimeoutMs}ms.`);
        }
        throw err; // parent abort (client gone) or network error
      } finally {
        clearTimeout(timer);
        if (onParentAbort && parentSignal) {
          parentSignal.removeEventListener("abort", onParentAbort);
        }
      }
      // Non-OK upstream status: retryable statuses fall through to the
      // backoff sleep below (the slot is already released by then, so the
      // queue keeps flowing); everything else fails fast.
      const status = response.status;
      if (!(LIMITS.retryStatuses.includes(status) && attempt < LIMITS.maxFetchAttempts)) {
        throw new HttpError(502, "upstream_error",
          `Bing responded with HTTP ${status}.`, { upstream_status: status });
      }
    } finally {
      slot.release();
    }
    await sleep(200 * attempt); // small backoff, then re-acquire a slot
    continue;
  }
}

// ---------------------------------------------------------------------------
// SERP parser — layout-resilient, tiered strategies
// ---------------------------------------------------------------------------

const RE_STYLE_BLOCK = /<style\b[^>]*>[\s\S]*?<\/style>/gi;
const RE_RESULTS_CONTAINER = /<(?:ol|ul|div)\b[^>]*(?:id="b_results"|class="[^"]*\bb_results\b[^"]*")/i;
const RE_NO_RESULTS = /class="[^"]*\bb_no\b[^"]*"/;
const RE_CONSENT_WALL = /clkconsent|consent\.bing\.com/i;

/** "About 50,900 results" / "50.900 Ergebnisse" -> 50900 (longest digit run wins). */
function parseTotalResults(html) {
  const m = /<[a-z0-9]+\b[^>]*\bclass="[^"]*\bsb_count\b[^"]*"[^>]*>([\s\S]{0,300}?)<\//i
    .exec(html);
  if (!m) return null;
  const text = decodeEntities(m[1]).replace(/\u00A0/g, " ");
  const groups = text.match(/\d[\d.,\s\u00A0]*/g);
  if (!groups) return null;
  let best = "";
  for (const g of groups) {
    if (g.replace(/\D/g, "").length > best.replace(/\D/g, "").length) best = g;
  }
  const n = parseInt(best.replace(/\D/g, ""), 10);
  return Number.isFinite(n) ? n : null;
}

/** Snippet extraction: paragraphs with known snippet classes first, then longest paragraph. */
function parseSnippet(blockBody) {
  const paragraphs = [...blockBody.matchAll(/<p\b([^>]*)>([\s\S]{0,2500}?)<\/p>/gi)]
    .map((m) => ({ attrs: m[1], text: stripTags(m[2]) }))
    .filter((p) => p.text.length >= 10);
  if (paragraphs.length === 0) return "";
  for (const marker of ["b_algoSlug", "b_paractr", "b_snippet", "b_lineclamp"]) {
    const hit = paragraphs.find((p) =>
      new RegExp(`\\b${marker}\\b`).test(p.attrs));
    if (hit) return hit.text;
  }
  const pool = paragraphs.filter((p) => !/\bb_factrow\b|\bb_attribution\b/.test(p.attrs));
  const candidates = pool.length ? pool : paragraphs;
  return candidates.reduce((a, b) => (b.text.length > a.text.length ? b : a)).text;
}

/** Favicon: img.rms_img / div.cico img from Bing markup, else DuckDuckGo icon service. */
function parseFavicon(blockBody, fallbackHost) {
  const imgTag =
    /<img\b[^>]*\bclass="[^"]*\brms_img\b[^"]*"[^>]*>/i.exec(blockBody)?.[0] ||
    /class="[^"]*\bcico\b[^"]*"[^>]*>\s*<img\b[^>]*>/i.exec(blockBody)?.[0];
  let src = imgTag
    ? (attrValue(imgTag, "src") || attrValue(imgTag, "data-src"))
    : null;
  if (src) {
    src = decodeEntities(src).trim();
    if (/^https?:\/\//i.test(src)) return src;
    if (src.startsWith("/")) return BING_ORIGIN + src;
  }
  return `https://icons.duckduckgo.com/ip3/${fallbackHost}.ico`;
}

function safeHost(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch { return null; }
}

/** Dedup key: host (www-stripped) + path (trailing-slash-stripped) + query. */
function normalizeUrlKey(url) {
  try {
    const u = new URL(url);
    return u.hostname.replace(/^www\./, "").toLowerCase() +
      u.pathname.replace(/\/+$/, "") + u.search;
  } catch {
    return url;
  }
}

function isInternalBingUrl(url) {
  const host = safeHost(url);
  return !host || /(^|\.)bing\.com$/i.test(host);
}

/** Parse a single <li class="b_algo"> block. Returns null when not a usable result. */
function parseResultBlock(blockHtml, includeFavicon) {
  const body = blockHtml.replace(RE_STYLE_BLOCK, " ");

  // --- Title + URL. Prefer the h2 anchor (the .tilk site-line anchor that
  // --- appears FIRST in modern blocks carries the site name, not the title).
  let href = null;
  let title = null;
  const h2 = /<h2\b[^>]*>([\s\S]*?)<\/h2>/i.exec(body);
  if (h2) {
    const a = /<a\b([^>]*)>([\s\S]{2,600}?)<\/a>/i.exec(h2[1]);
    if (a) { href = attrValue(a[1], "href"); title = stripTags(a[2]); }
  }
  if (!href) {
    const bTitle = /<div\b[^>]*\bclass="[^"]*\bb_title\b[^"]*"[^>]*>([\s\S]{0,2000}?)<\/div>/i
      .exec(body);
    if (bTitle) {
      const a = /<a\b([^>]*)>([\s\S]{2,600}?)<\/a>/i.exec(bTitle[1]);
      if (a) { href = attrValue(a[1], "href"); title = stripTags(a[2]); }
    }
  }
  if (!href) {
    // Last resort within the block: the anchor with the longest visible text.
    let best = null;
    for (const m of body.matchAll(/<a\b([^>]*)>([\s\S]{2,400}?)<\/a>/gi)) {
      const h = attrValue(m[1], "href");
      const t = stripTags(m[2]);
      if (!h || t.length < 3) continue;
      if (!best || t.length > best.title.length) best = { href: h, title: t };
    }
    if (best) { href = best.href; title = best.title; }
  }
  if (!href || !title) return null;

  const url = decodeBingRedirect(href);
  if (!/^https?:\/\//i.test(url)) return null;   // internal/relative link
  if (isInternalBingUrl(url)) return null;       // bing.com self-references
  if (title.length > 400) title = title.slice(0, 400);

  const host = safeHost(url);
  const snippet = parseSnippet(body);
  const favicon = includeFavicon ? parseFavicon(body, host) : undefined;

  return {
    title,
    url,
    snippet,
    ...(favicon ? { favicon } : {}),
    quality: "Unknown", // assigned positionally by parseSerp()
  };
}

/** Layout-drift fallback: harvest h2 anchors anywhere in the document. */
function parseLoose(html, seen, includeFavicon, wanted) {
  const out = [];
  for (const m of html.matchAll(/<h2\b[^>]*>([\s\S]*?)<\/h2>/gi)) {
    if (out.length >= wanted) break;
    const a = /<a\b([^>]*)>([\s\S]{2,400}?)<\/a>/i.exec(m[1]);
    if (!a) continue;
    const href = attrValue(a[1], "href");
    if (!href) continue;
    const url = decodeBingRedirect(href);
    if (!/^https?:\/\//i.test(url) || isInternalBingUrl(url)) continue;
    const title = stripTags(a[2]);
    if (title.length < 3) continue;
    const key = normalizeUrlKey(url);
    if (seen.has(key)) continue;
    seen.add(key);
    const host = safeHost(url);
    out.push({
      title,
      url,
      snippet: "",
      ...(includeFavicon ? { favicon: `https://icons.duckduckgo.com/ip3/${host}.ico` } : {}),
      quality: "Unknown",
    });
  }
  return out;
}

/** Deterministic quality tier (see header docs). */
function assignQuality(result, position, pageIdx) {
  if (!result.snippet || result.snippet.length < 10) return "Unknown";
  let tier = position === 1 ? 5
    : position <= 3 ? 4
    : position <= 6 ? 3
    : position <= 10 ? 2
    : 1;
  try {
    const host = new URL(result.url).hostname.toLowerCase();
    if (/\.(gov|edu|mil|int)$/.test(host)) tier = Math.min(5, tier + 1);
    if (result.url.startsWith("http://")) tier = Math.max(0, tier - 1);
  } catch { /* unreachable — url already validated */ }
  // Deep-pagination demotion (weaker matches on page 2+), but never stacks
  // with the position penalty below Subpar.
  if (pageIdx >= 1 && tier > 1) tier -= 1;
  return QUALITY_TIERS[Math.max(0, Math.min(5, tier))];
}

/**
 * Parse one Bing SERP page.
 * opts: { seen, includeFavicon, wanted, startIndex, pageIdx }
 * Returns { results, totalResults, containerFound, rawBlocks, noResults }.
 *
 * Tier A: li.b_algo blocks (current Bing layout — verified against a real
 *         2026 SERP capture; tolerates nested <style>, multi-class attrs,
 *         .tilk site-lines, b_lineclamp snippets).
 * Tier B: zero b_algo found but container present -> loose h2 harvest.
 * Tier C: container missing entirely -> containerFound=false; the caller
 *         fails loud with 502 upstream_changed instead of returning fake
 *         empty results.
 */
function parseSerp(html, opts = {}) {
  const seen = opts.seen || new Set();
  const includeFavicon = !!opts.includeFavicon;
  const wanted = opts.wanted || Infinity;
  const startIndex = opts.startIndex || 0;
  const pageIdx = opts.pageIdx || 0;

  const totalResults = parseTotalResults(html);
  const containerFound = RE_RESULTS_CONTAINER.test(html);
  const results = [];
  let rawBlocks = 0;

  if (containerFound) {
    for (const m of html.matchAll(/<li\b[^>]*\bclass="([^"]*)"[^>]*>([\s\S]*?)<\/li>/gi)) {
      const cls = m[1];
      if (!/\bb_algo\b/.test(cls)) continue;
      if (/\bb_ad\b|\bsb_ad\b/.test(cls)) continue; // ads / sponsored
      rawBlocks += 1;
      if (results.length >= wanted) continue;
      const r = parseResultBlock(m[2], includeFavicon);
      if (!r) continue;
      const key = normalizeUrlKey(r.url);
      if (seen.has(key)) continue;
      seen.add(key);
      r.quality = assignQuality(r, startIndex + results.length + 1, pageIdx);
      results.push(r);
    }
    if (rawBlocks === 0) {
      for (const r of parseLoose(html, seen, includeFavicon, wanted)) {
        results.push(r); // degraded mode: quality stays "Unknown"
      }
    }
  }

  return {
    results,
    totalResults,
    containerFound,
    rawBlocks,
    noResults: RE_NO_RESULTS.test(html),
    consentWall: RE_CONSENT_WALL.test(html) && !containerFound,
  };
}

/** Registrable domain (pragmatic public-suffix handling for url_tree grouping). */
function registrableDomain(hostname) {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  const labels = host.split(".");
  if (labels.length <= 2) return host;
  const SECOND_LEVEL_SUFFIXES = new Set([
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "ne.jp", "or.jp", "ac.jp",
    "com.au", "net.au", "org.au", "com.br", "com.cn", "com.mx", "co.in",
    "co.nz", "co.za", "com.sg", "com.tr", "com.ar", "com.pl", "com.tw",
  ]);
  const lastTwo = labels.slice(-2).join(".");
  if (SECOND_LEVEL_SUFFIXES.has(lastTwo) && labels.length >= 3) {
    return labels.slice(-3).join(".");
  }
  return lastTwo;
}

/** url_tree: domain breakdown of the result set (OpenAPI "query domain breakdown"). */
function buildUrlTree(results, maxCategories = 5) {
  const byHost = new Map(); // registrable domain -> Map(pathSegment -> count)
  for (const r of results) {
    let domain, segment;
    try {
      const u = new URL(r.url);
      domain = registrableDomain(u.hostname);
      segment = "/" + (u.pathname.split("/").filter(Boolean)[0] || "");
    } catch { continue; }
    if (!byHost.has(domain)) byHost.set(domain, new Map());
    const segs = byHost.get(domain);
    segs.set(segment, (segs.get(segment) || 0) + 1);
  }
  const total = (segs) => [...segs.values()].reduce((a, b) => a + b, 0);
  return [...byHost.entries()]
    .sort((a, b) => total(b[1]) - total(a[1]) || a[0].localeCompare(b[0]))
    .slice(0, maxCategories)
    .map(([domain, segs]) => ({
      category: domain,
      subcategories: [...segs.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 6)
        .map(([s]) => s),
    }));
}

// ---------------------------------------------------------------------------
// Request-body validation (OpenAPI-shaped, strict with documented coercions)
// ---------------------------------------------------------------------------

function validatePayload(raw, env) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new HttpError(400, "invalid_body", "Request body must be a JSON object.");
  }

  // request (required)
  if (typeof raw.request !== "string") {
    throw new HttpError(400, "invalid_request",
      "'request' is required and must be a string.");
  }
  const query = raw.request.trim();
  if (!query) {
    throw new HttpError(400, "missing_query", "'request' must not be empty.");
  }
  if (query.length > LIMITS.queryMaxChars) {
    throw new HttpError(400, "invalid_query",
      `'request' must be at most ${LIMITS.queryMaxChars} characters.`);
  }

  // lang (optional)
  let lang;
  if (raw.lang !== undefined && raw.lang !== null && raw.lang !== "") {
    if (typeof raw.lang !== "string" ||
        !/^[a-z]{2,3}(?:[-_][a-z0-9]{2,8})?$/i.test(raw.lang)) {
      throw new HttpError(400, "invalid_lang",
        "'lang' must be a language code such as 'es', 'fr', 'ja' or 'pt-BR'.");
    }
    lang = raw.lang.replace("_", "-");
  }

  // key (optional)
  let key;
  if (raw.key !== undefined && raw.key !== null && raw.key !== "") {
    if (typeof raw.key !== "string" || raw.key.length > LIMITS.keyMaxChars) {
      throw new HttpError(400, "invalid_key", "'key' must be a string (max 256 chars).");
    }
    key = raw.key;
  }

  // include_favicon (optional, default false; "true"/"false" tolerated)
  let includeFavicon = false;
  if (raw.include_favicon !== undefined && raw.include_favicon !== null) {
    const v = raw.include_favicon;
    if (typeof v === "boolean") includeFavicon = v;
    else if (v === "true") includeFavicon = true;
    else if (v === "false") includeFavicon = false;
    else {
      throw new HttpError(400, "invalid_include_favicon",
        "'include_favicon' must be a boolean.");
    }
  }

  // result_number (optional, default 10; numeric string tolerated)
  let resultNumber = 10;
  if (raw.result_number !== undefined && raw.result_number !== null) {
    let v = raw.result_number;
    if (typeof v === "string" && /^-?\d+$/.test(v.trim())) v = parseInt(v.trim(), 10);
    if (typeof v !== "number" || !Number.isInteger(v)) {
      throw new HttpError(400, "invalid_result_number",
        "'result_number' must be an integer between 1 and 100.");
    }
    const max = Math.max(LIMITS.resultNumberMin,
      Math.min(LIMITS.resultNumberMax, intVal(env.MAX_RESULT_NUMBER, 100)));
    if (v < LIMITS.resultNumberMin || v > max) {
      throw new HttpError(400, "out_of_range_result_number",
        `'result_number' must be between ${LIMITS.resultNumberMin} and ${max}.`);
    }
    resultNumber = v;
  }

  return { query, lang, key, includeFavicon, resultNumber };
}

// ---------------------------------------------------------------------------
// Search orchestration (pagination + telemetry)
// ---------------------------------------------------------------------------

/**
 * Run the full search: paginate Bing until `resultNumber` unique results are
 * collected (or Bing runs dry). Every upstream GET goes through the 6-slot
 * concurrency queue. Returns everything needed for the OpenAPI response body.
 */
async function searchBing(payload, env, signal) {
  const limiter = getLimiter(intVal(env.BING_MAX_CONCURRENCY, 6));
  const headers = buildBingHeaders(payload.lang);

  const seen = new Set();
  const collected = [];
  const timing = { queueWaitMs: 0, fetchMs: 0, parseMs: 0, pages: 0 };
  let totalResults = null;
  let first = 1;
  let pageIdx = 0;
  const maxPages = Math.min(
    Math.ceil(payload.resultNumber / LIMITS.minResultsPerPageGuess),
    intVal(env.MAX_PAGES, LIMITS.maxPagesHardCap)
  );

  while (collected.length < payload.resultNumber && pageIdx < maxPages) {
    const url = buildBingUrl(payload.query, { lang: payload.lang, first });

    let page;
    try {
      page = await fetchBingPage(url, headers, signal, env, limiter);
    } catch (err) {
      if (err instanceof HttpError && err.code === "upstream_empty") {
        if (pageIdx === 0) throw err;
        break; // later page came back empty — treat as exhaustion
      }
      throw err;
    }
    timing.queueWaitMs += page.queueMs;
    timing.fetchMs += page.fetchMs;
    timing.pages += 1;

    const tParse = nowMs();
    const parsed = parseSerp(page.html, {
      seen,
      includeFavicon: payload.includeFavicon,
      wanted: payload.resultNumber - collected.length,
      startIndex: collected.length,
      pageIdx,
    });
    timing.parseMs += nowMs() - tParse;

    if (totalResults === null && parsed.totalResults !== null) {
      totalResults = parsed.totalResults; // first page's count wins
    }
    if (!parsed.containerFound) {
      if (parsed.consentWall) {
        throw new HttpError(502, "upstream_blocked",
          "Bing served a consent/interstitial page instead of results.");
      }
      throw new HttpError(502, "upstream_changed",
        "Bing returned an unexpected page layout (no results container). The parser may need an update.");
    }

    let added = 0;
    for (const r of parsed.results) {
      if (collected.length >= payload.resultNumber) break;
      collected.push(r);
      added += 1;
    }
    if (parsed.rawBlocks === 0 || added === 0) break; // exhausted or all dupes

    first += Math.max(parsed.rawBlocks, 1);
    pageIdx += 1;
  }

  return {
    results: collected,
    totalResults: totalResults ?? collected.length,
    urlTree: buildUrlTree(collected),
    queueDepth: limiter.depth(),
    timing,
  };
}

// ---------------------------------------------------------------------------
// Router — Worker entry point
// ---------------------------------------------------------------------------

function normalizePath(pathname) {
  if (pathname.length > 1 && pathname.endsWith("/")) {
    return pathname.slice(0, -1);
  }
  return pathname;
}

async function handleFetch(request, env = {}, _ctx = {}) {
  const t0 = nowMs();
  const requestId = newRequestId();
  const cors = corsHeaders(env, request);
  try {
    const { pathname } = new URL(request.url);
    if (normalizePath(pathname) !== "/api/v1") {
      return jsonResponse(404, {
        error: "not_found",
        message: `Unknown route '${pathname}'. Use POST /api/v1/.`,
      }, cors);
    }

    // CORS preflight (browsers POST with Content-Type: application/json)
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: { ...cors, allow: "POST, OPTIONS", "cache-control": "no-store" },
      });
    }

    if (request.method !== "POST") {
      return jsonResponse(405, {
        error: "method_not_allowed",
        message: `Method ${request.method} is not allowed. Use POST with a JSON body.`,
      }, { ...cors, allow: "POST, OPTIONS" });
    }

    checkRateLimit(env, request);

    // --- Body guards -------------------------------------------------------
    const maxBodyBytes = intVal(env.MAX_BODY_BYTES, 16384);
    const contentLength = parseInt(request.headers.get("content-length") || "0", 10);
    if (contentLength > maxBodyBytes) {
      throw new HttpError(413, "payload_too_large",
        `Request body exceeds ${maxBodyBytes} bytes.`);
    }
    const contentType = (request.headers.get("content-type") || "").toLowerCase();
    if (contentType && !contentType.includes("json")) {
      throw new HttpError(415, "unsupported_media_type",
        "Content-Type must be application/json.");
    }
    const text = await request.text();
    if (text.length > maxBodyBytes) {
      throw new HttpError(413, "payload_too_large",
        `Request body exceeds ${maxBodyBytes} bytes.`);
    }
    let raw;
    try {
      raw = JSON.parse(text);
    } catch {
      throw new HttpError(400, "invalid_json", "Request body is not valid JSON.");
    }

    // --- Validation + auth -------------------------------------------------
    const payload = validatePayload(raw, env);
    await checkAuth(env, payload.key);

    // --- Search ------------------------------------------------------------
    const search = await searchBing(payload, env, request.signal || undefined);
    const elapsed = nowMs() - t0;

    const body = {
      query: payload.query,
      ...(payload.lang ? { translated_query: payload.query } : {}),
      total_results: search.totalResults,
      response_time_ms: elapsed,
      request_id: requestId,
      url_tree: search.urlTree,
      latency_info: {
        inflight_time_ms: search.timing.queueWaitMs + search.timing.fetchMs,
        search_execution_ms: search.timing.fetchMs,
        queue_wait_ms: search.timing.queueWaitMs,
        pages_fetched: search.timing.pages,
        parsing_ms: search.timing.parseMs,
        queue_depth: search.queueDepth,
      },
      results: search.results,
    };

    console.log(
      `[serp] rid=${requestId} q="${payload.query.slice(0, 60)}"` +
      ` results=${search.results.length} pages=${search.timing.pages}` +
      ` queue_wait=${search.timing.queueWaitMs}ms fetch=${search.timing.fetchMs}ms` +
      ` total=${elapsed}ms status=200`
    );
    return jsonResponse(200, body, cors);
  } catch (err) {
    if (err instanceof HttpError) {
      console.warn(`[serp] rid=${requestId} status=${err.status} code=${err.code}`);
      return jsonResponse(err.status, {
        error: err.code,
        message: err.message,
        ...(err.details ? { details: err.details } : {}),
      }, cors);
    }
    const clientGone = err?.name === "AbortError" || request.signal?.aborted;
    if (clientGone) {
      // Client disconnected (or aborted while queued): nothing to deliver.
      return new Response(null, { status: 499 });
    }
    console.error(`[serp] rid=${requestId} internal error:`, err?.stack || err);
    return jsonResponse(500, {
      error: "internal_error",
      message: "An unexpected error occurred.",
      request_id: requestId,
    }, cors);
  }
}

// ---------------------------------------------------------------------------
// Exports — Worker entry point + pure functions for automated tests
// ---------------------------------------------------------------------------

export default { fetch: handleFetch };

export {
  VERSION,
  HttpError,
  validatePayload,
  checkAuth,
  safeEqualStrings,
  isTruthy,
  intVal,
  decodeEntities,
  stripTags,
  b64urlDecode,
  decodeBingRedirect,
  buildBingUrl,
  buildBingHeaders,
  langToMkt,
  toAcceptLanguage,
  parseSerp,
  parseResultBlock,
  parseSnippet,
  parseFavicon,
  parseTotalResults,
  buildUrlTree,
  assignQuality,
  normalizeUrlKey,
  searchBing,
  handleFetch,
};

/** Test-only surface: reset module-scope state between test cases. */
export const __internals = {
  FairSemaphore,
  getLimiter,
  limiterRegistry,
  rateBuckets,
  OUTBOUND_HEADER_ALLOWLIST,
  FORBIDDEN_OUTBOUND,
  STRIP_INBOUND,
  resetForTests() {
    limiterRegistry.clear();
    rateBuckets.clear();
  },
};

/*
 * ============================================================================
 * SCALING NOTE (global 6-slot guarantee)
 * ============================================================================
 * Cloudflare runs many isolates of a Worker in parallel; module-scope state is
 * shared only within one isolate. The FairSemaphore here therefore enforces
 * "at most 6 concurrent Bing GETs" per isolate, which in practice keeps the
 * aggregate rate well-behaved, but it is NOT a hard global cap.
 *
 * For a hard global cap, move the semaphore into a Durable Object:
 *
 *   // wrangler.toml:
 *   //   [[durable_objects.bindings]]
 *   //   name = "QUEUE"; class_name = "SearchQueue"
 *   //   [[migrations]]; tag = "v1"; new_sqlite_classes = ["SearchQueue"]
 *   //
 *   // export class SearchQueue {
 *   //   constructor(state) { this.state = state; this.sem = new FairSemaphore(6); }
 *   //   async fetch(req) { return handleFetch(req, req.env, null); } // same handler,
 *   // }                                                 // semaphore now DO-scoped
 *
 * and route fetchBingPage's acquire/release through `env.QUEUE.fetch(...)`.
 * Everything else in this file stays unchanged.
 * ============================================================================
 */
