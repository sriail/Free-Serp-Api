/**
 * ============================================================================
 *  free-serp-api — Cloudflare Worker (search proxy API)  ·  v1.1.0
 * ============================================================================
 *
 *  POST /api/v1/            → execute a search query (see README.md / openapi.yaml)
 *  POST /api/v1/search      → alias (also POST /search, for OpenAPI compatibility)
 *  GET  /api/v1/            → service info (key-required?, rate-limit, endpoints)
 *  GET  /api/v1/key-status  → minimal "environment key check"
 *  GET  /demo               → self-hosted browser test page (prints to console)
 *
 *  REQUEST BODY (application/json):
 *    {
 *      "is-stream":     false,          // required. true → paginated streaming protocol
 *      "stream-id":     "<cursor>",     // required on subsequent streaming requests
 *      "query":         "quantum computing", // required, 1..512 chars
 *      "results":       10,             // required, integer 1..100
 *      "lang":          "en-US",        // optional target language code (default env DEFAULT_LANG)
 *      "favicon":       false,          // optional: include favicon URL on every result
 *      "show-telemetry": false,         // optional: include shown-telemetry block
 *      "key":           "…"             // optional: only enforced when REQUIRE_KEY="true"
 *    }
 *
 *  RESPONSE 200:
 *    {
 *      "shown-telemetry": { "que-time", "in-flight", "parse-time", "total-time",
 *                           "time-grade": "A".."F", "ping" },          // only when requested
 *      "stream-id": "…", "has-more": true,                            // only when is-stream
 *      "stats": { "total-results": 50900 },
 *      "results": [ { "rank", "title", "url", "favicon?", "path?", "summary?" } ]
 *    }
 *
 *  ERRORS: JSON { "error": "<CODE>", "message": "…" } + response headers
 *          X-Error-Code / X-Failure-Reason / X-Request-Id on every error.
 *          400 validation · 401 auth · 404 route · 405 method · 413 payload size
 *          415 media type · 429 rate limit · 502 fetch/parse · 503 queue timeout · 500 internal
 *
 *  BING PIPELINE:
 *    · URL is always  https://www.bing.com/search?q=<encoded>&webscp=1[&count=&first=&setmkt=&setlang=]
 *      ("webscp=1" is unconditionally appended).
 *    · Outbound requests are built from scratch: no inbound CF/proxy headers are forwarded
 *      (cf-*, x-forwarded-*, cdn-loop, cookie, … are stripped — see STRIP_OUTBOUND_HEADERS),
 *      and browser-like headers (User-Agent, Accept, Accept-Language, Referer, …) are injected.
 *    · Outbound concurrency is capped at 6 simultaneous GETs to Bing (per isolate).
 *      Excess requests wait in a FIFO queue (max wait = env QUEUE_WAIT_MS, default 15 s)
 *      and time out with 503 QUEUE_TIMEOUT.
 *
 *  CONFIG (wrangler.toml [vars], all values are strings):
 *    REQUIRE_KEY   "false" (default) | "true"  → enforce `key` against KEY-1..KEY-n secrets
 *    RATE_LIMIT    "0" (default = unlimited) | "<n>" → client requests per minute per IP
 *    DEFAULT_LANG  "en-US"  ·  CORS_ORIGIN  "*" (or comma-separated exact origins)
 *    QUEUE_WAIT_MS "15000"  ·  UPSTREAM_TIMEOUT_MS "10000"   (optional overrides)
 *
 *  Secrets (never in wrangler.toml):  wrangler secret put KEY-1   (KEY-2, KEY-3, …)
 *
 *  This file is dependency-free, uses only standard Worker/JS APIs (no HTMLRewriter →
 *  the tiered-regex parser below also runs in Node 18+, which the offline test-suite
 *  exploits for automated validation). Named exports exist purely for testing/tooling;
 *  Cloudflare only consumes `export default { fetch }`.
 * ============================================================================
 */

/* ============================== entry point ============================== */

export default { fetch };

export {
  /* — testing / tooling exports (not used by the runtime router) — */
  Semaphore,
  scrubProxyHeaders,
  buildOutboundHeaders,
  buildBingUrl,
  validatePayload,
  authorize,
  timingSafeEqual,
  rateCheck,
  parseRateLimit,
  requireKeyFlag,
  encodeCursor,
  decodeCursor,
  b64UrlDecode,
  decodeBingRedirect,
  decodeEntities,
  cleanText,
  parseBingSerp,
  gradeFromMs,
  ApiError,
  __testHooks,
};

/* ================================ constants =============================== */

const VERSION = '1.1.0';

const BING_ORIGIN = 'https://www.bing.com';
const BING_SEARCH_PATH = '/search';

/** Maximum simultaneous outbound GETs to Bing (per isolate). */
const OUTBOUND_CONCURRENCY = 6;
/** Default max time a request may wait for a free Bing slot. */
const DEFAULT_QUEUE_WAIT_MS = 15_000;
/** Default per-attempt timeout for the Bing fetch. */
const DEFAULT_UPSTREAM_TIMEOUT_MS = 10_000;
/** Failed upstream attempts are retried once (2 attempts total). */
const UPSTREAM_RETRIES = 1;
const RETRY_DELAY_MS = 400;

/** Bing page size ceiling (count=). */
const PAGE_SIZE_MAX = 50;
/** Non-streaming requests may stitch up to this many Bing pages. */
const NONSTREAM_MAX_PAGES = 3;
/** Bing deep-paging ceiling for the `first` parameter. */
const BING_FIRST_MAX = 300;

const MAX_BODY_BYTES = 65_536;
const MAX_QUERY_CHARS = 512;
const RESULTS_MIN = 1;
const RESULTS_MAX = 100;

const RATE_WINDOW_MS = 60_000;
const RATE_BUCKETS_MAX = 5_000; // per-isolate memory hygiene

const GRADE_TABLE = [
  [400, 'A'],
  [800, 'B'],
  [1500, 'C'],
  [3000, 'D'],
];

const USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';

const LANG_RE = /^[A-Za-z]{2}(?:-[A-Za-z]{2,8})?$/; // case-insensitive input, normalized to xx / xx-XX / xx-Script
const STREAM_ID_RE = /^[A-Za-z0-9_-]+$/;
const CORS_ALLOW_HEADERS = ['content-type', 'x-client-sent-at'];
const CORS_EXPOSE_HEADERS = [
  'x-error-code',
  'x-failure-reason',
  'x-request-id',
  'x-rate-limit-limit',
  'x-rate-limit-remaining',
  'x-rate-limit-reset',
  'server-timing',
];

/**
 * Inbound/outbound header hygiene: none of these may ever reach Bing.
 * Cloudflare injects some of these on the *network* layer (outside JS control,
 * see README "Header hygiene"); this list guarantees application-level control.
 */
const STRIP_OUTBOUND_HEADERS = [
  'cf-connecting-ip', 'cf-ipcountry', 'cf-ray', 'cf-visitor', 'cf-worker', 'cf-ect',
  'cf-mitigated', 'cf-access-client-id', 'cf-bot-score', 'cf-poisoned-request-id',
  'true-client-ip', 'x-forwarded-for', 'x-forwarded-proto', 'x-forwarded-host',
  'x-forwarded-server', 'x-real-ip', 'cdn-loop', 'forwarded', 'via',
  'cookie', 'authorization', 'proxy-authorization',
  'host', 'connection', 'content-length', 'transfer-encoding', 'keep-alive',
  'te', 'upgrade', 'expect', 'referer-policy',
];

/* =============================== tiny utils =============================== */

const now = () => Date.now();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const round1 = (n) => Math.round(n * 10) / 10;
const safeMsg = (e) =>
  e instanceof Error ? `${e.name}: ${e.message}` : String(e && e.message ? e.message : e);

function uuid() {
  try {
    if (typeof crypto !== 'undefined' && crypto.randomUUID) return crypto.randomUUID();
  } catch { /* fall through */ }
  const b = new Uint8Array(16);
  (crypto && crypto.getRandomValues ? crypto : { getRandomValues: (a) => { for (let i = 0; i < a.length; i++) a[i] = (Math.random() * 256) | 0; return a; } }).getRandomValues(b);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/* ================================ ApiError ================================ */

/** Typed operational error → mapped to an HTTP response with X-Error-* headers. */
class ApiError extends Error {
  constructor(status, code, reason, message) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.reason = reason;
  }
}

/* ========================== concurrency queue (6) ========================= */
/**
 * FIFO semaphore. `acquire()` resolves as soon as one of OUTBOUND_CONCURRENCY
 * slots is free, or rejects with QUEUE_TIMEOUT after `timeoutMs`. `release()`
 * hands the slot directly to the longest-waiting acquirer (no slot churn).
 */
class Semaphore {
  constructor(limit) {
    this.limit = limit;
    this.active = 0;
    this.queue = []; // { resolve, reject, timer, settled, queuedAt }
  }

  get depth() {
    return this.queue.length;
  }

  acquire(timeoutMs = 0) {
    const queuedAt = now();
    if (this.active < this.limit) {
      this.active++;
      return Promise.resolve({ waitedMs: 0 });
    }
    return new Promise((resolve, reject) => {
      const entry = { resolve, reject, timer: null, settled: false, queuedAt };
      entry.timer = setTimeout(() => {
        if (entry.settled) return;
        entry.settled = true;
        const i = this.queue.indexOf(entry);
        if (i !== -1) this.queue.splice(i, 1);
        reject(new ApiError(503, 'QUEUE_TIMEOUT', 'OVERLOADED', `Bing request queue wait exceeded ${timeoutMs} ms.`));
      }, timeoutMs);
      this.queue.push(entry);
    }).then(() => ({ waitedMs: now() - queuedAt }));
  }

  release() {
    const next = this.queue.shift();
    if (next) {
      if (next.settled) return this.release(); // timed-out entry (defensive)
      next.settled = true;
      clearTimeout(next.timer);
      next.resolve(); // slot hand-off: `active` count intentionally unchanged
    } else {
      this.active = Math.max(0, this.active - 1);
    }
  }
}

/** Module-level (per-isolate) queue guarding all outbound Bing GETs. */
let bingQueue = new Semaphore(OUTBOUND_CONCURRENCY);

/* ============================== rate limiting ============================= */
/**
 * Sliding-window per-IP limiter (per isolate). limit <= 0 → unlimited.
 * Returns { allowed, retryAfterMs?, remaining?, resetAt? }.
 */
const rateBuckets = new Map(); // ip → sorted timestamps (ms)

function rateCheck(ip, limit, nowMs = now()) {
  if (!(limit > 0)) return { allowed: true, unlimited: true };
  const cutoff = nowMs - RATE_WINDOW_MS;
  let arr = rateBuckets.get(ip);
  if (!arr) {
    arr = [];
    rateBuckets.set(ip, arr);
  }
  while (arr.length && arr[0] <= cutoff) arr.shift();
  if (arr.length >= limit) {
    return { allowed: false, retryAfterMs: arr[0] + RATE_WINDOW_MS - nowMs };
  }
  arr.push(nowMs);
  if (rateBuckets.size > RATE_BUCKETS_MAX) {
    for (const [k, v] of rateBuckets) {
      if (!v.length || v[v.length - 1] <= cutoff) rateBuckets.delete(k);
    }
  }
  return {
    allowed: true,
    remaining: limit - arr.length,
    resetAt: arr[0] + RATE_WINDOW_MS,
  };
}

function parseRateLimit(v) {
  const n = parseInt(String(v ?? '0'), 10);
  return Number.isFinite(n) && n > 0 ? n : 0;
}

function requireKeyFlag(env) {
  return String(env && env.REQUIRE_KEY != null ? env.REQUIRE_KEY : 'false').trim().toLowerCase() === 'true';
}

/* ============================ base64url helpers =========================== */

function b64UrlDecode(s) {
  let b = String(s).replace(/-/g, '+').replace(/_/g, '/');
  while (b.length % 4) b += '=';
  const bin = atob(b); // throws on invalid input → caller handles
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder('utf-8').decode(bytes);
}

function b64UrlEncodeStr(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/* ===================== HTML text / entity sanitization ==================== */

const NAMED_ENTITIES = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', hellip: '…',
  rsquo: '\u2019', lsquo: '\u2018', ldquo: '\u201C', rdquo: '\u201D',
  mdash: '\u2014', ndash: '\u2013', middot: '\u00B7', copy: '\u00A9',
  reg: '\u00AE', trade: '\u2122', eacute: '\u00E9', egrave: '\u00E8',
  auml: '\u00E4', ouml: '\u00F6', uuml: '\u00FC', szlig: '\u00DF',
};

/** Decode the subset of HTML entities that occur in Bing SERP markup (once, no re-parse). */
function decodeEntities(s) {
  if (!s) return s;
  return s.replace(/&(#[xX]?[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]{1,31});/g, (m, g) => {
    if (g[0] === '#') {
      const hex = g[1] === 'x' || g[1] === 'X';
      const code = parseInt(g.slice(hex ? 2 : 1), hex ? 16 : 10);
      if (!Number.isFinite(code) || code < 0x20 || code > 0x10ffff) return m;
      try { return String.fromCodePoint(code); } catch { return m; }
    }
    const name = g.toLowerCase();
    return Object.prototype.hasOwnProperty.call(NAMED_ENTITIES, name) ? NAMED_ENTITIES[name] : m;
  });
}

/** Strip all tags, decode entities, collapse whitespace. `space` controls tag→'' vs tag→' '. */
function cleanText(htmlFragment, { space = false } = {}) {
  if (!htmlFragment) return '';
  let s = String(htmlFragment)
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ')
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ')
    .replace(/<[^>]*>/g, space ? ' ' : '');
  s = decodeEntities(s);
  s = s.replace(/\s+/g, ' ').trim();
  return s;
}

/* ===================== Bing tracking-redirect decoding ==================== */
/**
 * Turn `https://www.bing.com/ck/a?!&&p=…&u=a1<base64url>&ntb=1` into the clean
 * destination URL. Handles: `a1`/`a2`/`a3` prefixes, URL-safe and standard
 * base64, percent-encoding (URLSearchParams decodes once), entity-encoded
 * input (caller pre-decodes), and both absolute and (rare) relative targets.
 * Any failure → returns the input unchanged (graceful degradation).
 */
function decodeBingRedirect(href) {
  if (!href || typeof href !== 'string') return href;
  try {
    const raw = href.trim();
    if (!/(^|\.)bing\.com\/ck\//i.test(raw) && !/^\/ck\//i.test(raw)) return raw; // not a tracking link
    const u = new URL(raw, BING_ORIGIN);
    if (!/\/ck\//.test(u.pathname)) return raw;
    let p = u.searchParams.get('u') || u.searchParams.get('url');
    if (!p) return raw;
    if (/^https?:\/\//i.test(p)) return p; // some variants carry a plain URL
    if (/^a\d/i.test(p)) p = p.slice(2); // strip 'a1' / 'a2' / 'a3' prefix
    const decoded = b64UrlDecode(p);
    if (/^https?:\/\//i.test(decoded)) return decoded;
    return raw; // relative/internal target → keep original link
  } catch {
    return href;
  }
}

/* ========================== SERP parser (tiered) ========================== */
/**
 * Layout-resilient parser. Strategy:
 *   1. Isolate the `<ol id="b_results">` region (avoids head-script noise).
 *   2. Split it into blocks at SERP-level <li> boundaries (b_algo* keep, b_ad /
 *      b_ans / b_pag / b_msg are separators → ads & widgets excluded).
 *   3. For every field, try a chain of independent regex strategies, most
 *      specific first — Bing markup changes degrade gracefully instead of
 *      hard-failing. A block survives only if it yields a title AND an http(s) URL.
 * All regexes are bounded (no unbounded nested quantifiers) to stay ReDoS-safe.
 */
function parseBingSerp(html) {
  const out = { results: [], totalResults: null, noResultsMarker: false, blockedMarker: false };

  if (typeof html !== 'string' || html.length === 0) return out;

  out.noResultsMarker = /class="[^"]*\bb_no\b[^"]*"/.test(html) || /There are no results for/i.test(html);
  out.blockedMarker = /b_captcha|\/challenge\/|consent\.bing\.com|microsoftsecurity/i.test(html);

  // total-results: <span class="sb_count">About 50,900 results</span> (locale-safe: keep digits only)
  const mTot = html.match(/class="[^"]*\bsb_count\b[^"]*"[^>]*>([\s\S]{0,200}?)<\/span>/i);
  if (mTot) {
    const digits = mTot[1].replace(/[^0-9]/g, '');
    if (digits) out.totalResults = parseInt(digits, 10);
  }

  // 1. results region
  const startMatch = html.search(/<ol\b[^>]*\bid\s*=\s*"b_results"/i);
  let serp = html;
  if (startMatch >= 0) {
    const ctxStart = html.search(/<ol\b[^>]*\bid\s*=\s*"b_context"/i);
    serp = html.slice(startMatch, ctxStart > startMatch ? ctxStart : html.length);
  }

  // 2. SERP-level <li> boundaries
  const liRe = /<li\b[^>]*>/gi;
  const marks = [];
  let m;
  while ((m = liRe.exec(serp))) {
    const cls = (m[0].match(/\bclass\s*=\s*"([^"]*)"/i) || [null, ''])[1];
    const tokens = cls.split(/\s+/);
    const isAlgo = tokens.some((t) => t === 'b_algo' || t.startsWith('b_algo'));
    const isBoundary = isAlgo || tokens.some((t) => ['b_ad', 'b_ans', 'b_pag', 'b_msg', 'b_pole'].includes(t));
    if (isBoundary) marks.push({ end: m.index + m[0].length, isAlgo });
  }

  // 3. per-block extraction
  for (let i = 0; i < marks.length; i++) {
    if (!marks[i].isAlgo) continue;
    const block = serp.slice(marks[i].end, i + 1 < marks.length ? marks[i + 1].end : serp.length);
    const r = parseAlgoBlock(block);
    if (r) out.results.push(r);
  }

  return out;
}

function parseAlgoBlock(rawBlock) {
  // Drop inline <style>/<script> payloads (Bing embeds per-result CSS).
  const block = rawBlock
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ')
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ');
  if (block.length > 64_000) return null; // sanity cap

  const tu = extractTitleUrl(block);
  if (!tu || !tu.title || !tu.href) return null;

  const finalUrl = resolveResultUrl(tu.href);
  if (!finalUrl) return null;

  return {
    title: tu.title.slice(0, 300),
    url: finalUrl,
    favicon: extractFavicon(block),
    path: extractPath(block, finalUrl),
    summary: extractSummary(block),
  };
}

/** title + href — ordered fallback strategies. */
function extractTitleUrl(block) {
  // S1 (current layout): <h2 …><a … href="URL">TITLE</a>
  let m = block.match(/<h2\b[^>]*>[\s\S]{0,240}?<a\b[^>]*?href="([^"]+)"[^>]*>([\s\S]{0,600}?)<\/a>/i);
  if (m) return { href: decodeEntities(m[1]), title: cleanText(m[2]) };

  // S2 (attribution variant): the site-card anchor <a class="tilk" href="URL">
  m = block.match(/<a\b[^>]*\bclass\s*=\s*"[^"]*\btilk\b[^"]*"[^>]*?href="([^"]+)"[^>]*>([\s\S]{0,600}?)<\/a>/i);
  if (m) {
    const title = cleanText(block.match(/class="[^"]*\btptt\b[^"]*"[^>]*>([\s\S]{0,200}?)<\/div>/i)?.[1] || m[2]);
    return { href: decodeEntities(m[1]), title };
  }

  // S3 (last resort): first http(s) anchor with non-trivial text
  m = block.match(/<a\b[^>]*?href="((?:https?:\/\/|\/)[^"]+)"[^>]*>([\s\S]{1,400}?)<\/a>/i);
  if (m) return { href: decodeEntities(m[1]), title: cleanText(m[2]) };

  return null;
}

/** href → clean absolute http(s) URL; null if unusable. */
function resolveResultUrl(href) {
  try {
    const decoded = decodeBingRedirect(href);
    const u = new URL(decoded, BING_ORIGIN);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
    // Drop internal navigation links (e.g. /search?q=… pagination inside a result card)
    if (/(^|\.)bing\.com$/i.test(u.hostname) && (/^\/(search|ck)\//i.test(u.pathname) || /^\/ck$/.test(u.pathname))) return null;
    if (u.toString().length > 2048) return null;
    return u.toString();
  } catch {
    return null;
  }
}

/** summary — ordered fallback strategies. */
function extractSummary(block) {
  const candidates = [
    // S1: <p class="…b_lineclamp…|…b_paractl…">…</p>
    block.match(/<p\b[^>]*\bclass\s*=\s*"[^"]*(?:b_lineclamp|b_paractl)[^"]*"[^>]*>([\s\S]{0,1500}?)<\/p>/i),
    // S2: first <p> inside <div class="b_caption">
    block.match(/<div\b[^>]*\bclass\s*=\s*"[^"]*b_caption[^"]*"[^>]*>[\s\S]{0,300}?<p\b[^>]*>([\s\S]{0,1500}?)<\/p>/i),
    // S3: any substantial paragraph
    block.match(/<p\b[^>]*>([\s\S]{20,1500}?)<\/p>/i),
  ];
  for (const m of candidates) {
    if (!m) continue;
    let s = m[1]
      .replace(/<span\b[^>]*\bclass\s*=\s*"[^"]*news_dt[^"]*"[^>]*>[\s\S]*?<\/span>/gi, '') // date slug
      .replace(/<\/(p|div|li)>/gi, ' ');
    s = cleanText(s, { space: true });
    s = s.replace(/^Web[A-Z][a-z]{2}\s+\d{1,2},\s*\d{4}\s*[—–-]\s*/, ''); // "WebJun 10, 2025 —" fallback
    s = s.replace(/^[·•|—–-]\s*/, '').trim();
    if (s) return s.slice(0, 1200);
  }
  return null;
}

/** breadcrumb path — cite text first, else derived from the final URL. */
function extractPath(block, finalUrl) {
  const m = block.match(/<cite\b[^>]*>([\s\S]{0,400}?)<\/cite>/i);
  if (m) {
    const c = cleanText(m[1], { space: true });
    if (c) {
      const normalized = c
        .replace(/^https?:\/\//i, '')
        .replace(/\s*(?:›|»|>)\s*/g, ' > ')
        .replace(/\s+/g, ' ')
        .trim();
      if (normalized) return normalized.slice(0, 250);
    }
  }
  try {
    const u = new URL(finalUrl);
    const seg = [u.hostname.replace(/^www\./i, '')];
    const parts = u.pathname.split('/').filter(Boolean).slice(0, 4);
    for (const p of parts) {
      let dec;
      try { dec = decodeURIComponent(p); } catch { dec = p; }
      seg.push(dec.replace(/[-_+]/g, ' ').trim());
    }
    return seg.join(' > ').slice(0, 250);
  } catch {
    return null;
  }
}

/** favicon — from the result markup if absolute; `null` otherwise (handler may fall back). */
function extractFavicon(block) {
  // S1: favicon wrapper context: class="…cico…" / "…b_favicon…" / "…wr_fav…" → <img src="…">
  let m = block.match(/class="[^"]*(?:\bcico\b|\bb_favicon\b|\bwr_fav\b)[^"]*"[^>]*>(?:\s|<a\b[^>]*>|<div\b[^>]*>){0,4}<img\b[^>]*?src="([^"]+)"/i);
  if (m) return absImgUrl(decodeEntities(m[1]));
  // S2: Bing thumbnail service with favicon-ish dimensions
  m = block.match(/<img\b[^>]*?src="(https:\/\/th\.bing\.com\/th\?[^"]*(?:[?&]w=16|[?&]h=16)[^"]*)"/i);
  if (m) return absImgUrl(decodeEntities(m[1]));
  return null;
}

function absImgUrl(src) {
  try {
    const u = new URL(src, BING_ORIGIN);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
    return u.toString();
  } catch {
    return null;
  }
}

/* ======================== streaming cursor (stateless) ==================== */
/**
 * stream-id = base64url({ q, l, f, n, s, r }) — a self-contained, stateless
 * pagination cursor (survives isolate restarts / multi-isolate routing, no
 * server memory, no TTL). r = next rank, s = next Bing `first`, n = requested
 * total, l = lang, f = favicon flag, q = query.
 */
function encodeCursor(state) {
  return b64UrlEncodeStr(JSON.stringify(state));
}

function makeCursor(p) {
  return { q: p.query, l: p.lang, f: p.favicon ? 1 : 0, n: p.results, s: 1, r: 1 };
}

function decodeCursor(id) {
  let parsed;
  try {
    if (typeof id !== 'string' || !id || id.length > 2000 || !STREAM_ID_RE.test(id)) throw 0;
    parsed = JSON.parse(b64UrlDecode(id));
  } catch {
    throw new ApiError(400, 'INVALID_STREAM_ID', 'VALIDATION', 'The provided stream-id is malformed or expired.');
  }
  const ok =
    parsed && typeof parsed === 'object' &&
    typeof parsed.q === 'string' && parsed.q.length >= 1 && parsed.q.length <= MAX_QUERY_CHARS &&
    (parsed.l === '' || (typeof parsed.l === 'string' && LANG_RE.test(parsed.l))) &&
    (parsed.f === 0 || parsed.f === 1) &&
    Number.isInteger(parsed.n) && parsed.n >= RESULTS_MIN && parsed.n <= RESULTS_MAX &&
    Number.isInteger(parsed.s) && parsed.s >= 1 && parsed.s <= BING_FIRST_MAX &&
    Number.isInteger(parsed.r) && parsed.r >= 1 && parsed.r <= 1000;
  if (!ok) throw new ApiError(400, 'INVALID_STREAM_ID', 'VALIDATION', 'The provided stream-id is malformed or expired.');
  return parsed;
}

/* ============================ payload validation ========================== */

function asBool(v, field) {
  if (typeof v === 'boolean') return v;
  if (v === 'true') return true;
  if (v === 'false') return false;
  throw new ApiError(400, `INVALID_${field.toUpperCase().replace(/-/g, '_')}`, 'VALIDATION', `Field "${field}" must be a boolean.`);
}

function validatePayload(body, env) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new ApiError(400, 'INVALID_PAYLOAD', 'VALIDATION', 'Request body must be a JSON object.');
  }

  // query (required)
  const query = typeof body.query === 'string' ? body.query.trim() : body.query;
  if (typeof query !== 'string' || query.length === 0) {
    throw new ApiError(400, 'QUERY_REQUIRED', 'VALIDATION', 'Field "query" is required and must be a non-empty string.');
  }
  if (query.length > MAX_QUERY_CHARS) {
    throw new ApiError(400, 'QUERY_TOO_LONG', 'VALIDATION', `Field "query" must be at most ${MAX_QUERY_CHARS} characters.`);
  }

  // results (required, integer 1..100; integer-valued strings tolerated)
  let results = body.results;
  if (typeof results === 'string' && /^-?\d+$/.test(results.trim())) results = parseInt(results.trim(), 10);
  if (typeof results !== 'number' || !Number.isInteger(results)) {
    throw new ApiError(400, 'INVALID_RESULTS', 'VALIDATION', 'Field "results" must be an integer between 1 and 100.');
  }
  if (results < RESULTS_MIN || results > RESULTS_MAX) {
    throw new ApiError(400, 'RESULTS_OUT_OF_RANGE', 'VALIDATION', 'Field "results" must be between 1 and 100.');
  }

  // is-stream (required)
  const isStream = asBool(body['is-stream'], 'is-stream');

  // show-telemetry (optional, default false)
  const showTelemetry = body['show-telemetry'] === undefined ? false : asBool(body['show-telemetry'], 'show-telemetry');

  // favicon (optional, default false)
  const favicon = body.favicon === undefined ? false : asBool(body.favicon, 'favicon');

  // lang (optional, default env DEFAULT_LANG → "en-US")
  let lang = body.lang === undefined ? (env && env.DEFAULT_LANG) || 'en-US' : body.lang;
  if (typeof lang !== 'string' || !LANG_RE.test(lang.trim())) {
    throw new ApiError(400, 'INVALID_LANG', 'VALIDATION', 'Field "lang" must be an RFC-1766-style code like "en" or "en-US".');
  }
  lang = normalizeLang(lang.trim());

  // key (optional)
  let key = body.key === undefined || body.key === null ? null : body.key;
  if (key !== null) {
    if (typeof key !== 'string') throw new ApiError(400, 'INVALID_KEY', 'VALIDATION', 'Field "key" must be a string.');
    key = key.trim().slice(0, 256);
    if (key === '') key = null;
  }

  // stream-id (optional; required for stream continuation)
  let streamId = body['stream-id'] === undefined || body['stream-id'] === null ? null : body['stream-id'];
  if (streamId !== null) {
    if (typeof streamId !== 'string' || streamId.length > 2000) {
      throw new ApiError(400, 'INVALID_STREAM_ID', 'VALIDATION', 'Field "stream-id" must be a string of at most 2000 characters.');
    }
    streamId = streamId.trim();
  }

  return { query, results, isStream, showTelemetry, favicon, lang, key, streamId };
}

function normalizeLang(lang) {
  const [primary, ...rest] = lang.split('-');
  if (!rest.length) return primary.toLowerCase();
  const region = rest.join('-');
  return `${primary.toLowerCase()}-${region.length === 2 ? region.toUpperCase() : region.charAt(0).toUpperCase() + region.slice(1)}`;
}

/* ================================ auth ==================================== */

function collectKeys(env) {
  const keys = [];
  for (const name of Object.keys(env || {})) {
    if (/^KEY-\d+$/.test(name)) {
      const v = env[name];
      if (typeof v === 'string' && v.length > 0) keys.push(v);
    }
  }
  return keys;
}

/** Constant-time-ish comparison (only length is leaked — acceptable for API keys). */
function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ea = new TextEncoder().encode(a);
  const eb = new TextEncoder().encode(b);
  let diff = ea.length ^ eb.length;
  const n = Math.max(ea.length, eb.length);
  for (let i = 0; i < n; i++) diff |= (ea[i] || 0) ^ (eb[i] || 0);
  return diff === 0;
}

/**
 * REQUIRE_KEY="false" (default) → every request authorized; `key` is ignored.
 * REQUIRE_KEY="true" → `key` must match one of the KEY-1..KEY-n secrets.
 */
function authorize(env, key) {
  if (!requireKeyFlag(env)) return;
  const keys = collectKeys(env);
  if (keys.length === 0) {
    throw new ApiError(500, 'CONFIG_ERROR', 'CONFIG', 'REQUIRE_KEY is enabled but no KEY-n secrets are configured. Run: wrangler secret put KEY-1');
  }
  if (!key) {
    throw new ApiError(401, 'MISSING_KEY', 'AUTH', 'This deployment requires a key. Send it as "key" in the JSON request body.');
  }
  if (!keys.some((k) => timingSafeEqual(k, key))) {
    throw new ApiError(401, 'INVALID_KEY', 'AUTH', 'The provided key is not valid.');
  }
}

/* ======================= Bing request construction ======================== */

/**
 * Always: https://www.bing.com/search?q=<encoded>&webscp=1
 * plus count/first for pagination and setmkt/setlang for localization.
 */
function buildBingUrl({ query, count, first = 1, lang = 'en-US' }) {
  const u = new URL(BING_ORIGIN + BING_SEARCH_PATH);
  u.searchParams.set('q', query);
  u.searchParams.set('webscp', '1'); // ← unconditionally appended (spec invariant)
  if (Number.isInteger(count) && count > 0) u.searchParams.set('count', String(Math.min(count, PAGE_SIZE_MAX)));
  if (Number.isInteger(first) && first > 1) u.searchParams.set('first', String(first));
  const [primary, region] = lang.split('-');
  if (region) u.searchParams.set('setmkt', lang);
  if (primary) u.searchParams.set('setlang', primary);
  return u.toString();
}

/** Remove every proxy/CF header from a Headers object (mutates + returns it). */
function scrubProxyHeaders(headers) {
  for (const name of STRIP_OUTBOUND_HEADERS) headers.delete(name);
  return headers;
}

/** Fresh, browser-like outbound headers. Nothing from the client is forwarded. */
function buildOutboundHeaders(lang = 'en-US') {
  const h = new Headers();
  h.set('User-Agent', USER_AGENT);
  h.set('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8');
  h.set('Accept-Language', acceptLanguageValue(lang));
  h.set('Referer', BING_ORIGIN + '/');
  h.set('Cache-Control', 'no-cache');
  h.set('Pragma', 'no-cache');
  h.set('Upgrade-Insecure-Requests', '1');
  // NOTE: Accept-Encoding intentionally omitted — the runtime negotiates and
  // transparently decompresses. Defense-in-depth: scrub once more below.
  return scrubProxyHeaders(h);
}

function acceptLanguageValue(lang) {
  const primary = lang.split('-')[0].toLowerCase();
  const parts = [lang];
  if (primary !== lang.toLowerCase()) parts.push(`${primary};q=0.9`);
  parts.push('en;q=0.5');
  return parts.join(',');
}

/* ============================ fetch pipeline ============================== */

async function fetchBingViaQueue(url, lang, timings, env) {
  const queueWaitMs = clampInt(env && env.QUEUE_WAIT_MS, 10, 120_000, DEFAULT_QUEUE_WAIT_MS);
  const timeoutMs = clampInt(env && env.UPSTREAM_TIMEOUT_MS, 100, 120_000, DEFAULT_UPSTREAM_TIMEOUT_MS);
  let lastErr = null;

  for (let attempt = 0; attempt <= UPSTREAM_RETRIES; attempt++) {
    let slot;
    try {
      slot = await bingQueue.acquire(queueWaitMs); // throws ApiError 503 on timeout
    } catch (e) {
      if (e instanceof ApiError) throw e;
      throw new ApiError(503, 'QUEUE_TIMEOUT', 'OVERLOADED', 'Bing request queue wait exceeded.');
    }
    timings.que += slot.waitedMs;

    const t = now();
    try {
      return await timedFetchText(url, buildOutboundHeaders(lang), timeoutMs);
    } catch (e) {
      lastErr = e;
      const retryable = e instanceof ApiError && e.status === 502;
      if (retryable && attempt < UPSTREAM_RETRIES) {
        await sleep(RETRY_DELAY_MS);
        continue;
      }
      throw e;
    } finally {
      timings.fetch += now() - t; // includes queue→fetch wall time of this attempt only
      bingQueue.release();        // ← ALWAYS released, even on error (no slot leaks)
    }
  }
  throw lastErr || new ApiError(502, 'FETCH_FAILED', 'FETCH', 'Bing request failed.');
}

async function timedFetchText(url, headers, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let res;
  try {
    // NOTE: globalThis.fetch is REQUIRED — a bare `fetch(...)` would resolve to
    // this module's own handler function (shadowing) and recurse into the worker.
    res = await globalThis.fetch(url, { method: 'GET', headers, redirect: 'follow', signal: controller.signal });
  } catch (e) {
    clearTimeout(timer);
    const code = controller.signal.aborted ? 'UPSTREAM_TIMEOUT' : 'FETCH_FAILED';
    throw new ApiError(502, code, 'FETCH', `Could not fetch Bing results (${code}): ${safeMsg(e)}`);
  }
  try {
    if (!res.ok) {
      const code = res.status === 429 ? 'UPSTREAM_RATE_LIMITED' : 'UPSTREAM_ERROR';
      throw new ApiError(502, code, 'FETCH', `Bing responded with HTTP ${res.status}.`);
    }
    const html = await res.text();
    return html;
  } catch (e) {
    if (e instanceof ApiError) throw e;
    throw new ApiError(502, 'FETCH_FAILED', 'FETCH', `Could not read Bing response: ${safeMsg(e)}`);
  } finally {
    clearTimeout(timer);
  }
}

function clampInt(v, min, max, dflt) {
  const n = parseInt(String(v ?? ''), 10);
  if (!Number.isFinite(n)) return dflt;
  return Math.min(max, Math.max(min, n));
}

/* ============================ grade + telemetry =========================== */

function gradeFromMs(ms) {
  for (const [threshold, grade] of GRADE_TABLE) if (ms <= threshold) return grade;
  return 'F';
}

function buildTelemetry(timings, totalMs, pingMs) {
  const t = {
    'que-time': round1(timings.que),
    'in-flight': round1(timings.fetch),
    'parse-time': round1(timings.parse),
    'total-time': round1(totalMs),
    'time-grade': gradeFromMs(totalMs),
  };
  if (typeof pingMs === 'number' && Number.isFinite(pingMs)) {
    t.ping = round1(pingMs); // one-way estimate; clock skew clamped at 0, sane ceiling 10 min
  }
  return t;
}

/** Parse X-Client-Sent-At defensively (Number(null) === 0 would fake a ping!). */
function parseClientSentAt(request) {
  const raw = request.headers.get('x-client-sent-at');
  if (raw === null) return null;
  const s = String(raw).trim();
  if (!/^-?\d+(\.\d+)?$/.test(s)) return null;
  return Number(s);
}

function pingMsFrom(receivedAt, clientSentAt) {
  if (clientSentAt === null) return null;
  return Math.min(600_000, Math.max(0, receivedAt - clientSentAt));
}

/* ============================== CORS helpers ============================== */

function corsHeaders(env, request) {
  const conf = String((env && env.CORS_ORIGIN) || '*').trim();
  const h = new Headers();
  const origin = request && request.headers ? request.headers.get('origin') : null;
  if (conf === '*') {
    h.set('Access-Control-Allow-Origin', '*');
  } else {
    const list = conf.split(',').map((s) => s.trim()).filter(Boolean);
    if (origin && list.includes(origin)) {
      h.set('Access-Control-Allow-Origin', origin);
      h.set('Vary', 'Origin');
    }
  }
  h.set('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  h.set('Access-Control-Expose-Headers', CORS_EXPOSE_HEADERS.join(', '));
  return h;
}

function applyCors(headers, env, request) {
  for (const [k, v] of corsHeaders(env, request).entries()) headers.set(k, v);
  return headers;
}

/* ============================ response helpers ============================ */

function jsonResponse(request, env, requestId, data, { status = 200, extra = null } = {}) {
  const h = new Headers();
  h.set('Content-Type', 'application/json; charset=utf-8');
  h.set('Cache-Control', 'no-store');
  h.set('X-Request-Id', requestId);
  if (extra) for (const [k, v] of extra.entries()) h.set(k, v);
  applyCors(h, env, request);
  return new Response(JSON.stringify(data), { status, headers: h });
}

function errorResponse(request, env, requestId, err) {
  const h = new Headers();
  h.set('Content-Type', 'application/json; charset=utf-8');
  h.set('Cache-Control', 'no-store');
  h.set('X-Request-Id', requestId);
  h.set('X-Error-Code', err.code || 'INTERNAL_ERROR');
  h.set('X-Failure-Reason', err.reason || 'INTERNAL');
  if (err.status === 429 && err.retryAfterSec) h.set('Retry-After', String(err.retryAfterSec));
  applyCors(h, env, request);
  const body = { error: err.code || 'INTERNAL_ERROR', message: err.message || 'Unexpected error.' };
  return new Response(JSON.stringify(body), { status: err.status || 500, headers: h });
}

/* ================================ router ================================== */

function normalizePath(pathname) {
  let p = pathname.replace(/\/+$/, '');
  return p === '' ? '/' : p;
}

async function route(request, env, requestId) {
  const url = new URL(request.url);
  const path = normalizePath(url.pathname);

  if (request.method === 'OPTIONS') return preflight(request, env);

  if (path === '/' || path === '/health') {
    if (request.method === 'GET') return infoResponse(request, env, requestId);
    return methodNotAllowed(request, env, requestId, 'GET, OPTIONS');
  }

  if (path === '/api/v1' || path === '/api/v1/search' || path === '/search') {
    if (request.method === 'POST') return handleSearch(request, env, requestId);
    if (request.method === 'GET' && path === '/api/v1') return infoResponse(request, env, requestId);
    return methodNotAllowed(request, env, requestId, 'POST, GET, OPTIONS');
  }

  if (path === '/api/v1/key-status') {
    if (request.method === 'GET') {
      return jsonResponse(request, env, requestId, {
        name: 'free-serp-api',
        version: VERSION,
        'key-required': requireKeyFlag(env),
      });
    }
    return methodNotAllowed(request, env, requestId, 'GET, OPTIONS');
  }

  if (path === '/demo') {
    if (request.method === 'GET') return demoPage(request, env, requestId);
    return methodNotAllowed(request, env, requestId, 'GET, OPTIONS');
  }

  throw new ApiError(404, 'NOT_FOUND', 'ROUTING', `No route for ${request.method} ${path}. Use POST /api/v1/.`);
}

function methodNotAllowed(request, env, requestId, allow) {
  const err = new ApiError(405, 'METHOD_NOT_ALLOWED', 'ROUTING', `Method ${request.method} is not allowed here. Allowed: ${allow}.`);
  err.allow = allow;
  const res = errorResponse(request, env, requestId, err);
  const h = new Headers(res.headers);
  h.set('Allow', allow);
  return new Response(res.body, { status: res.status, headers: h });
}

function preflight(request, env) {
  const h = corsHeaders(env, request);
  const reqMethod = (request.headers.get('access-control-request-method') || '').toUpperCase();
  if (reqMethod && reqMethod !== 'POST' && reqMethod !== 'GET' && reqMethod !== 'OPTIONS') {
    return new Response(null, { status: 403, headers: h });
  }
  const requested = (request.headers.get('access-control-request-headers') || '')
    .toLowerCase().split(',').map((s) => s.trim()).filter(Boolean);
  if (requested.some((x) => !CORS_ALLOW_HEADERS.includes(x))) {
    return new Response(null, { status: 403, headers: h });
  }
  h.set('Access-Control-Allow-Headers', CORS_ALLOW_HEADERS.join(', '));
  h.set('Access-Control-Max-Age', '86400');
  return new Response(null, { status: 204, headers: h });
}

function infoResponse(request, env, requestId) {
  const limit = parseRateLimit(env && env.RATE_LIMIT);
  return jsonResponse(request, env, requestId, {
    name: 'free-serp-api',
    version: VERSION,
    status: 'ok',
    'key-required': requireKeyFlag(env),
    'rate-limit-per-minute': limit > 0 ? limit : null,
    'rate-limit-unlimited': limit <= 0,
    endpoints: {
      search: 'POST /api/v1/',
      search_alias: 'POST /api/v1/search (also POST /search)',
      info: 'GET /api/v1/',
      key_status: 'GET /api/v1/key-status',
      demo: 'GET /demo',
    },
  });
}

/* eslint-disable no-unused-vars */
const DEMO_PAGE = `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>free-serp-api demo</title>
<style>body{font:14px/1.5 system-ui,sans-serif;margin:2rem auto;max-width:56rem;padding:0 1rem;color:#222}
input{padding:.45rem .6rem;font:inherit;width:24rem}button{padding:.45rem 1rem;font:inherit;cursor:pointer}
pre{background:#f4f4f5;padding:1rem;border-radius:8px;overflow:auto;max-height:24rem}
code{background:#f4f4f5;padding:.1rem .3rem;border-radius:4px}</style></head>
<body><h3 style="font-weight:600">free-serp-api — live test</h3>
<p><input id="q" value="quantum computing"> <button id="go">Search → POST /api/v1/</button></p>
<p>Open DevTools (F12) — the full JSON response and a <code>console.table</code> of results are printed there. Raw JSON also shown below.</p>
<pre id="out">waiting for search…</pre>
<script>
(function () {
  var ENDPOINT = new URL('/api/v1/', location.href).href;
  document.getElementById('go').onclick = function () {
    var q = document.getElementById('q').value || 'quantum computing';
    fetch(ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 'is-stream': false, query: q, results: 10, 'show-telemetry': true })
    })
      .then(function (r) { return r.json().then(function (d) { return { status: r.status, d: d }; }); })
      .then(function (x) {
        console.log('[free-serp-api] HTTP ' + x.status + ' response:', x.d);
        if (x.d && x.d.results) {
          console.table(x.d.results.map(function (r) { return { rank: r.rank, title: r.title, url: r.url }; }));
        }
        document.getElementById('out').textContent = JSON.stringify(x.d, null, 2);
      })
      .catch(function (e) {
        console.error('[free-serp-api] request failed:', e);
        document.getElementById('out').textContent = String(e);
      });
  };
  document.getElementById('go').click();
})();
</script></body></html>`;
/* eslint-enable no-unused-vars */

function demoPage(request, env, requestId) {
  const h = new Headers();
  h.set('Content-Type', 'text/html; charset=utf-8');
  h.set('Cache-Control', 'no-store');
  h.set('X-Request-Id', requestId);
  applyCors(h, env, request);
  return new Response(DEMO_PAGE, { status: 200, headers: h });
}

/* ============================ search handler ============================== */

async function handleSearch(request, env, requestId) {
  const t0 = now();
  const pingMs = pingMsFrom(t0, parseClientSentAt(request));

  // 1) Rate limiting (cheapest DoS guard, keyed per client IP, before body parsing)
  const limit = parseRateLimit(env && env.RATE_LIMIT);
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  const rl = rateCheck(ip, limit);
  if (!rl.allowed) {
    const retryAfterSec = Math.max(1, Math.ceil(rl.retryAfterMs / 1000));
    const err = new ApiError(429, 'RATE_LIMITED', 'RATE_LIMIT', `Rate limit exceeded: max ${limit} requests/minute per client. Retry after ${retryAfterSec}s.`);
    err.retryAfterSec = retryAfterSec;
    throw err;
  }

  // 2) Body + content type
  const declaredLength = parseInt(request.headers.get('content-length') || '0', 10);
  if (declaredLength > MAX_BODY_BYTES) {
    throw new ApiError(413, 'PAYLOAD_TOO_LARGE', 'VALIDATION', `Request body exceeds ${MAX_BODY_BYTES} bytes.`);
  }
  const contentType = (request.headers.get('content-type') || '').toLowerCase();
  if (contentType && !contentType.includes('application/json')) {
    throw new ApiError(415, 'UNSUPPORTED_MEDIA_TYPE', 'VALIDATION', 'Content-Type must be application/json.');
  }
  const raw = await request.text();
  if (raw.length > MAX_BODY_BYTES) {
    throw new ApiError(413, 'PAYLOAD_TOO_LARGE', 'VALIDATION', `Request body exceeds ${MAX_BODY_BYTES} bytes.`);
  }
  let body;
  try {
    body = JSON.parse(raw);
  } catch {
    throw new ApiError(400, 'INVALID_JSON', 'VALIDATION', 'Request body is not valid JSON.');
  }

  // 3) Payload + auth
  const p = validatePayload(body, env);
  authorize(env, p.key);

  // 4) Plan: stateless cursor for streams, page-stitching otherwise
  const timings = { que: 0, fetch: 0, parse: 0 };
  const cursor = p.isStream ? (p.streamId ? decodeCursor(p.streamId) : makeCursor(p)) : null;
  const query = cursor ? cursor.q : p.query;
  const lang = cursor ? (cursor.l || 'en-US') : p.lang;
  const faviconFlag = cursor ? cursor.f === 1 : p.favicon;
  const targetTotal = cursor ? cursor.n : p.results;
  let first = cursor ? cursor.s : 1;
  let nextRank = cursor ? cursor.r : 1;

  let totalResults = null;
  let lastParse = null;
  const collected = [];
  const seen = new Set();
  const maxPages = p.isStream ? 1 : NONSTREAM_MAX_PAGES;

  for (let page = 0; page < maxPages && collected.length < targetTotal; page++) {
    const count = Math.min(targetTotal - collected.length, PAGE_SIZE_MAX);
    const bingUrl = buildBingUrl({ query, count, first, lang });
    const html = await fetchBingViaQueue(bingUrl, lang, timings, env);

    const pt = now();
    const parsed = parseBingSerp(html);
    timings.parse += now() - pt;
    lastParse = parsed;

    if (totalResults === null) totalResults = parsed.totalResults;

    if (parsed.results.length === 0) break; // empty/blocked page → stop paging
    for (const r of parsed.results) {
      const k = dedupeKey(r.url);
      if (seen.has(k)) continue;
      seen.add(k);
      collected.push(r);
    }
    first += parsed.results.length; // continue AFTER the last result actually received
  }

  const totalMs = now() - t0;

  // 5) Failure taxonomy when nothing could be collected at all
  if (collected.length === 0) {
    if (lastParse && lastParse.blockedMarker) {
      throw new ApiError(502, 'UPSTREAM_BLOCKED', 'FETCH', 'Bing returned a captcha/consent/challenge page instead of search results.');
    }
    const isContinuation = Boolean(cursor && cursor.s > 1); // later stream batch
    if (!isContinuation && !(lastParse && lastParse.noResultsMarker)) {
      throw new ApiError(502, 'PARSE_ERROR', 'PARSE', 'Bing responded, but no results could be parsed — the page layout may have changed.');
    }
    // Genuine "no results" (or exhausted stream) → valid empty response
    const empty = {};
    if (p.showTelemetry) empty['shown-telemetry'] = buildTelemetry(timings, totalMs, pingMs);
    if (p.isStream) {
      empty['stream-id'] = null;
      empty['has-more'] = false;
    }
    empty.stats = { 'total-results': (lastParse && lastParse.totalResults) || 0 };
    empty.results = [];
    return finalize(request, env, requestId, empty, timings, totalMs, rl);
  }

  // 6) Rank, slice to the promised quantity, apply response flags
  const take = Math.min(collected.length, targetTotal - (nextRank - 1));
  const batch = [];
  for (let i = 0; i < take; i++) {
    const r = collected[i];
    const item = { rank: nextRank + i, title: r.title, url: r.url };
    if (faviconFlag) {
      const fav = r.favicon || faviconFallback(r.url);
      if (fav) item.favicon = fav;
    }
    if (r.path) item.path = r.path;
    if (r.summary) item.summary = r.summary;
    batch.push(item);
  }
  const endRank = nextRank + batch.length;
  const remaining = targetTotal - endRank + 1;
  const moreAvailable = batch.length > 0 && remaining > 0 && first <= BING_FIRST_MAX;

  // 7) Assemble the response (schema order: telemetry → stream → stats → results)
  const response = {};
  if (p.showTelemetry) response['shown-telemetry'] = buildTelemetry(timings, totalMs, pingMs);
  if (p.isStream) {
    response['stream-id'] = moreAvailable
      ? encodeCursor({ q: query, l: lang, f: faviconFlag ? 1 : 0, n: targetTotal, s: first, r: endRank })
      : null;
    response['has-more'] = moreAvailable;
  }
  response.stats = { 'total-results': totalResults == null ? endRank - 1 : totalResults };
  response.results = batch;

  return finalize(request, env, requestId, response, timings, totalMs, rl);
}

/** Stable dedupe key (host + path, tracking params stripped, trailing slash ignored). */
function dedupeKey(url) {
  try {
    const u = new URL(url);
    for (const t of ['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content']) u.searchParams.delete(t);
    let key = `${u.hostname.toLowerCase()}${u.pathname.replace(/\/+$/, '')}`;
    const qs = [...u.searchParams].sort().map(([k, v]) => `${k}=${v}`).join('&');
    if (qs) key += '?' + qs;
    return key;
  } catch {
    return url;
  }
}

/** Deterministic favicon fallback when Bing's own markup carries none. */
function faviconFallback(url) {
  try {
    const host = new URL(url).hostname;
    return `https://www.google.com/s2/favicons?domain=${encodeURIComponent(host)}&sz=32`;
  } catch {
    return null;
  }
}

/** Attach Server-Timing (+ X-Rate-Limit-* when a limit is active) to a JSON response. */
function finalize(request, env, requestId, data, timings, totalMs, rl) {
  const extra = new Headers();
  extra.set(
    'Server-Timing',
    `que;dur=${round1(timings.que)}, fetch;dur=${round1(timings.fetch)}, parse;dur=${round1(timings.parse)}, total;dur=${round1(totalMs)}`
  );
  if (rl && rl.remaining != null && rl.resetAt) {
    extra.set('X-Rate-Limit-Limit', String(parseRateLimit(env && env.RATE_LIMIT)));
    extra.set('X-Rate-Limit-Remaining', String(rl.remaining));
    extra.set('X-Rate-Limit-Reset', String(Math.ceil(rl.resetAt / 1000)));
  }
  return jsonResponse(request, env, requestId, data, { extra });
}

/* ============================ worker entry point ========================== */

async function fetch(request, env, ctx) {
  const requestId = uuid();
  try {
    return await route(request, env || {}, requestId);
  } catch (err) {
    if (err instanceof ApiError) return errorResponse(request, env || {}, requestId, err);
    console.error(`[free-serp-api ${requestId}] unhandled error:`, safeMsg(err));
    return errorResponse(
      request,
      env || {},
      requestId,
      new ApiError(500, 'INTERNAL_ERROR', 'INTERNAL', 'An unexpected internal error occurred.')
    );
  }
}

/* ============================== test hooks ================================ */
/** Not used by the runtime — lets the offline test-suite reset per-isolate state. */
const __testHooks = {
  resetState() {
    rateBuckets.clear();
    bingQueue = new Semaphore(OUTBOUND_CONCURRENCY);
  },
  queue() {
    return bingQueue;
  },
};
