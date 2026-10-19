# Sriail (Github) Basic Serp Api For Cloudflare (Python)
# For More Info, Read the README.md
import asyncio
import base64
import binascii
import html as html_mod
import hmac
import logging
import re
import time
from typing import Optional
from urllib.parse import quote_plus
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import AliasChoices, BaseModel, Field, field_validator
from starlette.exceptions import HTTPException as StarletteHTTPException
from workers import WorkerEntrypoint
from workers import asgi
from workers import fetch as http_fetch
#--------------------------------------------------------------------------------
# Configuration (For Your Personal Needs / Config)
passkeyProtection: bool = False # Set To True To Force API Authentacation
Passkeys: list[str] = [ # You Can Add Or Remove Paskeys From the List
    "K1-SERP-GtAat5hutd2vRPLCFvPlpZMn5CuMJ5dR", 
    "K2-SERP-NU0cbIlsKpIgPEWO7Sn0IVpuQ5Ge4H4c",
] # For Maximum Paskey Seceurity, Use a Seudo-Random API Key Generator
MAX_CONCURRENT_FETCHES: int = 6 # Maximum Current Operation (Maximum Of 6 On Cloudflare Workers, Can Be More on Local)
MAX_QUEUE_SIZE: int = 500 # Maximum Que (Edit to you Needs), After throws 503 Retry
QUEUE_RETRY_AFTER_SECONDS: int = 5 # Wait to Retry Query

BING_BASE_URL = "https://www.bing.com/search"
RESULTS_PER_PAGE = 10 # Set Amount of results Per page
MAX_PAGES = 10 # Max Amount of Pages Users Can Query
FETCH_TIMEOUT_SECONDS = 10.0 # The Timeout Between Requests
#--------------------------------------------------------------------------------
BING_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/129.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9", # Want Diffrent Language? Change the HTTP Headers.
}
# Remains the Same
CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
}
_RE_HAS_RESULTS_LIST = re.compile(r'<ol[^>]*id="b_results"', re.IGNORECASE)
_RE_RESULT_ITEMS = re.compile(
    r'<li[^>]*class="[^"]*\bb_algo\b[^"]*"[^>]*>'
    r'.*?'
    r'</li>\s*'
    r'(?=<li[^>]*class="[^"]*\bb_(?:algo|ans|pag)\b|</ol>)',
    re.IGNORECASE | re.DOTALL,
)
_RE_TITLE_LINK = re.compile(
    r'<h2[^>]*>\s*<a[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
_RE_SNIPPET = re.compile(
    r'<div[^>]*class="[^"]*\bb_caption\b[^"]*"[^>]*>.*?<p[^>]*>(.*?)</p>',
    re.IGNORECASE | re.DOTALL,
)
_RE_SUMMARY = re.compile(
    r'<div[^>]*class="[^"]*\bb_text\b[^"]*"[^>]*>(.*?)</div>',
    re.IGNORECASE | re.DOTALL,
)
_RE_WIKIBOX = re.compile(
    r'<div[^>]*class="[^"]*\bb_entitytp\b[^"]*"[^>]*>(.*?)</div>\s*</div>',
    re.IGNORECASE | re.DOTALL,
)
_RE_WIKIBOX_TITLE = re.compile(r'<h2[^>]*>(.*?)</h2>', re.IGNORECASE | re.DOTALL)
_RE_WIKIBOX_DESC = re.compile(
    r'<div[^>]*class="[^"]*\bb_snippet\b[^"]*"[^>]*>(.*?)</div>',
    re.IGNORECASE | re.DOTALL,
)
_RE_WIKIBOX_LINK = re.compile(r'<a[^>]*href="(?!#)([^"]+)"', re.IGNORECASE)
_RE_DEFINITION = re.compile(
    r'<div[^>]*class="[^"]*\bb_dict\b[^"]*"[^>]*>(.*?)</div>',
    re.IGNORECASE | re.DOTALL,
)
_RE_TAG_OR_WS = re.compile(r'<[^>]+>|\s+')
def _strip_tags(html_fragment: str) -> str:
    text = _RE_TAG_OR_WS.sub(' ', html_fragment)
    text = html_mod.unescape(text)
    return ' '.join(text.split())
def validate_config() -> Optional[str]:
    if not isinstance(passkeyProtection, bool):
        return "passkeyProtection must be a bool"
    if not isinstance(Passkeys, list) or not all(isinstance(k, str) for k in Passkeys):
        return "Passkeys must be a list of strings"
    if not (isinstance(MAX_CONCURRENT_FETCHES, int) and 1 <= MAX_CONCURRENT_FETCHES <= 6):
        return "MAX_CONCURRENT_FETCHES must be an integer from 1 to 6 (Cloudflare limit)"
    if not (isinstance(MAX_QUEUE_SIZE, int) and MAX_QUEUE_SIZE >= 1):
        return "MAX_QUEUE_SIZE must be an integer of at least 1"
    return None
CONFIG_ERROR = validate_config()
VALID_PASSKEYS = [k.encode() for k in Passkeys if k]

logger = logging.getLogger("serp")

fetch_slots = asyncio.Semaphore(MAX_CONCURRENT_FETCHES)
waiting = 0
class Ticket:
    def __init__(self) -> None:
        self.counted = True

    def mark_started(self) -> None:
        global waiting
        if self.counted:
            waiting -= 1
            self.counted = False
def try_enter_queue() -> bool:
    global waiting
    if waiting >= MAX_QUEUE_SIZE:
        return False
    waiting += 1
    return True
class ApiError(Exception):
    def __init__(self, status: int, message: str, headers: Optional[dict] = None) -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.headers = headers or {}
def json_error(status: int, message: str, headers: Optional[dict] = None) -> JSONResponse:
    return JSONResponse(
        {"error": message},
        status_code=status,
        headers={**CORS_HEADERS, **(headers or {})},
    )
class SearchRequest(BaseModel):
    query: str
    results: int = 1
    includeSummary: bool = False
    includeWikibox: bool = False
    includeDefinition: bool = Field(
        False,
        validation_alias=AliasChoices("includeDefinition", "includeDeffinition"),
    )
    passkeyProtection: Optional[bool] = None
    passkey: Optional[str] = None

    @field_validator("query")
    @classmethod
    def strip_query(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("query must not be empty")
        return value
def check_passkey(submitted: Optional[str]) -> None:
    if not passkeyProtection:
        return
    if not submitted:
        raise ApiError(401, "passkey required")
    if not VALID_PASSKEYS:
        raise ApiError(500, "server misconfigured")
    submitted_bytes = submitted.encode()
    matched = False
    for key in VALID_PASSKEYS:
        if hmac.compare_digest(submitted_bytes, key):
            matched = True
    if not matched:
        raise ApiError(403, "invalid passkey")
async def fetch_page(query: str, page: int, ticket: Ticket) -> str:
    first = (page - 1) * RESULTS_PER_PAGE + 1
    url = f"{BING_BASE_URL}?q={quote_plus(query)}&first={first}"
    await fetch_slots.acquire()
    try:
        ticket.mark_started()
        try:
            resp = await asyncio.wait_for(
                http_fetch(url, headers=BING_HEADERS), FETCH_TIMEOUT_SECONDS
            )
        except asyncio.TimeoutError:
            raise ApiError(502, "Bing request timed out")
        if resp.status != 200:
            raise ApiError(502, f"Bing returned status {resp.status}")
        return await resp.text()
    finally:
        fetch_slots.release()
def decode_bing_url(href: str) -> str:
    if "bing.com/ck/a" not in href:
        return href
    try:
        qstart = href.find("?")
        if qstart == -1:
            return href
        # Locate `u=` as a standalone query parameter (not embedded in another value).
        u_start = -1
        for prefix in ("&u=", "?u="):
            idx = href.find(prefix, qstart)
            if idx != -1:
                u_start = idx + len(prefix)
                break
        if u_start == -1:
            return href
        u_end = href.find("&", u_start)
        if u_end == -1:
            u_end = len(href)
        encoded = href[u_start:u_end]
        if encoded.startswith("a1"):
            encoded = encoded[2:]
        pad = (-len(encoded)) % 4
        if pad:
            encoded = encoded + "=" * pad
        return base64.urlsafe_b64decode(encoded).decode("utf-8", errors="replace")
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return href
def parse_results(html: str) -> list[dict]:
    items: list[dict] = []
    for block in _RE_RESULT_ITEMS.finditer(html):
        inner = block.group(0)
        m_link = _RE_TITLE_LINK.search(inner)
        if not m_link:
            continue
        href = m_link.group(1)
        title = _strip_tags(m_link.group(2))
        m_snip = _RE_SNIPPET.search(inner)
        snippet = _strip_tags(m_snip.group(1)) if m_snip else ""
        items.append({
            "title": title,
            "url": decode_bing_url(href),
            "snippet": snippet,
        })
    return items
def parse_summary(html: str) -> Optional[str]:
    m = _RE_SUMMARY.search(html)
    if not m:
        return None
    text = _strip_tags(m.group(1))
    return text or None
def parse_wikibox(html: str) -> Optional[dict]:
    m = _RE_WIKIBOX.search(html)
    if not m:
        return None
    inner = m.group(1)
    m_title = _RE_WIKIBOX_TITLE.search(inner)
    if not m_title:
        return None
    title = _strip_tags(m_title.group(1))
    if not title:
        return None
    m_desc = _RE_WIKIBOX_DESC.search(inner)
    m_link = _RE_WIKIBOX_LINK.search(inner)
    return {
        "title": title,
        "description": _strip_tags(m_desc.group(1)) if m_desc else "",
        "url": m_link.group(1) if m_link else None,
    }
def parse_definition(html: str) -> Optional[str]:
    m = _RE_DEFINITION.search(html)
    if not m:
        return None
    text = _strip_tags(m.group(1))
    return text or None
app = FastAPI()
@app.exception_handler(RequestValidationError)
async def handle_validation_error(request: Request, exc: RequestValidationError):
    message = exc.errors()[0].get("msg", "invalid request") if exc.errors() else "invalid request"
    return json_error(400, message)
@app.exception_handler(StarletteHTTPException)
async def handle_http_error(request: Request, exc: StarletteHTTPException):
    if exc.status_code == 404:
        return json_error(404, "not found")
    if exc.status_code == 405:
        return json_error(405, "method not allowed", {"Allow": "POST, OPTIONS"})
    return json_error(exc.status_code, str(exc.detail))
@app.exception_handler(ApiError)
async def handle_api_error(request: Request, exc: ApiError):
    return json_error(exc.status, exc.message, exc.headers)
@app.exception_handler(Exception)
async def handle_unexpected(request: Request, exc: Exception):
    logger.exception("unhandled error")
    return json_error(500, "internal server error")
@app.options("/api")
@app.options("/api/")
async def preflight() -> Response:
    return Response(status_code=204, headers=CORS_HEADERS)
@app.post("/api")
@app.post("/api/")
async def search(body: SearchRequest) -> JSONResponse:
    started = time.monotonic()
    if CONFIG_ERROR:
        logger.error("config error: %s", CONFIG_ERROR)
        raise ApiError(500, "server misconfigured")
    check_passkey(body.passkey)
    if not try_enter_queue():
        logger.warning("queue full (%d waiting)", waiting)
        raise ApiError(
            503,
            "queue full, please retry shortly",
            {"Retry-After": str(QUEUE_RETRY_AFTER_SECONDS)},
        )
    pages = max(1, min(body.results, MAX_PAGES))
    ticket = Ticket()
    try:
        htmls = await asyncio.gather(
            *(fetch_page(body.query, page, ticket) for page in range(1, pages + 1))
        )
    finally:
        ticket.mark_started()
    for html in htmls:
        if not _RE_HAS_RESULTS_LIST.search(html[:8192]):
            raise ApiError(502, "unexpected Bing response (possible consent or CAPTCHA page)")
    payload: dict = {"query": body.query}
    first_page = htmls[0]
    if body.includeSummary:
        summary = parse_summary(first_page)
        if summary:
            payload["summary"] = summary
    if body.includeWikibox:
        wikibox = parse_wikibox(first_page)
        if wikibox:
            payload["wikibox"] = wikibox
    if body.includeDefinition:
        definition = parse_definition(first_page)
        if definition:
            payload["definition"] = definition

    results: list[dict] = []
    for page_no, html in enumerate(htmls, start=1):
        items = parse_results(html)
        if not items:
            break
        for item in items:
            results.append({"position": len(results) + 1, "page": page_no, **item})
    payload["results"] = results

    logger.info(
        "search ok: query_len=%d pages=%d results=%d ms=%d",
        len(body.query), pages, len(results), int((time.monotonic() - started) * 1000),
    )
    return JSONResponse(payload, headers=CORS_HEADERS)
class Default(WorkerEntrypoint):
    async def fetch(self, request):
        return await asgi.fetch(app, request, self.env)
