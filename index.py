# Sriail (Github) Basic Serp Api For Cloudflare (Python)
# For More, Read the Full README.md
import asyncio
import base64
import hmac
import logging
import time
from typing import Optional
from urllib.parse import parse_qs, quote_plus, urlparse
from bs4 import BeautifulSoup
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import AliasChoices, BaseModel, Field, field_validator
from starlette.exceptions import HTTPException as StarletteHTTPException
from workers import WorkerEntrypoint
from workers import asgi
from workers import fetch as http_fetch
#--------------------------------------------------------------------------------
# Configuration (For Your Personal Needs / Configureation)
passkeyProtection: bool = False  # Set this Booleen to True to Require Passwords
Passkeys: list[str] = [
    "K1-SERP-GtAat5hutd2vRPLCFvPlpZMn5CuMJ5dR",
    "K2-SERP-NU0cbIlsKpIgPEWO7Sn0IVpuQ5Ge4H4c",
    # Add More Keys If Needed, Change the Default Keys for Maximum Security
]
MAX_CONCURRENT_FETCHES: int = 6     # Max In-Flight
MAX_QUEUE_SIZE: int = 500           # Max In-Que
QUEUE_RETRY_AFTER_SECONDS: int = 5  # Max Retry If Que Overflows

BING_BASE_URL = "https://www.bing.com/search" # DO NOT EDIT (Base uses bing)
RESULTS_PER_PAGE = 10 # DO NOT EDIT (const for bing)
MAX_PAGES = 10 # Edit for more search results if needed
FETCH_TIMEOUT_SECONDS = 10.0 # Edit for more or less timout in response time
# Serp Config End (Main)
#--------------------------------------------------------------------------------
BING_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/129.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9", # Edit if needed for lang
}

SELECTORS = {
    "results_list": "ol#b_results",
    "result": "ol#b_results > li.b_algo",
    "title": "h2 a",
    "snippet": "div.b_caption p",
    "summary": "div.b_text",
    "wikibox": "div.b_entitytp",
    "wikibox_title": "h2",
    "wikibox_desc": "div.b_snippet",
    "definition": "div.b_dict",
}

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
}

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

fetch_slots = asyncio.Semaphore(MAX_CONCURRENT_FETCHES)  # Limits in-flight Bing fetches.
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
    for key in VALID_PASSKEYS:  # Check every key so timing does not reveal the closest match.
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
        encoded = parse_qs(urlparse(href).query).get("u", [""])[0]
        if encoded.startswith("a1"):
            encoded = encoded[2:]
        encoded += "=" * (-len(encoded) % 4)
        return base64.urlsafe_b64decode(encoded).decode("utf-8")
    except Exception:
        return href

def parse_results(soup: BeautifulSoup) -> list[dict]:
    items = []
    for node in soup.select(SELECTORS["result"]):
        link = node.select_one(SELECTORS["title"])
        if not link or not link.get("href"):
            continue
        snippet = node.select_one(SELECTORS["snippet"])
        items.append({
            "title": link.get_text(strip=True),
            "url": decode_bing_url(link["href"]),
            "snippet": snippet.get_text(" ", strip=True) if snippet else "",
        })
    return items

def parse_summary(soup: BeautifulSoup) -> Optional[str]:
    node = soup.select_one(SELECTORS["summary"])
    return node.get_text(" ", strip=True) if node else None

def parse_wikibox(soup: BeautifulSoup) -> Optional[dict]:
    node = soup.select_one(SELECTORS["wikibox"])
    if not node:
        return None
    title = node.select_one(SELECTORS["wikibox_title"])
    if not title:
        return None
    desc = node.select_one(SELECTORS["wikibox_desc"])
    link = node.select_one("a[href]")
    return {
        "title": title.get_text(strip=True),
        "description": desc.get_text(" ", strip=True) if desc else "",
        "url": link["href"] if link else None,
    }

def parse_definition(soup: BeautifulSoup) -> Optional[str]:
    node = soup.select_one(SELECTORS["definition"])
    return node.get_text(" ", strip=True) if node else None

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
        ticket.mark_started()  # Covers requests that failed before getting a slot.

    soups = [BeautifulSoup(html, "html.parser") for html in htmls]
    for soup in soups:
        if soup.select_one(SELECTORS["results_list"]) is None:
            raise ApiError(502, "unexpected Bing response (possible consent or CAPTCHA page)")

    payload: dict = {"query": body.query}
    first_page = soups[0]
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
    for page_no, soup in enumerate(soups, start=1):
        items = parse_results(soup)
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
