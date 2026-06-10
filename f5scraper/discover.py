"""Coveo-based discovery of my.f5.com Security Advisory articles.

Why this exists: the main ingestion pipeline is index-driven — it only sees
CVEs that appear in K12201527's Scheduled QSN table or Additional Security
Announcements table. Standalone advisory articles never linked from K12201527
are invisible to that pipeline. The Coveo search API (the same backend the
my.f5.com search bar talks to) exposes ALL 5000+ "Security Advisory" articles
with their K-numbers and titles, accessible with a guest JWT captured from one
browser page load (~5 s). This module enumerates that full set and returns the
K-numbers not yet seen by the rest of the pipeline.

Public surface
--------------
async enumerate_advisories(session) -> list[dict]
    Returns all advisory dicts [{k, title, url, original_published_ms,
    last_updated_ms}] whose titles match the advisory regex. Uses session's
    already-running Playwright browser for token capture — does NOT launch a
    second browser. Raises RuntimeError on unrecoverable failure.

filter_new(advisories, covered_ks) -> list[dict]
    Returns only advisory dicts whose k is not in covered_ks.

ADVISORY_RE
    The compiled regex used to title-filter. Exported so callers can apply it
    independently if needed.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
import urllib.error
import urllib.request
from typing import Any

from .browser import ArticleSession

log = logging.getLogger("f5scraper.discover")

# ---------------------------------------------------------------------------
# Coveo endpoint constants
# ---------------------------------------------------------------------------

_ORG_ID = "f5networksproduction5vkhn00h"
_ENDPOINT = (
    f"https://{_ORG_ID}.org.coveo.com/rest/search/v2"
    f"?organizationId={_ORG_ID}"
)
_SEARCH_TOKEN_URL = "https://my.f5.com/manage/s/global-search/vulnerability%20CVE"
_ADVISORY_AQ = '@f5_document_type="Security Advisory"'
_PAGE_SIZE = 1000
_HTTP_TIMEOUT = 30
_POLITE_SLEEP = 1.0  # seconds between paginated API calls

# ---------------------------------------------------------------------------
# Title filter — conservative regex that matches security advisory titles
# ---------------------------------------------------------------------------
#
# Patterns observed:
#   K000158112: iputils vulnerability CVE-2025-47268
#   K15893: Apache HTTP server vulnerabilities CVE-2014-0117, CVE-2014-0118
#   K23565223: Apache vulnerability CVE-2017-9788
#   K97810133: BIND vulnerability CVE-2020-8616
#   K23440942: Insufficient validation of ICMP error messages CVE-2004-0790 (…)
#
# The Coveo filter already restricts to @f5_document_type="Security Advisory",
# so the regex is a second guard — it validates we got what we expected and
# catches any stray non-advisory documents that might leak through.
# We cast a wide net: any title that contains at least one CVE-YYYY-NNNNN token
# OR ends in a known advisory keyword, all starting with the K<digits>: prefix.

ADVISORY_RE = re.compile(
    r"^K\d+\s*:\s*.*"      # must start with K<digits>:
    r"(?:"
    r"CVE-\d{4}-\d{4,}"    # has at least one CVE ID
    r"|vulnerabilit"        # or has "vulnerability/vulnerabilities"
    r"|security\s+(?:advisory|exposure|notification)"  # or explicit label
    r"|exposure"
    r")",
    re.IGNORECASE,
)

# Negative filter: digest/overview pages that match ADVISORY_RE incidentally but
# are index-style documents listing many CVEs rather than per-CVE advisories.
# These should not be rendered as single advisory articles.
_DIGEST_RE = re.compile(
    r"^K\d+\s*:\s*(?:overview|list)\s+of\s+",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Token capture via Playwright request interception
# ---------------------------------------------------------------------------

async def _capture_coveo_token(session: ArticleSession) -> str:
    """Capture a Coveo guest JWT by intercepting the first search XHR.

    Reuses the session's existing Playwright page — no second browser launch.
    The token is a 24-hour guest/anonymous JWT; no login required.

    Raises RuntimeError if no token is captured within the timeout.
    """
    page = session._page  # noqa: SLF001 — we own this internal
    assert page is not None, "ArticleSession not started"

    token_holder: list[str] = []

    def on_request(req: Any) -> None:
        if "coveo.com/rest/search" in req.url:
            auth = req.headers.get("authorization", "")
            if auth.startswith("Bearer ") and not token_holder:
                token_holder.append(auth)

    page.on("request", on_request)
    try:
        log.info("discover: navigating to Coveo search page to capture token")
        await page.goto(_SEARCH_TOKEN_URL, wait_until="domcontentloaded", timeout=30_000)
        for _ in range(30):
            if token_holder:
                break
            await asyncio.sleep(1)
    finally:
        page.remove_listener("request", on_request)

    if not token_holder:
        raise RuntimeError(
            "discover: failed to capture Coveo token — no XHR to coveo.com/rest/search "
            "observed within 30 s of loading the search page"
        )

    log.info("discover: Coveo token captured")
    return token_holder[0]  # "Bearer eyJ..."


# ---------------------------------------------------------------------------
# Coveo REST search helper (pure stdlib HTTP)
# ---------------------------------------------------------------------------

def _coveo_search(
    auth_header: str,
    *,
    q: str = "",
    aq: str = "",
    number: int = _PAGE_SIZE,
    first_result: int = 0,
    sort: str = "date ascending",
) -> dict[str, Any]:
    """POST one page of results to the Coveo search API.

    Raises urllib.error.HTTPError / urllib.error.URLError on network failure;
    raises RuntimeError on a non-200 response that urllib doesn't already raise.
    The caller is responsible for raising on unexpected HTTP codes.
    """
    body: dict[str, Any] = {
        "locale": "en-US",
        "debug": False,
        "tab": "default",
        "referrer": "default",
        "timezone": "GMT",
        "actionsHistory": [],
        "pipeline": "askf5-federatedsearch",
        "enableQuerySyntax": True,   # required for @field= syntax
        "searchHub": "myF5",
        "sortCriteria": sort,
        "analytics": {
            "originContext": "Search",
            "actionCause": "searchboxSubmit",
        },
        "fieldsToInclude": [
            "title",
            "date",
            "uri",
            "f5_document_type",
            "f5_original_published_date",
            "f5_updated_published_date",
            "sfknowledgearticleid",
            "sfid",
            "f5_kb_public",
        ],
        "q": q,
        "aq": aq,
        "numberOfResults": number,
        "firstResult": first_result,
    }
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        _ENDPOINT,
        data=data,
        headers={
            "Authorization": auth_header,
            "Content-Type": "application/json",
            "Origin": "https://my.f5.com",
            "Referer": "https://my.f5.com/",
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
            ),
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
        return json.loads(resp.read())  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Result extraction
# ---------------------------------------------------------------------------

def _extract_article_info(result: dict[str, Any]) -> dict[str, Any]:
    """Extract a normalised advisory dict from one Coveo search result."""
    raw = result.get("raw", {})
    title = result.get("title", "")
    click_uri: str = result.get("clickUri", raw.get("sysuri", ""))
    # K-number: last path segment of clickUri (most reliable)
    # e.g. https://my.f5.com/manage/s/article/K000158112 → K000158112
    k_number = click_uri.rstrip("/").split("/")[-1] if click_uri else ""
    if not k_number.upper().startswith("K"):
        # fall back to parsing the title prefix
        m = re.match(r"^(K\d+)\s*:", title)
        k_number = m.group(1) if m else ""
    return {
        "k": k_number,
        "title": title,
        "url": click_uri,
        "original_published_ms": raw.get("f5_original_published_date"),
        "last_updated_ms": raw.get("f5_updated_published_date"),
        "sf_article_id": raw.get("sfknowledgearticleid", ""),
    }


# ---------------------------------------------------------------------------
# Main enumeration — runs in the async context so it can reuse the session page
# ---------------------------------------------------------------------------

def _enumerate_year_slice(
    auth_header: str,
    year: int,
) -> list[dict[str, Any]]:
    """Fetch all Security Advisory results for one calendar year.

    Year-slicing is required because Coveo enforces a hard cap: requests with
    firstResult >= 5000 return 0 results even when totalCount > 5000. All known
    per-year slice sizes are well under 5000 (the largest observed is 2023: 3438).
    If a future year-slice itself exceeds 4999, this function raises RuntimeError
    rather than silently truncating — the caller should split by quarter then.
    """
    _HARD_CAP = 4999   # firstResult values >= this return empty on Coveo
    aq = f'{_ADVISORY_AQ} @date>={year}/01/01 @date<={year}/12/31'
    raw: list[dict[str, Any]] = []
    first_result = 0

    # Initial call to get totalCount for this slice.
    try:
        resp = _coveo_search(auth_header, q="", aq=aq, number=_PAGE_SIZE, first_result=0)
    except (urllib.error.HTTPError, urllib.error.URLError) as exc:
        raise RuntimeError(
            f"discover: Coveo API failed for year-slice {year}: {exc}"
        ) from exc
    total = resp.get("totalCount", 0)
    if total > _HARD_CAP:
        raise RuntimeError(
            f"discover: year-slice {year} has totalCount={total} which exceeds "
            f"the Coveo hard cap of {_HARD_CAP}; split by quarter and retry"
        )
    raw.extend(resp.get("results", []))
    first_result += _PAGE_SIZE

    while first_result < total:
        time.sleep(_POLITE_SLEEP)
        try:
            resp = _coveo_search(
                auth_header, q="", aq=aq,
                number=_PAGE_SIZE, first_result=first_result,
            )
        except (urllib.error.HTTPError, urllib.error.URLError) as exc:
            raise RuntimeError(
                f"discover: Coveo API failed on page for year {year} "
                f"at firstResult={first_result}: {exc}"
            ) from exc
        batch = resp.get("results", [])
        if not batch:
            log.warning(
                "discover: empty batch at firstResult=%d for year %d "
                "(expected totalCount=%d); stopping slice early with %d results",
                first_result, year, total, len(raw),
            )
            break
        raw.extend(batch)
        first_result += _PAGE_SIZE

    log.info("discover: year %d → %d results (totalCount=%d)", year, len(raw), total)
    return raw


async def enumerate_advisories(session: ArticleSession) -> list[dict[str, Any]]:
    """Enumerate all Security Advisory articles from the Coveo search API.

    Uses the session's Playwright page to capture a guest JWT (one page load,
    ~5 s), then paginates the Coveo REST API per calendar year using stdlib
    urllib — no additional browser renders. Year-slicing is required because
    Coveo enforces a hard cap of firstResult < 5000; plain pagination truncates
    the result set at ~4999 items when totalCount exceeds 5000.

    The article's "year" is determined by its f5_updated_published_date (the
    field Coveo's @date filter references), not its original publish date.
    Example: K000158112 was originally published 2025-12-09 but appears in the
    2026 year-slice because it was last updated 2026-05-29.

    Returns a list of article dicts (deduplicated by K-number):
        {k, title, url, original_published_ms, last_updated_ms, sf_article_id}

    Raises RuntimeError on unrecoverable failures (token capture, HTTP error,
    a year-slice exceeding the 4999 hard cap). Never silently returns a partial
    set without logging what was dropped.
    """
    auth = await _capture_coveo_token(session)

    # Determine the year range: probe total count first to confirm the API is
    # reachable, then sweep years from the first known advisory year (2013,
    # based on observed data) through the current year + 1 (to catch any
    # article updated with a future timestamp).
    log.info("discover: probing Coveo total advisory count")
    try:
        probe = _coveo_search(auth, q="", aq=_ADVISORY_AQ, number=1, first_result=0)
    except (urllib.error.HTTPError, urllib.error.URLError) as exc:
        raise RuntimeError(f"discover: Coveo probe request failed: {exc}") from exc

    total_count: int = probe.get("totalCount", 0)
    if total_count == 0:
        raise RuntimeError(
            "discover: Coveo returned totalCount=0 for Security Advisory filter — "
            "the API may have changed or the token may be invalid"
        )
    log.info("discover: totalCount=%d Security Advisory articles across all years", total_count)

    # Sweep years. Start from 2013 (earliest observed advisory data) through
    # current year + 1. We include next year as a safety net for articles with
    # future-dated update timestamps.
    import datetime as _dt
    current_year = _dt.datetime.now(_dt.timezone.utc).year
    years = range(2013, current_year + 2)

    all_raw: list[dict[str, Any]] = []
    for year in years:
        time.sleep(_POLITE_SLEEP)
        try:
            year_raw = _enumerate_year_slice(auth, year)
        except RuntimeError as exc:
            raise RuntimeError(
                f"discover: year-slice enumeration failed for {year}: {exc}"
            ) from exc
        all_raw.extend(year_raw)

    log.info("discover: collected %d raw results across all year-slices", len(all_raw))

    # --- normalise, dedup by K-number, title-filter ------------------------- #
    seen_ks: set[str] = set()
    articles: list[dict[str, Any]] = []
    skipped_no_k = 0
    skipped_regex = 0
    for result in all_raw:
        info = _extract_article_info(result)
        if not info["k"]:
            skipped_no_k += 1
            continue
        if info["k"] in seen_ks:
            continue   # same article can appear in multiple year-slices if updated across year boundary
        seen_ks.add(info["k"])
        if not ADVISORY_RE.search(info["title"]):
            skipped_regex += 1
            log.debug("discover: title-filter dropped %s: %r", info["k"], info["title"])
            continue
        if _DIGEST_RE.search(info["title"]):
            skipped_regex += 1
            log.debug("discover: digest-filter dropped %s: %r", info["k"], info["title"])
            continue
        articles.append(info)

    if skipped_no_k:
        log.warning("discover: %d results had no parseable K-number — skipped", skipped_no_k)
    if skipped_regex:
        log.info(
            "discover: %d results filtered by ADVISORY_RE (no CVE/vuln/exposure in title); "
            "%d articles pass",
            skipped_regex, len(articles),
        )
    else:
        log.info("discover: %d unique articles pass title filter", len(articles))

    return articles


# ---------------------------------------------------------------------------
# Dedup helper
# ---------------------------------------------------------------------------

def filter_new(
    advisories: list[dict[str, Any]],
    covered_ks: set[str],
    manifest: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Return advisory dicts whose k is not in covered_ks, or whose content has
    been updated on my.f5.com since it was last scraped.

    covered_ks should be the union of:
      - manifest keys (all ever-scraped K-numbers)
      - cves/*.json article_k values
      - reports/*.json k_number values
    See vulns.py for how this set is built before calling this function.

    If manifest is provided, advisory articles previously scraped (k in covered_ks
    AND k in manifest) whose Coveo last_updated_ms is more recent than the manifest
    scraped_at timestamp are treated as stale and re-included for re-scraping.
    """
    from datetime import datetime, timezone

    out: list[dict[str, Any]] = []
    for a in advisories:
        k = a["k"]
        if k not in covered_ks:
            out.append(a)
            continue
        # Already scraped — check staleness if manifest available.
        if manifest is None:
            continue
        entry = manifest.get(k)
        if entry is None:
            continue
        last_updated_ms = a.get("last_updated_ms")
        if last_updated_ms is None:
            continue
        try:
            scraped_at = datetime.fromisoformat(entry["scraped_at"])
        except (KeyError, ValueError):
            continue
        last_updated_dt = datetime.fromtimestamp(last_updated_ms / 1000, tz=timezone.utc)
        if last_updated_dt > scraped_at:
            out.append(a)
    return out
