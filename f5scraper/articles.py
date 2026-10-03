"""Full knowledge-base dump: every my.f5.com K-article saved as standalone HTML.

Unlike the vulns/EOL/compat crawls this does NOT render pages in the browser.
The Coveo search API (see discover.py) returns each K-article's full HTML body
in the raw field `sfdetails__c`, so the whole KB (~37k articles) is fetched in
~40 paginated API calls. The browser session is used once, to capture the guest
token.

Pagination is a @rowid cursor rather than discover.py's year-slicing: ~19k
articles share a Sep 2024 date, so no date slice stays under Coveo's 5000-result
cap, whereas `@rowid>{last}` sorted ascending never needs firstResult > 0.

Output:
  all_articles/{Knumber}.html : one standalone page per article — metadata
                                header (type, dates, products/versions, source
                                URL) followed by F5's article body verbatim.
  all_articles.json           : {"{Knumber}.html": "short description"} for
                                every file in all_articles/.
  article_metadata.json / article_updates.json / article_history/ : structured
                                metadata, recent activity, and revisions.

The API pass is cheap, so there is no manifest/TTL gating: `articles` fetches
everything; `updates` filters by source publication/update date. Files are
written only when their content changed. Deliberately
NOT recorded in manifest.json — vulns.py treats manifest keys as already-covered
advisories, so recording every K-number here would suppress advisory discovery.
"""

from __future__ import annotations

import html
import json
import logging
import re
import time
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .browser import ARTICLE_URL, ArticleSession
from .cache import Cache
from .discover import _POLITE_SLEEP, _capture_coveo_token, _coveo_search
from .updates import ArticleHistory

log = logging.getLogger("f5scraper.articles")

ARTICLES_DIR = "all_articles"
INDEX_FILE = "all_articles.json"

# The three Coveo sources that hold my.f5.com K-articles (everything else in
# the index is community posts, manuals, bug tracker entries, videos, ...).
_KB_AQ = (
    '@source==("SO_SENS_XS_SFDC_Knowledge",'
    '"SO_SENS_XS_SFDC_Knowledge_SA_Published",'
    '"SRC_XS_SFDC_SDC_Knowledge")'
)
_FIELDS = [
    "rowid",
    "f5_kb_id",
    "f5_title",
    "title",
    "f5_document_type",
    "sfdetails__c",
    "f5_original_published_date",
    "f5_updated_published_date",
    "f5_product",
    "sfapplies_to_products__c",
    "sfarticle_status__c",
]
_PAGE_SIZE = 1000
_MAX_ATTEMPTS = 3
_RETRY_SLEEP = 10.0
_DESC_MAX = 200
# Unattended daily runs prune files for articles that disappeared. If a run
# sees fewer than this share of the previous index, assume the Coveo index is
# mid-rebuild rather than that F5 retired thousands of articles: don't prune.
_MIN_KEEP_RATIO = 0.9

_K_RE = re.compile(r"^K\d+$")
_K_PREFIX_RE = re.compile(r"^K\d+\s*:\s*")
_DROP_RE = re.compile(r"<!--.*?-->|<(style|script)\b.*?</\1\s*>", re.S | re.I)
_BLOCK_END_RE = re.compile(r"</(?:p|div|h[1-6]|li|tr|ul|ol|table|blockquote|pre)\s*>|<br\s*/?>", re.I)
_CELL_END_RE = re.compile(r"</t[dh]\s*>", re.I)
_TAG_RE = re.compile(r"<[^>]+>")


def _iso_date(ms: Any) -> str | None:
    try:
        return datetime.fromtimestamp(int(ms) / 1000, tz=timezone.utc).date().isoformat()
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _first(value: Any) -> str:
    """Coveo multi-value fields arrive as lists; take the first value."""
    if isinstance(value, list):
        value = value[0] if value else ""
    return str(value or "")


def _applies_to(raw: dict[str, Any]) -> list[str]:
    """Product/version lines for the header, e.g. 'BIG-IP ASM: 17.1.0, 16.1.4'."""
    try:
        entries = json.loads(raw.get("sfapplies_to_products__c") or "[]")
    except ValueError:
        entries = []
    lines: list[str] = []
    for e in entries if isinstance(entries, list) else []:
        if not isinstance(e, dict) or not e.get("Product"):
            continue
        versions = ", ".join(str(v) for v in e.get("Versions") or [])
        lines.append(f"{e['Product']}: {versions}" if versions else str(e["Product"]))
    if lines:
        return lines
    products = raw.get("f5_product") or []
    return [str(p) for p in (products if isinstance(products, list) else [products])]


def _summary(body: str) -> str:
    """First real sentence of the body, as plain text capped at _DESC_MAX chars.

    Section headings ("Description", "Topic", "Known Issue", ...) come first in
    most bodies, so prefer the first line long enough to be prose — and one
    that isn't a lead-in ("... refer to the following article:") or the
    cross-reference it leads into ("K17411: ...").
    """
    text = _DROP_RE.sub("", body)
    text = _BLOCK_END_RE.sub("\n", text)
    text = _CELL_END_RE.sub(" ", text)
    text = html.unescape(_TAG_RE.sub("", text)).replace("\xa0", " ")
    lines = [" ".join(ln.split()) for ln in text.split("\n")]
    lines = [ln for ln in lines if ln]
    pick = next((ln for ln in lines if len(ln) >= 60 and not ln.endswith(":")
                 and not _K_PREFIX_RE.match(ln)), None) \
        or next((ln for ln in lines if len(ln) >= 40), None) \
        or " ".join(lines)
    if len(pick) > _DESC_MAX:
        pick = pick[:_DESC_MAX].rsplit(" ", 1)[0].rstrip(" ,;:") + "…"
    return pick


def _article(result: dict[str, Any]) -> dict[str, Any] | None:
    """Normalise one Coveo result; None if it has no usable K-number."""
    raw = result.get("raw", {})
    k = str(raw.get("f5_kb_id") or "").strip()
    if not _K_RE.match(k):
        k = (result.get("clickUri") or "").rstrip("/").split("/")[-1]
    if not _K_RE.match(k):
        return None
    title = _first(raw.get("f5_title")) or _K_PREFIX_RE.sub("", result.get("title") or "")
    return {
        "k": k,
        "title": title.strip(),
        "doc_type": _first(raw.get("f5_document_type")) or "Article",
        "published": _iso_date(raw.get("f5_original_published_date")),
        "updated": _iso_date(raw.get("f5_updated_published_date")),
        "status": _first(raw.get("sfarticle_status__c")),
        "applies_to": _applies_to(raw),
        "body": raw.get("sfdetails__c") or "",
    }


def _description(a: dict[str, Any]) -> str:
    summary = _summary(a["body"])
    head = f"{a['doc_type']}: {a['title']}"
    return f"{head} — {summary}" if summary else head


def _render(a: dict[str, Any], description: str) -> str:
    esc = html.escape
    url = ARTICLE_URL.format(k=a["k"])
    heading = esc(f"{a['k']}: {a['title']}")
    meta = [("Type", esc(a["doc_type"]))]
    if a["published"]:
        meta.append(("Published", a["published"]))
    if a["updated"]:
        meta.append(("Updated", a["updated"]))
    if a["status"]:
        meta.append(("Status", esc(a["status"])))
    if a["applies_to"]:
        items = "".join(f"<li>{esc(line)}</li>" for line in a["applies_to"])
        meta.append(("Applies to", f"<ul>{items}</ul>"))
    meta.append(("Source", f'<a href="{esc(url)}">{esc(url)}</a>'))
    rows = "\n".join(f"<dt>{label}</dt><dd>{value}</dd>" for label, value in meta)
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        f"<title>{heading}</title>\n"
        f'<meta name="description" content="{esc(description)}">\n'
        f'<link rel="canonical" href="{esc(url)}">\n'
        "</head>\n"
        "<body>\n"
        "<header>\n"
        f"<h1>{heading}</h1>\n"
        f"<dl>\n{rows}\n</dl>\n"
        "</header>\n"
        "<hr>\n"
        f"<article>\n{a['body']}\n</article>\n"
        "</body>\n"
        "</html>\n"
    )


def _search_page(auth: str, cursor: str | None, number: int, *, since: str | None = None) -> dict[str, Any]:
    aq = _KB_AQ
    if since:
        date_query = since.replace("-", "/")
        aq += (f" (@f5_updated_published_date>={date_query}"
               f" OR @f5_original_published_date>={date_query})")
    if cursor:
        aq += f" @rowid>{cursor}"
    last_err: Exception | None = None
    for attempt in range(_MAX_ATTEMPTS):
        try:
            return _coveo_search(
                auth, q="", aq=aq, number=number,
                sort="@rowid ascending", fields=_FIELDS,
            )
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ValueError) as exc:
            last_err = exc
            log.warning("articles: Coveo page failed (attempt %d/%d): %s",
                        attempt + 1, _MAX_ATTEMPTS, exc)
            if attempt < _MAX_ATTEMPTS - 1:
                time.sleep(_RETRY_SLEEP)
    raise RuntimeError(f"articles: Coveo API failed after {_MAX_ATTEMPTS} attempts: {last_err}")


async def run(
    session: ArticleSession, output_dir: Path, *, limit: int | None = None,
    recent_only: bool = False, days: int = 30,
) -> dict:
    cache = Cache(output_dir)
    auth = await _capture_coveo_token(session)
    history = ArticleHistory(cache)
    history.bootstrap()
    since = (datetime.now(timezone.utc).date() - timedelta(days=days)).isoformat() if recent_only else None

    index: dict[str, str] = {}
    seen: set[str] = set()
    changed = skipped = 0
    total: int | None = None
    cursor: str | None = None
    missing_body = False

    while limit is None or len(seen) < limit:
        number = _PAGE_SIZE if limit is None else min(_PAGE_SIZE, limit - len(seen))
        resp = _search_page(auth, cursor, number, since=since)
        if total is None:
            total = resp.get("totalCount", 0)
            log.info("articles: %d K-articles%s in the Coveo index", total,
                     f" published/updated since {since}" if since else "")
        results = resp.get("results", [])
        if not results:
            break
        for result in results:
            a = _article(result)
            if a is None:
                skipped += 1
                log.warning("articles: no K-number for %r — skipped", result.get("title"))
                continue
            if not isinstance(a["body"], str) or not a["body"].strip():
                skipped += 1
                missing_body = True
                log.warning("articles: missing HTML body for %s — keeping any existing copy", a["k"])
                continue
            # An article re-indexed mid-run gets a new, higher rowid and shows
            # up a second time; the later copy is the fresher one, so let it win.
            name = f"{a['k']}.html"
            description = _description(a)
            page = _render(a, description)
            history.record(a, description, page)
            if cache.write_text(f"{ARTICLES_DIR}/{name}", page):
                changed += 1
            index[name] = description
            seen.add(name)
        next_cursor = str(results[-1]["raw"]["rowid"])
        if cursor is not None and int(next_cursor) <= int(cursor):
            raise RuntimeError("articles: Coveo rowid cursor did not advance")
        cursor = next_cursor
        log.info("articles: %d fetched", len(seen))
        time.sleep(_POLITE_SLEEP)

    # Prune files for articles F5 no longer publishes — but only after a full,
    # complete enumeration, so a truncated run can never delete good data. A
    # partial run (--limit, or a short enumeration) instead updates the existing
    # index in place, keeping it in step with the files left on disk.
    pruned = 0
    previous: dict[str, str] = cache.read_json(INDEX_FILE) or {}
    complete = (not recent_only and not missing_body and limit is None
                and bool(total) and len(seen) + skipped >= total)
    shrunk = len(seen) < _MIN_KEEP_RATIO * len(previous)
    if complete and not shrunk:
        for p in sorted((cache.dir / ARTICLES_DIR).glob("*.html")):
            if p.name not in seen:
                history.remove(p.stem, p.read_text())
                p.unlink()
                pruned += 1
    else:
        if limit is None and not recent_only:
            log.warning(
                "articles: fetched %d (Coveo total %s, previous index %d) — %s, not pruning",
                len(seen), total, len(previous),
                "sharp drop vs previous run" if complete else "incomplete enumeration",
            )
        index = {**previous, **index}

    cache.write_json(INDEX_FILE, index)
    feed = history.save(days=days)
    log.info("articles: %d fetched, %d files written/updated, %d pruned, %d in index",
             len(seen), changed, pruned, len(index))
    return {"articles": len(seen), "changed": changed, "pruned": pruned,
            "recent_articles": feed["article_count"], "observed_changes": sum(history.counts.values())}
