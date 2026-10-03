"""Structured KB metadata, observed changes, and preserved article revisions.

Existing HTML files establish a baseline, not a wave of newly discovered
articles. Only new content creates history entries. Source publication dates
and observation timestamps are kept separate: a date on F5's site is not proof
that this scraper observed a change on that date.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import date, datetime, timedelta, timezone
from html.parser import HTMLParser
from typing import Any

from .cache import Cache

log = logging.getLogger("f5scraper.updates")

METADATA_FILE = "article_metadata.json"
FEED_FILE = "article_updates.json"
HISTORY_DIR = "article_history"
_METADATA_FIELDS = ("title", "doc_type", "published", "updated", "status", "applies_to", "description")


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _body(page: str) -> str:
    return page.partition("<article>\n")[2].rpartition("\n</article>")[0]


def metadata(article: dict[str, Any], description: str, page: str) -> dict[str, Any]:
    return {
        "k": article["k"],
        **{key: article[key] for key in _METADATA_FIELDS if key != "description"},
        "description": description,
        "url": f"https://my.f5.com/manage/s/article/{article['k']}",
        "file": f"all_articles/{article['k']}.html",
        "content_hash": _hash(page),
        "body_hash": _hash(article["body"]),
    }


class _Header(HTMLParser):
    """Read the deterministic header produced by articles._render."""

    def __init__(self) -> None:
        super().__init__()
        self.values: dict[str, str] = {}
        self.products: list[str] = []
        self.description = ""
        self.url = ""
        self.tag = ""
        self.label = ""
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag == "meta" and attributes.get("name") == "description":
            self.description = attributes.get("content") or ""
        if tag == "link" and attributes.get("rel") == "canonical":
            self.url = attributes.get("href") or ""
        if tag in ("h1", "dt", "dd", "li"):
            self.tag, self.parts = tag, []

    def handle_data(self, data: str) -> None:
        if self.tag:
            self.parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag != self.tag:
            return
        value = "".join(self.parts).strip()
        if tag == "dt":
            self.label = value
        elif tag == "h1":
            self.values["heading"] = value
        elif tag == "li":
            self.products.append(value)
        elif tag == "dd":
            self.values[self.label] = value
        self.tag, self.parts = "", []


def metadata_from_html(k: str, page: str) -> dict[str, Any]:
    header = _Header()
    header.feed(page.partition("<hr>")[0])
    heading = header.values.get("heading", k)
    title = heading.removeprefix(f"{k}: ")
    result = metadata({
        "k": k,
        "title": title,
        "doc_type": header.values.get("Type", "Article"),
        "published": header.values.get("Published"),
        "updated": header.values.get("Updated"),
        "status": header.values.get("Status", ""),
        "applies_to": header.products,
        "body": _body(page),
    }, header.description, page)
    result["url"] = header.url or result["url"]
    return result


class ArticleHistory:
    def __init__(self, cache: Cache, *, observed_at: str | None = None) -> None:
        self.cache = cache
        self.catalog: dict[str, dict[str, Any]] = cache.read_json(METADATA_FILE) or {}
        self.observed_at = observed_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        self.counts = {kind: 0 for kind in ("new", "updated", "removed", "restored")}

    def bootstrap(self) -> None:
        """Index existing files without inventing historical observations."""
        for path in sorted((self.cache.dir / "all_articles").glob("K*.html")):
            if path.stem not in self.catalog:
                self.catalog[path.stem] = metadata_from_html(path.stem, path.read_text())
        log.info("updates: %d articles in metadata catalog", len(self.catalog))

    def _snapshot(self, k: str, page: str) -> str:
        rel = f"{HISTORY_DIR}/{k}/{_hash(page)}.html"
        self.cache.write_text(rel, page)
        return rel

    def _event(
        self, kind: str, before: dict[str, Any] | None, after: dict[str, Any] | None,
        old_page: str | None, new_page: str | None,
    ) -> None:
        current = after if after is not None else before
        assert current is not None
        k = current["k"]
        rel = f"{HISTORY_DIR}/{k}/changes.json"
        events = self.cache.read_json(rel) or []
        previous_hash = before["content_hash"] if before else None
        current_hash = after["content_hash"] if after else None
        # An interrupted run may have saved history just before the canonical
        # write. Repeating that same pending transition must not duplicate it.
        if events and (
            events[-1]["kind"], events[-1]["previous_hash"], events[-1]["content_hash"]
        ) == (kind, previous_hash, current_hash):
            return
        event = {
            "k": k,
            "kind": kind,
            "observed_at": self.observed_at,
            "title": current["title"],
            "url": current["url"],
            "doc_type": current["doc_type"],
            "published": current["published"],
            "updated": current["updated"],
            "previous_hash": previous_hash,
            "content_hash": current_hash,
            "body_changed": before is None or after is None or before["body_hash"] != after["body_hash"],
            "changed_fields": [key for key in _METADATA_FIELDS
                               if (before or {}).get(key) != (after or {}).get(key)],
            "previous_snapshot": self._snapshot(k, old_page) if old_page is not None else None,
            "snapshot": self._snapshot(k, new_page) if new_page is not None else None,
        }
        events.append(event)
        self.cache.write_json(rel, events)
        self.counts[kind] += 1

    def record(self, article: dict[str, Any], description: str, page: str) -> None:
        """Preserve history before the caller overwrites the canonical file."""
        current = metadata(article, description, page)
        path = self.cache.dir / current["file"]
        old_page = path.read_text() if path.exists() else None
        previous = self.catalog.get(article["k"])
        if old_page is not None:
            if previous is None or previous["content_hash"] != _hash(old_page):
                previous = metadata_from_html(article["k"], old_page)
            if previous["content_hash"] != current["content_hash"]:
                self._event("updated", previous, current, old_page, page)
        else:
            events = self.cache.read_json(f"{HISTORY_DIR}/{article['k']}/changes.json") or []
            kind = "restored" if events and events[-1]["kind"] in ("removed", "restored") else "new"
            self._event(kind, None, current, None, page)
        self.catalog[article["k"]] = current

    def remove(self, k: str, page: str) -> None:
        previous = self.catalog.get(k)
        if previous is None or previous["content_hash"] != _hash(page):
            previous = metadata_from_html(k, page)
        self._event("removed", previous, None, page, None)
        self.catalog.pop(k, None)

    def save(self, *, days: int = 30) -> dict[str, Any]:
        since = (date.fromisoformat(self.observed_at[:10]) - timedelta(days=days)).isoformat()
        recent = []
        for article in self.catalog.values():
            if max(article.get("published") or "", article.get("updated") or "") >= since:
                recent.append(article)
        recent.sort(key=lambda a: (max(a["published"] or "", a["updated"] or ""), a["k"]), reverse=True)
        changes = []
        for path in sorted((self.cache.dir / HISTORY_DIR).glob("*/changes.json")):
            for event in self.cache.read_json(str(path.relative_to(self.cache.dir))) or []:
                if event["observed_at"][:10] >= since:
                    changes.append(event)
        changes.sort(key=lambda e: (e["observed_at"], e["k"]), reverse=True)
        feed = {
            "since": since,
            "article_count": len(recent),
            "articles": recent,
            "change_count": len(changes),
            "changes": changes,
        }
        self.cache.write_json(METADATA_FILE, self.catalog)
        self.cache.write_json(FEED_FILE, feed)
        log.info("updates: %d recently published/updated articles, %d observed changes; this run %s",
                 len(recent), len(changes), self.counts)
        return feed
