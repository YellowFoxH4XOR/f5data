"""K9476 hardware/software compatibility crawl.

Mirrors the eol.py pattern: render the article, parse its tables into
CompatRecords (which hardware platform supports which software versions), write
a per-source canonical file, and rebuild a combined compat.json. Mutable
(F5 revises the matrix), so TTL-refreshed.
"""

from __future__ import annotations

import logging
from pathlib import Path

from .browser import ArticleSession
from .cache import Cache, content_hash
from . import parse

log = logging.getLogger("f5scraper.compat")

SOURCE_K = "K9476"


async def run(session: ArticleSession, output_dir: Path, *, refresh: bool = False,
              ttl_days: int = 0) -> dict:
    cache = Cache(output_dir, refresh=refresh, ttl_days=ttl_days)

    if cache.should_scrape(SOURCE_K, "mutable"):
        try:
            data = await session.render_article(SOURCE_K)
            records = parse.parse_compat(data)
            payload = {
                "source": SOURCE_K,
                "updated_date": parse.normalize_date(data.get("updated")),
                "records": [r.to_dict() for r in records],
            }
            cache.write_json(f"compat/{SOURCE_K}.json", payload)
            cache.record(SOURCE_K, content_hash(payload), "mutable")
            log.info("compat %s: %d records", SOURCE_K, len(records))
        except RuntimeError as e:
            log.warning("compat article %s failed: %s", SOURCE_K, e)
    else:
        log.info("skip compat %s (cached)", SOURCE_K)

    sources = cache.glob_json("compat")
    all_records = [rec for s in sources for rec in s.get("records", [])]
    cache.write_json("compat.json", {
        "source_count": len(sources),
        "record_count": len(all_records),
        "sources": sources,
    })
    cache.save_manifest()
    log.info("compat: %d records from %d sources", len(all_records), len(sources))
    return {"records": len(all_records)}
