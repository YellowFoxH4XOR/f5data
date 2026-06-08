"""EOL / lifecycle crawl: software + hardware support dates.

Sources:
  - K5903  : BIG-IP software support policy (software)
  - K4309  : F5 hardware product lifecycle (hardware)
  - K11478 : End of Life / End of Sale index (links to per-product articles)

All EOL articles are "mutable" — F5 extends and revises lifecycle dates, so we
re-scrape each run (subject to TTL). Output is rebuilt into eol.json from the
per-source canonical files, keeping it duplicate-free.
"""

from __future__ import annotations

import logging
from pathlib import Path

from .browser import ArticleSession
from .cache import Cache, content_hash
from . import parse

log = logging.getLogger("f5scraper.eol")

# (article, category) pairs to scrape directly.
SOURCES = [
    ("K5903", "software"),
    ("K4309", "hardware"),
]
INDEX_K = "K11478"


async def run(session: ArticleSession, output_dir: Path, *, refresh: bool = False,
              follow_index: bool = True, ttl_days: int = 0) -> dict:
    cache = Cache(output_dir, refresh=refresh, ttl_days=ttl_days)
    total = 0

    sources = list(SOURCES)

    # The EOL index (K11478) links out to additional per-product lifecycle
    # articles. Render it to discover them and queue any we can categorize.
    if follow_index and cache.should_scrape(INDEX_K, "mutable"):
        try:
            idx = await session.render_article(INDEX_K)
            for link in idx.get("links", []):
                k = parse.k_from_href(link.get("href"))
                title = (link.get("text") or "").lower()
                if not k or k in {s[0] for s in sources}:
                    continue
                if "end of life" in title or "end of sale" in title or "eol" in title:
                    cat = "hardware" if "hardware" in title or "platform" in title else "software"
                    sources.append((k, cat))
            cache.record(INDEX_K, content_hash([s[0] for s in sources]), "mutable")
        except RuntimeError as e:
            log.warning("EOL index %s failed: %s", INDEX_K, e)

    for k, category in sources:
        if not cache.should_scrape(k, "mutable"):
            log.info("skip EOL %s (cached)", k)
            continue
        try:
            data = await session.render_article(k)
        except RuntimeError as e:
            log.warning("EOL article %s failed: %s", k, e)
            continue
        records = parse.parse_eol(data, category)
        if not records:
            log.info("EOL %s: no lifecycle tables found", k)
            continue
        payload = {
            "source": k,
            "category": category,
            "updated_date": parse.normalize_date(data.get("updated")),
            "records": [r.to_dict() for r in records],
        }
        cache.write_json(f"eol/{k}.json", payload)
        cache.record(k, content_hash(payload), "mutable")
        total += len(records)
        log.info("EOL %s: %d records", k, len(records))

    # Rebuild combined eol.json from per-source files.
    sources_data = cache.glob_json("eol")
    all_records = [rec for s in sources_data for rec in s.get("records", [])]
    combined = {
        "source_count": len(sources_data),
        "record_count": len(all_records),
        "sources": sources_data,
    }
    cache.write_json("eol.json", combined)
    cache.save_manifest()
    log.info("eol: %d records from %d sources", len(all_records), len(sources_data))
    return {"sources": len(sources_data), "records": len(all_records)}
