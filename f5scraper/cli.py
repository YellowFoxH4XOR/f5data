"""Command-line entrypoint: `python -m f5scraper.cli {vulns|eol|compat|articles|updates|docs|all} [opts]`."""

from __future__ import annotations

import argparse
import asyncio
import logging
from pathlib import Path

from .browser import ArticleSession
from .cache import Cache
from .updates import ArticleHistory
from . import vulns, eol, compat, articles, docs

DEFAULT_OUTPUT = Path("data/output")


async def _run(args: argparse.Namespace) -> None:
    if args.command == "docs":
        await docs.run(args.output, source_names=args.doc_source, limit=args.limit,
                       refresh=args.refresh, ttl_days=args.ttl_days,
                       throttle=args.throttle, workers=args.workers)
        return
    if args.command == "updates" and args.local:
        history = ArticleHistory(Cache(args.output))
        history.bootstrap()
        history.save(days=args.days)
        return
    async with ArticleSession(
        headless=not args.headful,
        throttle_seconds=args.throttle,
    ) as session:
        # For `all`, run EOL + compat first so the CVE EOL cross-link sees fresh
        # eol.json in the same invocation.
        if args.command in ("eol", "all"):
            await eol.run(
                session, args.output,
                refresh=args.refresh, ttl_days=args.ttl_days,
            )
        if args.command in ("compat", "all"):
            await compat.run(
                session, args.output,
                refresh=args.refresh, ttl_days=args.ttl_days,
            )
        if args.command in ("vulns", "all"):
            await vulns.run(
                session, args.output,
                refresh=args.refresh, limit=args.limit, ttl_days=args.ttl_days,
                no_discover=args.no_discover,
            )
        # Not part of `all`: the full KB dump is ~37k files and is run on its own.
        if args.command in ("articles", "updates"):
            await articles.run(session, args.output, limit=args.limit,
                               recent_only=args.command == "updates", days=args.days)


def _positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def main() -> None:
    p = argparse.ArgumentParser(prog="f5scraper", description=__doc__)
    p.add_argument("command", choices=["vulns", "eol", "compat", "articles", "updates", "docs", "all"])
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT,
                   help="output/cache directory (default: data/output)")
    p.add_argument("--refresh", action="store_true",
                   help="ignore cache; re-scrape everything")
    p.add_argument("--limit", type=_positive_int, default=None,
                   help="cap reports / KB articles / documentation page fetches")
    p.add_argument("--ttl-days", type=int, default=None,
                   help="re-scrape content older than N days (default: 7 for docs, 0/always otherwise)")
    p.add_argument("--throttle", type=float, default=1.0,
                   help="seconds between article loads or documentation HTTP requests")
    p.add_argument("--headful", action="store_true",
                   help="run a visible browser (debugging)")
    p.add_argument("--no-discover", action="store_true",
                   help="skip Coveo search-based advisory discovery (step 3c)")
    p.add_argument("--days", type=_positive_int, default=30,
                   help="recent publication/change window for articles/updates (default: 30 days)")
    p.add_argument("--local", action="store_true",
                   help="updates only: build metadata/feed from existing HTML without network access")
    p.add_argument("--doc-source", action="append", choices=list(docs.SOURCES),
                   help="docs only: restrict to a source; repeat to select several (default: all)")
    p.add_argument("--workers", type=_positive_int, default=4,
                   help="concurrent documentation downloads (default: 4)")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()
    if args.ttl_days is None:
        args.ttl_days = 7 if args.command == "docs" else 0
    if args.doc_source and args.command != "docs":
        p.error("--doc-source is only supported by the docs command")
    if args.local and args.command != "updates":
        p.error("--local is only supported by the updates command")
    if args.local and args.limit is not None:
        p.error("--local cannot be combined with --limit")

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    asyncio.run(_run(args))


if __name__ == "__main__":
    main()
