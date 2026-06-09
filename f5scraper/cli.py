"""Command-line entrypoint: `python -m f5scraper.cli {vulns|eol|all} [opts]`."""

from __future__ import annotations

import argparse
import asyncio
import logging
from pathlib import Path

from .browser import ArticleSession
from . import vulns, eol, compat

DEFAULT_OUTPUT = Path("data/output")


async def _run(args: argparse.Namespace) -> None:
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
            )


def main() -> None:
    p = argparse.ArgumentParser(prog="f5scraper", description=__doc__)
    p.add_argument("command", choices=["vulns", "eol", "compat", "all"])
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT,
                   help="output/cache directory (default: data/output)")
    p.add_argument("--refresh", action="store_true",
                   help="ignore cache; re-scrape everything")
    p.add_argument("--limit", type=int, default=None,
                   help="cap number of quarterly reports (testing)")
    p.add_argument("--ttl-days", type=int, default=0,
                   help="re-scrape mutable articles older than N days (0 = always)")
    p.add_argument("--throttle", type=float, default=1.0,
                   help="seconds to wait between article loads")
    p.add_argument("--headful", action="store_true",
                   help="run a visible browser (debugging)")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    asyncio.run(_run(args))


if __name__ == "__main__":
    main()
