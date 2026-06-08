"""Repo-backed incremental cache.

The committed `data/output/` tree IS the datastore and the cache. A run reads
the previous `manifest.json`, decides what to (re)scrape based on each article's
mutability class, and writes canonical entity files only when their content
actually changed (so unchanged articles produce zero git diff).

Mutability classes:
  - "index"     : always re-scraped (cheap; discovers new quarters).
  - "immutable" : scraped once, then skipped forever (closed past quarters).
  - "mutable"   : re-scraped when older than `ttl_days` (CVE details, EOL pages
                  whose fixed-in versions / lifecycle dates change over time).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class Cache:
    def __init__(self, output_dir: Path, refresh: bool = False, ttl_days: int = 0):
        self.dir = Path(output_dir)
        self.refresh = refresh
        self.ttl_days = ttl_days
        self.manifest_path = self.dir / "manifest.json"
        self.manifest: dict[str, dict[str, Any]] = {}
        if self.manifest_path.exists():
            self.manifest = json.loads(self.manifest_path.read_text())

    # -- scrape decisions ---------------------------------------------------- #

    def should_scrape(self, k: str, mutability: str) -> bool:
        if self.refresh or mutability == "index":
            return True
        entry = self.manifest.get(k)
        if entry is None:
            return True
        if mutability == "immutable":
            return False
        # mutable: honor TTL (ttl_days <= 0 means always re-scrape)
        if self.ttl_days <= 0:
            return True
        try:
            ts = datetime.fromisoformat(entry["scraped_at"])
        except (KeyError, ValueError):
            return True
        return datetime.now(timezone.utc) - ts >= timedelta(days=self.ttl_days)

    def record(self, k: str, content_hash: str, mutability: str) -> None:
        self.manifest[k] = {
            "scraped_at": _now_iso(),
            "content_hash": content_hash,
            "mutability": mutability,
        }

    # -- persistence helpers ------------------------------------------------- #

    def save_manifest(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        _write_if_changed(self.manifest_path, self.manifest)

    def read_json(self, rel: str) -> Any | None:
        p = self.dir / rel
        return json.loads(p.read_text()) if p.exists() else None

    def write_json(self, rel: str, obj: Any) -> bool:
        """Write `obj` to `rel`; returns True if the file changed on disk."""
        p = self.dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        return _write_if_changed(p, obj)

    def glob_json(self, subdir: str) -> list[Any]:
        d = self.dir / subdir
        if not d.is_dir():
            return []
        return [json.loads(p.read_text()) for p in sorted(d.glob("*.json"))]


def _write_if_changed(path: Path, obj: Any) -> bool:
    new = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if path.exists() and path.read_text() == new:
        return False
    path.write_text(new)
    return True


def content_hash(obj: Any) -> str:
    import hashlib

    blob = json.dumps(obj, sort_keys=True, ensure_ascii=False).encode()
    return hashlib.sha256(blob).hexdigest()[:16]
