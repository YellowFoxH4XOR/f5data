"""Post-processing enrichment pass over the scraped CVE files.

Runs after CVEs are scraped: decomposes CVSS vectors, applies CISA KEV + EPSS,
cross-links each affected branch to its EOL status, and computes a heuristic
priority. Writes each canonical `cves/*.json` only when it changed (so unchanged
records stay diff-free), keeping the existing output format.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import date
from pathlib import Path

from . import parse
from .cache import _write_if_changed

log = logging.getLogger("f5scraper.enrich")

_BRANCH_RE = re.compile(r"(\d+\.\d+)")


def _branch_of(version_range: str | None) -> str | None:
    """'17.1.0 - 17.1.2' -> '17.1'; '16.1.x' -> '16.1'; '16.x' -> None."""
    m = _BRANCH_RE.search(version_range or "")
    return m.group(1) if m else None


def _is_past(date_text: str | None) -> bool | None:
    iso = parse.normalize_date(date_text)
    if not iso:
        return None
    try:
        return date.fromisoformat(iso) < date.today()
    except ValueError:
        return None


def _build_eots_map(eol_path: Path) -> dict[str, str]:
    """major.minor branch -> End-of-Technical-Support date (software branches)."""
    out: dict[str, str] = {}
    if not eol_path.exists():
        return out
    data = json.loads(eol_path.read_text())
    for src in data.get("sources", []):
        if src.get("category") != "software":
            continue
        for rec in src.get("records", []):
            br = _branch_of(rec.get("product", ""))
            eots = rec.get("end_of_technical_support")
            if br and eots:
                out.setdefault(br, eots)
    return out


def compute_priority(rec: dict) -> tuple[float, str]:
    """Heuristic 0-10 priority + label. Documented as a heuristic, not official.

    Base = highest CVSS score; KEV forces >=9 (Critical); +1 if remotely
    exploitable without auth; +0.5 if any affected branch is past EoTS.
    """
    score = max(rec.get("cvss_v31_score") or 0.0, rec.get("cvss_v40_score") or 0.0)
    if rec.get("kev"):
        score = max(score, 9.0)
    if rec.get("remote") and rec.get("unauthenticated"):
        score = min(10.0, score + 1.0)
    if rec.get("has_eol_affected"):
        score = min(10.0, score + 0.5)
    score = round(min(10.0, score), 1)
    label = ("Critical" if score >= 9 else "High" if score >= 7
             else "Medium" if score >= 4 else "Low")
    return score, label


def enrich_dataset(output_dir: Path, kev_map: dict, epss_map: dict) -> int:
    """Apply all derived/external enrichments to cves/*.json. Returns #changed."""
    out = Path(output_dir)
    eots = _build_eots_map(out / "eol.json")
    cve_dir = out / "cves"
    if not cve_dir.is_dir():
        return 0

    changed = 0
    for f in sorted(cve_dir.glob("*.json")):
        rec = json.loads(f.read_text())
        cid = (rec.get("id") or "").upper()

        # CVSS vector decomposition (prefer v3.1).
        flags = parse.parse_cvss_vector(rec.get("cvss_v31_vector") or rec.get("cvss_v40_vector"))
        for k in ("attack_vector", "remote", "unauthenticated", "user_interaction_required"):
            rec[k] = flags.get(k)

        # CISA KEV.
        kv = kev_map.get(cid)
        rec["kev"] = bool(kv)
        rec["kev_date_added"] = kv.get("date_added") if kv else None
        rec["kev_ransomware"] = kv.get("ransomware") if kv else None

        # EPSS.
        rec["epss_score"] = epss_map.get(cid)

        # EOL cross-link per affected branch.
        has_eol = False
        for a in rec.get("affected", []):
            br = None
            for vr in a.get("affected_versions", []):
                cand = _branch_of(vr)
                if cand and cand in eots:
                    br = cand
                    break
            if br:
                past = _is_past(eots[br])
                a["branch_is_eol"] = past
                a["branch_eots_date"] = eots[br]
                if past:
                    has_eol = True
            else:
                a.setdefault("branch_is_eol", None)
                a.setdefault("branch_eots_date", None)
        rec["has_eol_affected"] = has_eol

        # Priority (depends on the above).
        rec["priority_score"], rec["priority"] = compute_priority(rec)

        if _write_if_changed(f, rec):
            changed += 1
    log.info("enrich: updated %d CVE files", changed)
    return changed
