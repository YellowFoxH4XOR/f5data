"""External threat-intel feeds, keyed by CVE ID.

Both fetchers are **fail-soft**: on any network/parse error they log a warning
and return an empty map, so a feed outage degrades enrichment gracefully rather
than breaking the scrape. Uses only the stdlib (urllib) — no new dependency.
"""

from __future__ import annotations

import json
import logging
import urllib.request
from typing import Iterable

log = logging.getLogger("f5scraper.intel")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"
_TIMEOUT = 30
_UA = "f5scraper (vulnerability dataset enrichment)"


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310 - fixed https hosts
        return resp.read()


def fetch_kev() -> dict[str, dict]:
    """CISA Known Exploited Vulnerabilities → {CVE-ID: {date_added, due_date, ransomware}}."""
    try:
        data = json.loads(_get(KEV_URL))
    except Exception as e:  # noqa: BLE001 - fail soft
        log.warning("KEV fetch failed: %s", e)
        return {}
    out: dict[str, dict] = {}
    for v in data.get("vulnerabilities", []):
        cid = (v.get("cveID") or "").upper()
        if not cid:
            continue
        rw = v.get("knownRansomwareCampaignUse")
        out[cid] = {
            "date_added": v.get("dateAdded"),
            "due_date": v.get("dueDate"),
            "ransomware": (rw.lower() == "known") if isinstance(rw, str) else None,
        }
    log.info("KEV: %d entries", len(out))
    return out


def fetch_epss(cve_ids: Iterable[str]) -> dict[str, float]:
    """EPSS exploitation-probability scores for the given CVE IDs → {CVE-ID: 0..1}.

    Queries the FIRST.org API in chunks so we only pull scores for CVEs we have.
    """
    ids = sorted({c.upper() for c in cve_ids if c and c.upper().startswith("CVE-")})
    out: dict[str, float] = {}
    chunk = 80
    for i in range(0, len(ids), chunk):
        url = f"{EPSS_API}?cve={','.join(ids[i:i + chunk])}"
        try:
            data = json.loads(_get(url))
        except Exception as e:  # noqa: BLE001 - fail soft per chunk
            log.warning("EPSS fetch failed for chunk %d: %s", i // chunk, e)
            continue
        for row in data.get("data", []):
            try:
                out[row["cve"].upper()] = float(row["epss"])
            except (KeyError, ValueError, TypeError):
                continue
    log.info("EPSS: %d scores", len(out))
    return out
