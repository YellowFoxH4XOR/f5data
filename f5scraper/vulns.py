"""Vulnerability crawl: K12201527 -> quarterly reports -> CVE details.

Flow:
  1. Render the index (K12201527), parse the Scheduled QSN report list.
  2. For each report (newest = mutable/"open", older = immutable), scrape its
     CVE/exposure tables when the cache says so. Upsert each CVE to a canonical
     file keyed by CVE ID; write the report file.
  3. Enrich each CVE from its own article (description, CWE, CVSS vectors,
     authoritative severity) when the cache says so.
  4. Rebuild data/output/vulnerabilities.json from all canonical files — this is
     what guarantees a duplicate-free, deterministic combined index regardless
     of run history.
"""

from __future__ import annotations

import logging
from pathlib import Path

from .browser import ArticleSession
from .cache import Cache, content_hash
from .models import CVE
from . import parse, intel, enrich

log = logging.getLogger("f5scraper.vulns")

INDEX_K = "K12201527"


def _cve_filename(cve_id: str) -> str:
    safe = cve_id.replace("/", "_")
    return f"cves/{safe}.json"


def _merge_cve(existing: dict | None, new: CVE) -> dict:
    """Merge a freshly-parsed report CVE onto any existing canonical record.

    Report-sourced fields (affected, scores, severity, title) win when present;
    enrichment-only fields already on disk (description, cwe, vectors) are kept.
    """
    d = new.to_dict()
    if not existing:
        return d
    keep_if_missing = (
        "description", "cwe", "cvss_v31_vector", "cvss_v40_vector", "updated_date",
    )
    for f in keep_if_missing:
        if not d.get(f) and existing.get(f):
            d[f] = existing[f]
    for f in ("severity", "cvss_v31_score", "cvss_v40_score"):
        if d.get(f) is None and existing.get(f) is not None:
            d[f] = existing[f]
    d["source_reports"] = sorted(set(existing.get("source_reports", [])) | set(d.get("source_reports", [])))
    return d


async def run(session: ArticleSession, output_dir: Path, *, refresh: bool = False,
              limit: int | None = None, ttl_days: int = 0) -> dict:
    cache = Cache(output_dir, refresh=refresh, ttl_days=ttl_days)

    # 1. Index ------------------------------------------------------------- #
    log.info("Rendering index %s", INDEX_K)
    index_data = await session.render_article(INDEX_K)
    reports = parse.parse_index(index_data)
    cache.record(INDEX_K, content_hash([r.to_dict() for r in reports]), "index")
    log.info("Found %d quarterly reports", len(reports))

    if limit:
        reports = reports[:limit]

    cve_article_ks: dict[str, str] = {}  # article_k -> cve_id (to enrich later)

    # 2. Reports ----------------------------------------------------------- #
    for i, report in enumerate(reports):
        mutability = "mutable" if i == 0 else "immutable"  # newest quarter is still open
        if not cache.should_scrape(report.k_number, mutability):
            log.info("skip report %s (cached, %s)", report.k_number, mutability)
            # still collect its CVE article_ks for enrichment decisions
            existing = cache.read_json(f"reports/{report.k_number}.json") or {}
            for cid in existing.get("cve_ids", []):
                rec = cache.read_json(_cve_filename(cid))
                if rec and rec.get("article_k"):
                    cve_article_ks[rec["article_k"]] = cid
            continue

        log.info("scrape report %s [%d/%d]", report.k_number, i + 1, len(reports))
        data = await session.render_article(report.k_number)
        cves = parse.parse_report(data)
        report.cve_ids = sorted({c.id for c in cves})
        report.updated_date = parse.normalize_date(data.get("updated"))

        for c in cves:
            fn = _cve_filename(c.id)
            merged = _merge_cve(cache.read_json(fn), c)
            cache.write_json(fn, merged)
            if c.article_k:
                cve_article_ks[c.article_k] = c.id

        cache.write_json(f"reports/{report.k_number}.json", report.to_dict())
        cache.record(report.k_number, content_hash(report.to_dict()), mutability)

    # 3. Enrichment from per-CVE articles ---------------------------------- #
    items = list(cve_article_ks.items())
    log.info("Enriching %d CVE detail articles", len(items))
    for n, (art_k, cve_id) in enumerate(items, 1):
        if n % 25 == 0:
            log.info("  ...enriched %d/%d CVE articles", n, len(items))
        if not cache.should_scrape(art_k, "mutable"):
            continue
        fn = _cve_filename(cve_id)
        rec = cache.read_json(fn)
        if rec is None:
            continue
        try:
            detail = await session.render_article(art_k)
        except RuntimeError as e:
            log.warning("enrichment failed for %s (%s): %s", cve_id, art_k, e)
            continue
        detail_fields = parse.parse_cve_detail(detail)
        for key, val in detail_fields.items():
            if val is not None:
                rec[key] = val  # detail is authoritative for these fields
        cache.write_json(fn, rec)
        cache.record(art_k, content_hash(detail_fields), "mutable")

    # 3b. Out-of-band advisories (Additional Security Announcements) -------- #
    # Skipped under --limit (a testing knob). Most entries are single-CVE
    # advisories; a few are multi-CVE "Out-of-band Security Notification" reports.
    if not limit:
        for ann in parse.parse_index_additional(index_data):
            k = ann["k"]
            if not cache.should_scrape(k, "mutable"):
                continue
            try:
                data = await session.render_article(k)
            except RuntimeError as e:
                log.warning("out-of-band %s failed: %s", k, e)
                continue
            report_cves = parse.parse_report(data)
            if report_cves:  # multi-CVE out-of-band notification (report-style)
                for c in report_cves:
                    c.is_out_of_band = True
                    c.source_reports = [k]
                    fn = _cve_filename(c.id)
                    cache.write_json(fn, _merge_cve(cache.read_json(fn), c))
                    if c.article_k and c.article_k != k:
                        try:
                            det = await session.render_article(c.article_k)
                            rec = cache.read_json(fn)
                            for key, val in parse.parse_cve_detail(det).items():
                                if val is not None:
                                    rec[key] = val
                            cache.write_json(fn, rec)
                        except RuntimeError as e:
                            log.warning("oob enrich failed %s: %s", c.article_k, e)
            else:  # single-CVE advisory article
                cve = parse.build_cve_from_article(data)
                if cve:
                    fn = _cve_filename(cve.id)
                    cache.write_json(fn, _merge_cve(cache.read_json(fn), cve))
            cache.record(k, content_hash(ann), "mutable")
            log.info("out-of-band %s ingested", k)

    # 4. Threat-intel + derived enrichment (KEV/EPSS/CVSS flags/EOL/priority) #
    kev_map = intel.fetch_kev()
    epss_map = intel.fetch_epss([c.get("id", "") for c in cache.glob_json("cves")])
    enrich.enrich_dataset(output_dir, kev_map, epss_map)

    # 5. Rebuild combined index (after enrichment; dedup-free by construction) #
    all_cves = cache.glob_json("cves")
    all_reports = cache.glob_json("reports")
    combined = {
        "generated_from": "my.f5.com K12201527 Quarterly Security Notifications + out-of-band advisories",
        "report_count": len(all_reports),
        "cve_count": len(all_cves),
        "kev_count": sum(1 for c in all_cves if c.get("kev")),
        "reports": sorted(all_reports, key=lambda r: r.get("date_iso") or "", reverse=True),
        "cves": sorted(all_cves, key=lambda c: c.get("id", "")),
    }
    cache.write_json("vulnerabilities.json", combined)
    cache.save_manifest()
    log.info("vulns: %d reports, %d CVEs (%d KEV)", len(all_reports), len(all_cves), combined["kev_count"])
    return {"reports": len(all_reports), "cves": len(all_cves)}
