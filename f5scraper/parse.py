"""Pure-Python parsers over the structured data returned by `browser.render_article`.

Nothing here touches the network or a browser, so every function is unit-testable
against a saved JSON fixture. The input `data` dicts have the shape produced by
`_EXTRACT_JS`: {title, published, updated, bodyText, links, tables:[{section,
header, rows:[[cell,...]]}]} where each cell is {text, rowspan, colspan, links}.
"""

from __future__ import annotations

import re
from dataclasses import asdict
from datetime import datetime
from typing import Any

from .models import AffectedProduct, CVE, EolRecord, Report

_K_RE = re.compile(r"/article/(K\w+)")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_CWE_RE = re.compile(r"CWE-\d+")
_SEVERITY_RE = re.compile(r"\b(Critical|High|Medium|Low)\b", re.IGNORECASE)
_CVSS31_RE = re.compile(r"([0-9]+\.[0-9])\s*\(CVSS v3\.1\)")
_CVSS40_RE = re.compile(r"([0-9]+\.[0-9])\s*\(CVSS v4\.0\)")
_NOT_AFFECTED = {"", "none", "not applicable", "not vulnerable", "n/a"}

# F5 product name -> normalized TMOS provisioning module code. Ordered: the
# first rule whose pattern matches the (lowercased) product name wins, so more
# specific phrases are listed before short bare codes. Short codes use word
# boundaries to avoid matching inside unrelated words. "all" is a sentinel for
# "BIG-IP (all modules)" (applies regardless of provisioning).
_MODULE_RULES: list[tuple[str, list[str]]] = [
    ("all", [r"all modules", r"all other modules"]),
    ("asm", [r"advanced waf", r"\bawaf\b", r"\basm\b", r"application security"]),
    ("afm", [r"advanced firewall", r"\bafm\b"]),
    ("apm", [r"\bapm\b", r"access policy"]),
    ("pem", [r"policy enforcement", r"\bpem\b"]),
    ("sslo", [r"ssl orchestrator", r"\bsslo\b"]),
    ("gtm", [r"\bdns\b", r"\bgtm\b", r"global traffic"]),
    ("cgnat", [r"\bcgnat\b", r"carrier-grade nat"]),
    ("avr", [r"\bavr\b", r"\banalytics\b"]),
    ("fps", [r"fraud protection", r"websafe", r"\bfps\b"]),
    ("lc", [r"link controller"]),
    ("ltm", [r"\bltm\b", r"local traffic"]),
]


def normalize_module(product: str | None) -> str | None:
    """Map an F5 product/module name to a TMOS provisioning code (or None).

    Returns None when the product is not a provisioned BIG-IP module (NGINX,
    F5OS, BIG-IQ, F5 Distributed Cloud, ...) or can't be confidently mapped.
    """
    p = (product or "").lower()
    if not p:
        return None
    for code, patterns in _MODULE_RULES:
        if any(re.search(pat, p) for pat in patterns):
            return code
    return None


def module_summary(affected: list[Any]) -> tuple[list[str], bool]:
    """Derive (required_modules, applies_to_all_modules) from affected entries.

    Accepts AffectedProduct instances or their dicts.
    """
    codes: set[str] = set()
    applies_all = False
    for a in affected:
        code = a["module_code"] if isinstance(a, dict) else a.module_code
        if code == "all":
            applies_all = True
        elif code:
            codes.add(code)
    return sorted(codes), applies_all


def k_from_href(href: str | None) -> str | None:
    if not href:
        return None
    m = _K_RE.search(href)
    return m.group(1) if m else None


def cve_from_text(text: str) -> str | None:
    m = _CVE_RE.search(text or "")
    return m.group(0).upper() if m else None


def normalize_date(s: str | None) -> str | None:
    """'February 4, 2026' or 'Feb 4, 2026' -> '2026-02-04'."""
    if not s:
        return None
    for fmt in ("%B %d, %Y", "%b %d, %Y"):
        try:
            return datetime.strptime(s.strip(), fmt).date().isoformat()
        except ValueError:
            continue
    return None


def _split_lines(text: str) -> list[str]:
    return [ln.strip() for ln in (text or "").split("\n") if ln.strip()]


def expand_grid(rows: list[list[dict[str, Any]]]) -> list[list[dict[str, Any]]]:
    """Expand an HTML table (with rowspan/colspan) into a dense rectangular grid.

    Spanned cells are repeated (the same dict object) into every column/row they
    cover, so callers can index by absolute column and detect row-groups by cell
    identity. This is the standard table-normalization algorithm.
    """
    grid: list[list[dict[str, Any]]] = []
    carry: dict[int, list[Any]] = {}  # col -> [cell, remaining_future_rows]
    for cells in rows:
        result: list[dict[str, Any]] = []
        col = 0
        si = 0
        while True:
            if col in carry:
                cell, rem = carry[col]
                result.append(cell)
                if rem - 1 <= 0:
                    del carry[col]
                else:
                    carry[col][1] = rem - 1
                col += cell.get("colspan", 1)
                continue
            if si < len(cells):
                cell = cells[si]
                si += 1
                cspan = cell.get("colspan", 1)
                rspan = cell.get("rowspan", 1)
                for k in range(cspan):
                    result.append(cell)
                    if rspan > 1:
                        carry[col + k] = [cell, rspan - 1]
                col += cspan
                continue
            future = [c for c in carry if c > col]
            if future:
                col = min(future)
                continue
            break
        grid.append(result)
    return grid


def _header_index(header: list[str], *needles: str) -> int | None:
    """Index of the first header column whose text contains any needle (ci)."""
    for i, h in enumerate(header):
        low = h.lower()
        if any(n.lower() in low for n in needles):
            return i
    return None


# --------------------------------------------------------------------------- #
# Index article (K12201527)
# --------------------------------------------------------------------------- #

def parse_index(data: dict[str, Any]) -> list[Report]:
    """Reports listed under 'Scheduled Quarterly Security Notifications'.

    Identified by the table's header row ['Notification date', 'Reference
    article'] rather than the section heading text, which is more robust.
    """
    reports: list[Report] = []
    for table in data.get("tables", []):
        header = [h.lower() for h in table.get("header", [])]
        if not (len(header) >= 2 and "notification date" in header[0]
                and "reference" in header[1]):
            continue
        for row in table["rows"][1:]:  # skip header
            if len(row) < 2:
                continue
            date_cell, ref_cell = row[0], row[1]
            links = ref_cell.get("links") or []
            if not links:
                continue
            href = links[0]["href"]
            k = k_from_href(href)
            if not k:
                continue
            notif = date_cell.get("text", "").strip() or None
            reports.append(Report(
                k_number=k,
                title=links[0]["text"].strip(),
                url=_abs(href),
                notification_date=notif,
                date_iso=normalize_date(notif),
            ))
        break  # only the first (Scheduled) table
    return reports


def _abs(href: str) -> str:
    if href.startswith("http"):
        return href
    return "https://my.f5.com" + href


# --------------------------------------------------------------------------- #
# Quarterly report article (lists CVEs + exposures)
# --------------------------------------------------------------------------- #

def parse_report(data: dict[str, Any]) -> list[CVE]:
    """CVEs and security exposures listed in a quarterly report's tables.

    A CVE table has header 'Article (CVE)'; an exposure table 'Article
    (Exposure)'. Severity comes from the table's section heading ('Medium CVEs',
    etc.). Multi-product CVEs use rowspan, handled via `expand_grid`.
    """
    out: list[CVE] = []
    report_k = data.get("k_number")
    for table in data.get("tables", []):
        header = table.get("header", [])
        is_cve = _header_index(header, "Article (CVE)") is not None
        is_exp = _header_index(header, "Article (Exposure)") is not None
        if not (is_cve or is_exp):
            continue
        severity = None
        if is_cve:
            m = _SEVERITY_RE.search(table.get("section") or "")
            severity = m.group(1).capitalize() if m else None

        grid = expand_grid(table["rows"])
        if not grid:
            continue
        ghead = [c.get("text", "") for c in grid[0]]
        col_prod = _header_index(ghead, "Affected product")
        col_vers = _header_index(ghead, "Affected version")
        col_fix = _header_index(ghead, "Fixes introduced")
        col_cvss = _header_index(ghead, "CVSS score")

        groups: list[tuple[dict[str, Any], list[list[dict[str, Any]]]]] = []
        for row in grid[1:]:
            article_cell = row[0]
            if groups and groups[-1][0] is article_cell:
                groups[-1][1].append(row)
            else:
                groups.append((article_cell, [row]))

        for article_cell, rows in groups:
            links = article_cell.get("links") or []
            if not links:
                continue
            href = links[0]["href"]
            art_k = k_from_href(href)
            title = links[0]["text"].strip()
            cve_id = cve_from_text(title) or art_k or href
            cvss31 = cvss40 = None
            if col_cvss is not None and rows:
                ctext = rows[0][col_cvss].get("text", "")
                cvss31 = _f(_first(_CVSS31_RE, ctext))
                cvss40 = _f(_first(_CVSS40_RE, ctext))
            affected: list[AffectedProduct] = []
            for r in rows:
                prod = r[col_prod].get("text", "").strip() if col_prod is not None else ""
                vers = _split_lines(r[col_vers].get("text", "")) if col_vers is not None else []
                fix = _split_lines(r[col_fix].get("text", "")) if col_fix is not None else []
                if prod:
                    affected.append(AffectedProduct(
                        product=prod, affected_versions=vers, fixes_introduced_in=fix,
                        module_code=normalize_module(prod)))
            req_modules, applies_all = module_summary(affected)
            out.append(CVE(
                id=cve_id,
                title=title,
                article_k=art_k,
                url=_abs(href),
                severity=severity,
                cvss_v31_score=cvss31,
                cvss_v40_score=cvss40,
                is_exposure=is_exp,
                affected=affected,
                required_modules=req_modules,
                applies_to_all_modules=applies_all,
                source_reports=[report_k] if report_k else [],
            ))
    return out


def _first(rx: re.Pattern[str], text: str) -> str | None:
    m = rx.search(text or "")
    return m.group(1) if m else None


def _f(s: str | None) -> float | None:
    try:
        return float(s) if s is not None else None
    except ValueError:
        return None


# --------------------------------------------------------------------------- #
# CVE detail article (enrichment: description, CWE, CVSS vectors, severity)
# --------------------------------------------------------------------------- #

def parse_cve_status(data: dict[str, Any]) -> list[AffectedProduct]:
    """Affected products from a CVE article's Security Advisory Status tables.

    These tables carry the columns the quarterly report lacks — Branch and
    'Vulnerable component or feature' (the activation condition) — and list every
    evaluated product. We keep only rows that are actually vulnerable (the
    'Versions known to be vulnerable' cell is a real range, not None/Not
    vulnerable/Not applicable).
    """
    affected: list[AffectedProduct] = []
    for table in data.get("tables", []):
        header = table.get("header", [])
        if _header_index(header, "Vulnerable component or feature") is None:
            continue
        grid = expand_grid(table["rows"])
        if not grid:
            continue
        ghead = [c.get("text", "") for c in grid[0]]
        col_prod = _header_index(ghead, "Product", "Service")
        col_branch = _header_index(ghead, "Branch")
        col_vuln = _header_index(ghead, "Versions known to be vulnerable")
        col_fix = _header_index(ghead, "Fixes introduced in")
        col_comp = _header_index(ghead, "Vulnerable component or feature")

        for row in grid[1:]:
            def cell(idx: int | None) -> str:
                return row[idx].get("text", "").strip() if (idx is not None and idx < len(row)) else ""

            vuln_text = cell(col_vuln)
            # Tables without a versions column (e.g. F5 Distributed Cloud) only
            # ever list "Not vulnerable", so this filter also drops them.
            if vuln_text.lower() in _NOT_AFFECTED:
                continue
            product = cell(col_prod)
            if not product:
                continue
            comp = cell(col_comp)
            affected.append(AffectedProduct(
                product=product,
                branch=cell(col_branch) or None,
                affected_versions=_split_lines(vuln_text),
                fixes_introduced_in=[v for v in _split_lines(cell(col_fix))
                                     if v.lower() not in _NOT_AFFECTED],
                vulnerable_component=None if comp.lower() in _NOT_AFFECTED else comp,
                module_code=normalize_module(product),
            ))
    return affected


def parse_cve_detail(data: dict[str, Any]) -> dict[str, Any]:
    """Extra fields for a CVE from its own article.

    Returns a dict of enrichment fields (description, cwe, cvss vectors/scores,
    severity, and the richer affected list with module/component) to merge onto
    the CVE built from the quarterly report.
    """
    body = data.get("bodyText", "")
    out: dict[str, Any] = {"updated_date": normalize_date(data.get("updated"))}

    affected = parse_cve_status(data)
    if affected:
        out["affected"] = [asdict(a) for a in affected]
        req_modules, applies_all = module_summary(affected)
        out["required_modules"] = req_modules
        out["applies_to_all_modules"] = applies_all

    desc = _between(body, "Security Advisory Description", ("Impact", "Security Advisory Status"))
    if desc:
        out["description"] = desc

    cwe = _CWE_RE.search(body)
    if cwe:
        out["cwe"] = cwe.group(0)

    # CVSS vectors + authoritative severity/score live in the Severity/CVSS cells
    # of the status tables, as first.org calculator links.
    for table in data.get("tables", []):
        for row in table.get("rows", []):
            for cell in row:
                for link in cell.get("links") or []:
                    href = link.get("href", "")
                    txt = link.get("text", "")
                    if "cvss/calculator/3.1" in href and "cvss_v31_vector" not in out:
                        out["cvss_v31_vector"] = _vector(href)
                        _apply_sev_score(out, txt, "31")
                    elif "cvss/calculator/4.0" in href and "cvss_v40_vector" not in out:
                        out["cvss_v40_vector"] = _vector(href)
                        _apply_sev_score(out, txt, "40")
    return out


def _apply_sev_score(out: dict[str, Any], text: str, ver: str) -> None:
    # text like "Medium/5.9" or "High/8.2"
    m = re.match(r"\s*(Critical|High|Medium|Low)\s*/\s*([0-9]+\.[0-9])", text, re.IGNORECASE)
    if not m:
        return
    out.setdefault("severity", m.group(1).capitalize())
    out[f"cvss_v{ver}_score"] = float(m.group(2))


def _vector(href: str) -> str | None:
    if "#" in href:
        return href.split("#", 1)[1]
    return None


def _between(body: str, start: str, ends: tuple[str, ...]) -> str | None:
    i = body.find(start)
    if i < 0:
        return None
    i += len(start)
    end_idx = len(body)
    for e in ends:
        j = body.find(e, i)
        if 0 <= j < end_idx:
            end_idx = j
    chunk = body[i:end_idx].strip()
    return chunk or None


# --------------------------------------------------------------------------- #
# EOL / lifecycle articles (K5903, K4309, ...)
# --------------------------------------------------------------------------- #

def parse_eol(data: dict[str, Any], category: str) -> list[EolRecord]:
    """Lifecycle rows from an EOL article.

    Columns vary by table (supported tables include 'First customer ship' /
    'Latest maintenance release'; EoL tables only have EoSD/EoTS), so columns
    are located by header text, not fixed positions.
    """
    source_k = data.get("k_number", "")
    out: list[EolRecord] = []
    for table in data.get("tables", []):
        header = table.get("header", [])
        col_eosd = _header_index(header, "End of Software Development")
        col_eots = _header_index(header, "End of Technical Support")
        col_eos = _header_index(header, "End of Sale")
        if col_eosd is None and col_eots is None and col_eos is None:
            continue  # not a lifecycle table
        col_fcs = _header_index(header, "First customer ship")
        col_latest = _header_index(header, "Latest maintenance")
        section = table.get("section")

        grid = expand_grid(table["rows"])
        for row in grid[1:]:  # skip header
            def cell(idx: int | None) -> str | None:
                if idx is None or idx >= len(row):
                    return None
                # version/branch cells can carry multiple branches; keep as-is
                t = row[idx].get("text", "").strip()
                return t or None

            product = cell(0)
            if not product:
                continue
            out.append(EolRecord(
                product=product,
                category=category,
                source_k=source_k,
                section=section,
                first_customer_ship=cell(col_fcs),
                end_of_software_development=cell(col_eosd),
                end_of_technical_support=cell(col_eots),
                end_of_sale=cell(col_eos),
                latest_maintenance_release=cell(col_latest),
            ))
    return out
