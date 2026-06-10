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
# CAN- is the pre-2005 provisional prefix for the same id space (e.g. K5004's
# "CAN-2005-2096"); cve_from_text normalizes it to CVE-.
_CVE_RE = re.compile(r"(?:CVE|CAN)-\d{4}-\d{4,7}", re.IGNORECASE)
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
    return m.group(0).upper().replace("CAN-", "CVE-") if m else None


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
        # Modern layout has 'Vulnerable component or feature'; legacy layouts
        # (pre-QSN advisories) instead pair a Product column with a
        # vulnerable-versions column ('Versions affected by this issue' on
        # exposure articles, bare 'Affected' on the oldest ones).
        is_modern = _header_index(header, "Vulnerable component or feature") is not None
        is_legacy = (_header_index(header, "Product", "Service") is not None
                     and _header_index(header, "Versions known to be vulnerable",
                                       "Versions affected by this issue", "Affected") is not None)
        if not (is_modern or is_legacy):
            continue
        grid = expand_grid(table["rows"])
        if not grid:
            continue
        ghead = [c.get("text", "") for c in grid[0]]
        col_prod = _header_index(ghead, "Product", "Service")
        col_branch = _header_index(ghead, "Branch")
        col_vuln = _header_index(ghead, "Versions known to be vulnerable",
                                 "Versions affected by this issue", "Affected")
        col_fix = _header_index(ghead, "Fixes introduced in",
                                "Versions known to be not vulnerable", "Not Affected")
        col_comp = _header_index(ghead, "Vulnerable component or feature")
        if col_vuln is not None and col_vuln == col_prod:
            continue  # ambiguous header match (e.g. 'Affected product') — not a status table

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

    # F5 operational fields (section order in the body is Description → Impact →
    # Security Advisory Status → Recommended Actions → Mitigation → Acknowledgements).
    out["published_date"] = normalize_date(data.get("published"))
    impact = _between(body, "Impact", ("Security Advisory Status",))
    if impact:
        out["impact"] = impact
    rec = _between(body, "Security Advisory Recommended Actions",
                   ("Mitigation", "Acknowledgements", "Supplemental Information", "Related Content"))
    if rec:
        out["recommended_actions"] = rec
    mit = _between(body, "Mitigation",
                   ("Acknowledgements", "Supplemental Information", "Related Content"))
    if mit:
        out["mitigation"] = mit
    bug = re.search(r"assigned ID (\d+)", body)
    if bug:
        out["f5_bug_id"] = bug.group(1)
    status = re.search(r"marked as '([^']+)'", body)
    if status:
        out["status"] = status.group(1)
    return out


# CVSS vector key -> attack-vector word
_AV_WORD = {"N": "network", "A": "adjacent", "L": "local", "P": "physical"}


def parse_cvss_vector(vector: str | None) -> dict[str, Any]:
    """Decompose a CVSS vector string into filterable flags.

    Handles both v3.1 (`AV/AC/PR/UI/...`) and v4.0 (`AV/AC/AT/PR/UI/...`).
    Returns keys: attack_vector, remote, unauthenticated, user_interaction_required.
    """
    if not vector:
        return {}
    parts = dict(p.split(":", 1) for p in vector.split("/") if ":" in p)
    out: dict[str, Any] = {}
    av = parts.get("AV")
    if av:
        out["attack_vector"] = _AV_WORD.get(av, av)
        out["remote"] = av in ("N", "A")
    if "PR" in parts:
        out["unauthenticated"] = parts["PR"] == "N"
    if "UI" in parts:
        # v3.1: N/R; v4.0: N/P/A. Anything other than None means UI is involved.
        out["user_interaction_required"] = parts["UI"] != "N"
    return out


def parse_index_additional(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Out-of-band advisories from the 'Additional Security Announcements' table."""
    out: list[dict[str, Any]] = []
    for table in data.get("tables", []):
        header = [h.lower() for h in table.get("header", [])]
        if not (len(header) >= 2 and "announcement date" in header[0]
                and "reference" in header[1]):
            continue
        for row in table["rows"][1:]:
            if len(row) < 2:
                continue
            links = row[1].get("links") or []
            if not links:
                continue
            k = k_from_href(links[0]["href"])
            if not k:
                continue
            out.append({
                "k": k,
                "title": links[0]["text"].strip(),
                "url": _abs(links[0]["href"]),
                "date": row[0].get("text", "").strip() or None,
            })
        break
    return out


def _advisory_description(data: dict[str, Any]) -> str | None:
    """The advisory's description text, never the page sidebar.

    Falls back to the body truncated before the related/recommended widgets
    for legacy articles that lack the 'Security Advisory Description' heading.
    Those widgets list other advisories, so CVE ids found past them would be
    noise from unrelated articles.
    """
    body = data.get("bodyText", "")
    desc = _between(body, "Security Advisory Description", ("Impact", "Security Advisory Status"))
    if desc:
        return desc
    cut = len(body)
    for marker in ("Related Content", "AI Recommended Content"):
        j = body.find(marker)
        if 0 <= j < cut:
            cut = j
    return body[:cut].strip() or None


def build_cves_from_article(data: dict[str, Any]) -> list[CVE]:
    """Build CVE records directly from an advisory article (out-of-band).

    Most advisories name one CVE in the title. Legacy 'Multiple <component>
    vulnerabilities' articles instead enumerate CVE ids in the description —
    those become one record per id, sharing the article's affected table. An
    article with no CVE ids anywhere but a real affected table is a security
    exposure, keyed by its K number. Returns [] when there is genuinely
    nothing to ingest (e.g. a not-affected advisory with no CVE ids).
    """
    title = data.get("title", "")
    k = data.get("k_number")
    affected = parse_cve_status(data)
    desc = _advisory_description(data)

    title_cid = cve_from_text(title)
    if title_cid:
        cids = [title_cid]
    else:
        cids = sorted({m.group(0).upper().replace("CAN-", "CVE-")
                       for m in _CVE_RE.finditer(desc or "")})
    if not cids and not affected:
        return []

    detail = parse_cve_detail(data)
    req_modules, applies_all = module_summary(affected)
    out: list[CVE] = []
    for cid in cids or [None]:
        cve = CVE(
            id=cid or (k or title),
            title=title,
            article_k=k,
            url=data.get("url"),
            is_exposure=cid is None,
            affected=affected,
            required_modules=req_modules,
            applies_to_all_modules=applies_all,
            is_out_of_band=True,
        )
        # Apply detail-derived fields (description, cwe, cvss, ops fields,
        # severity); the article-wide values hold for every CVE it lists.
        for key, val in detail.items():
            if key == "affected" or val is None:
                continue
            if hasattr(cve, key):
                setattr(cve, key, val)
        if len(cids) > 1 and desc:
            chunk = _between(desc, cid, tuple(c for c in cids if c != cid))
            if chunk:
                cve.description = f"{cid} {chunk}"
        out.append(cve)
    return out


def parse_compat(data: dict[str, Any]) -> list["CompatRecord"]:
    """Hardware/software compatibility records from K9476.

    K9476 uses a two-row header: a 'Compatible software versions' super-header
    (colspan) over per-branch sub-columns (21.x / 17.x / ...). We expand spans,
    combine the two header rows into real column labels, then emit one record per
    hardware row.
    """
    from .models import CompatRecord  # local import to avoid top-level churn

    source_k = data.get("k_number", "")
    out: list[CompatRecord] = []
    for table in data.get("tables", []):
        grid = expand_grid(table["rows"])
        if len(grid) < 3:
            continue
        h0 = [c.get("text", "").strip() for c in grid[0]]
        h1 = [c.get("text", "").strip() for c in grid[1]]
        n = len(h0)

        sw_cols: dict[int, str] = {}   # col index -> branch label
        meta: dict[str, int] = {}      # 'lifecycle'/'aom'/'eud' -> col index
        type_cols: list[int] = []
        hw_cols: list[int] = []
        for i in range(n):
            top = h0[i].lower()
            sub = h1[i] if i < len(h1) else ""
            if "compatible software" in top:
                sw_cols[i] = sub or h0[i]
            elif "lifecycle" in top:
                meta["lifecycle"] = i
            elif top == "aom":
                meta["aom"] = i
            elif top == "eud":
                meta["eud"] = i
            elif "type" in top or "type" in sub.lower():
                type_cols.append(i)
            else:
                hw_cols.append(i)

        if not sw_cols:
            continue  # not a compatibility table

        for row in grid[2:]:
            def cell(idx: int) -> str:
                return row[idx].get("text", "").strip() if idx < len(row) else ""

            hardware = " / ".join(t for i in hw_cols if (t := cell(i)))
            if not hardware:
                continue
            hw_type = " / ".join(t for i in type_cols if (t := cell(i))) or None
            compatible = {
                label: cell(i)
                for i, label in sw_cols.items()
                if cell(i) and cell(i).lower() not in _NOT_AFFECTED
            }
            out.append(CompatRecord(
                hardware=hardware,
                source_k=source_k,
                hw_type=hw_type,
                compatible_software=compatible,
                lifecycle_note=(cell(meta["lifecycle"]) or None) if "lifecycle" in meta else None,
                aom=(cell(meta["aom"]) or None) if "aom" in meta else None,
                eud=(cell(meta["eud"]) or None) if "eud" in meta else None,
            ))
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
        grid = expand_grid(table["rows"])
        if not grid:
            continue
        header = table.get("header", [])
        section = table.get("section")
        body_start = 1
        # Some articles (e.g. K21501912 / F5OS) put a one-cell title row above
        # the real header; use the title as section and read headers a row down.
        if len(grid) > 1 and len({id(c) for c in grid[0]}) == 1:
            section = section or (header[0] if header else None)
            header = [c.get("text", "") for c in grid[1]]
            body_start = 2
        # "EoSD/EoTS" is the combined-milestone column in F5OS tables; the
        # slash keeps prose headers like "EoSD and EoTS milestone" excluded.
        col_eosd = _header_index(header, "End of Software Development", "EoSD/EoTS")
        col_eots = _header_index(header, "End of Technical Support", "EoSD/EoTS")
        col_eos = _header_index(header, "End of Sale")
        if col_eosd is None and col_eots is None and col_eos is None:
            continue  # not a lifecycle table
        col_fcs = _header_index(header, "First customer ship")
        col_latest = _header_index(header, "Latest maintenance", "Latest patch")

        for row in grid[body_start:]:  # skip header
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
