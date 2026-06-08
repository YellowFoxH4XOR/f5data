"""Data shapes for the scraped F5 dataset.

These dataclasses are the canonical schema written to JSON. Keep them flat and
JSON-friendly: every field is a str / number / list of primitives or nested
dataclasses, so `to_dict` round-trips cleanly.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class AffectedProduct:
    """One product row within a CVE/exposure listing.

    `affected_versions` and `fixes_introduced_in` are lists because a single
    product line in F5's tables often carries several version ranges, each on
    its own line in the source cell.
    """

    product: str
    affected_versions: list[str] = field(default_factory=list)
    fixes_introduced_in: list[str] = field(default_factory=list)
    # Normalized TMOS provisioning module code (ltm/asm/apm/...), the sentinel
    # "all" for "BIG-IP (all modules)", or None when the product is not a
    # provisioned module (NGINX, F5OS, BIG-IQ, ...) or could not be mapped.
    module_code: str | None = None
    # CVE-detail-only extras (absent when sourced from the quarterly table):
    branch: str | None = None
    # F5's verbatim "Vulnerable component or feature" — the condition that must
    # hold for the CVE to apply (e.g. a specific profile/feature configured).
    vulnerable_component: str | None = None


@dataclass
class CVE:
    """A single vulnerability or security exposure.

    Keyed by `id` (the CVE ID, e.g. CVE-2026-22548). For F5 security exposures
    that have no CVE assigned, `id` falls back to the article K-number and
    `is_exposure` is True.
    """

    id: str
    title: str
    article_k: str | None
    url: str | None
    severity: str | None = None          # Critical / High / Medium / Low
    cvss_v31_score: float | None = None
    cvss_v40_score: float | None = None
    cvss_v31_vector: str | None = None
    cvss_v40_vector: str | None = None
    is_exposure: bool = False
    affected: list[AffectedProduct] = field(default_factory=list)
    # Applicability summary (so the user can quickly decide per device):
    #   required_modules: modules that must be provisioned for this CVE to apply.
    #   applies_to_all_modules: True for "BIG-IP (all modules)" CVEs — applies to
    #     any BIG-IP at a vulnerable version regardless of provisioning.
    required_modules: list[str] = field(default_factory=list)
    applies_to_all_modules: bool = False
    description: str | None = None
    cwe: str | None = None
    source_reports: list[str] = field(default_factory=list)  # quarterly K-numbers
    updated_date: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Report:
    """A quarterly security notification report listed under K12201527."""

    k_number: str
    title: str
    url: str
    notification_date: str | None = None   # as printed, e.g. "February 4, 2026"
    date_iso: str | None = None            # normalized YYYY-MM-DD when parseable
    cve_ids: list[str] = field(default_factory=list)
    updated_date: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EolRecord:
    """A product/version lifecycle row from an EOL article (K5903/K4309/...)."""

    product: str                       # version branch or hardware platform
    category: str                      # "software" | "hardware"
    source_k: str
    section: str | None = None         # table section heading for context
    first_customer_ship: str | None = None
    end_of_software_development: str | None = None
    end_of_technical_support: str | None = None
    end_of_sale: str | None = None
    latest_maintenance_release: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
