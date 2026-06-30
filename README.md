# f5scraper — F5 vulnerability + EOL data scraper

Builds a structured JSON dataset from F5's support site (`my.f5.com`):

1. **Vulnerabilities** — every CVE / security exposure from two complementary
   discovery channels:
   - **Index-driven:** [K12201527](https://my.f5.com/manage/s/article/K12201527) →
     each **Quarterly Security Notification** report → each CVE's own article
     (severity, CVSS v3.1/v4.0 score + vector, affected products/versions,
     fixes, CWE, description). Also includes the "Additional Security
     Announcements" (out-of-band advisories) linked from that index.
   - **Search-driven:** the Coveo search API (same backend as the my.f5.com
     search bar) is queried for all ~5000+ Security Advisory articles. Any
     K-number not already ingested via the index channel is rendered and ingested
     — this catches standalone advisory articles never linked from K12201527.
     The full listing is persisted to `data/output/discovered.json` for
     diffability. Skip with `--no-discover`.
2. **End of Life / End of Support** — software (`K5903`) and hardware (`K4309`)
   lifecycle dates, plus best-effort follow of the EOL index (`K11478`).

## Why a headless browser

`my.f5.com` is a Salesforce Lightning SPA. Article bodies — including every
`table.askf5table` we parse — render **inside shadow DOM**, so a plain HTTP
fetch returns only a loading shell and `page.content()` misses the content.
The scraper renders each article with **Playwright (headless Chromium)** and runs
a shadow-piercing extraction routine that returns fully structured table data;
parsing then happens in pure Python.

## Output layout

The repo doubles as the datastore **and** the incremental cache:

```
data/output/
  manifest.json          # internal state: per-article {scraped_at, content_hash, mutability}
  vulnerabilities.json   # combined, deduped index (rebuilt every run)
  reports/{Knumber}.json # one per quarterly report
  cves/{CVE-ID}.json     # one per CVE / exposure (canonical, keyed by ID)
  eol.json               # combined lifecycle records
  eol/{Knumber}.json     # one per EOL source article
```

**No duplication, stays current:** each entity is written to a canonical file
keyed by its natural ID, and the combined indexes are *rebuilt from those files*
each run — so re-running can only overwrite-in-place, never append a duplicate.
Files are written only when their content changes, so unchanged articles produce
zero diff. Mutable data (CVE details, EOL dates) is refreshed on a TTL; closed
past quarters are immutable and scraped once.

## Enrichment fields

Each CVE record is enriched (same JSON shape, just more fields):

- **Threat intel:** `kev` (CISA Known Exploited), `kev_date_added`, `kev_ransomware`,
  `epss_score` (0–1 exploitation probability). Keyed by CVE ID; feeds are
  fetched fail-soft, so an outage degrades gracefully.
- **CVSS decomposition:** `attack_vector`, `remote`, `unauthenticated`,
  `user_interaction_required` (computed from the stored vectors).
- **F5 operational:** `impact`, `mitigation`, `recommended_actions`, `f5_bug_id`,
  `status`, `published_date`.
- **EOL cross-link:** per affected branch, `branch_is_eol` / `branch_eots_date`
  (best-effort, matched on major.minor against the EOL dataset); CVE-level
  `has_eol_affected`.
- **Priority:** `priority` (Critical/High/Medium/Low) + `priority_score` (0–10).
  **Heuristic, not an official score:** base = max CVSS; KEV forces ≥9; +1 if
  remotely exploitable without auth; +0.5 if any affected branch is past EoTS.

Coverage also includes **out-of-band advisories** (the "Additional Security
Announcements" on K12201527), marked `is_out_of_band: true` — not just the
scheduled quarterly reports.

`compat.json` (from **K9476**) maps each hardware platform to the software
versions it supports — useful to check whether a device's hardware can run a
fixed/target version.

## Is a CVE applicable to my device?

Each CVE record carries the **module/feature that must be active** for it to
apply, so you can match it against your fleet (product + version + provisioned
modules):

- `required_modules` — normalized TMOS provisioning codes (`ltm`, `asm`, `apm`,
  `afm`, `gtm`, `pem`, `avr`, `cgnat`, `sslo`, `fps`, `lc`) that must be
  provisioned for the CVE to apply. Match against `tmsh list sys provision`.
  Example: `["asm"]` → only boxes with ASM/Advanced WAF provisioned.
- `applies_to_all_modules` — `true` for "BIG-IP (all modules)" CVEs: applies to
  **any** BIG-IP running a vulnerable version, regardless of provisioning (e.g.
  Configuration utility / TMUI issues). `required_modules` is then empty.
- `affected[]` — per product+branch detail: `product` (F5's module name),
  `module_code` (normalized, or `null` for non-TMOS products like NGINX/F5OS/
  BIG-IQ), `branch`, `affected_versions`, `fixes_introduced_in`, and
  `vulnerable_component` — F5's verbatim condition (e.g. "Virtual server
  configured with a BIG-IP Advanced WAF or ASM security policy") for the final
  human check beyond just "is the module on".

So a CVE applies to one of your devices when: the device's **product/version**
falls in an `affected_versions` range (and below `fixes_introduced_in`), **and**
either `applies_to_all_modules` is true or one of `required_modules` is
provisioned **and** the `vulnerable_component` condition holds.

> `module_code` is best-effort normalization of F5's product text; when it's
> `null` on a BIG-IP product, fall back to matching on `product`/`vulnerable_component`.

## Usage

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
python -m playwright install chromium

python -m f5scraper.cli all                 # vulns + EOL
python -m f5scraper.cli vulns --limit 2 -v  # newest 2 reports only (testing)
python -m f5scraper.cli eol                  # EOL only
```

Flags: `--refresh` (ignore cache), `--limit N` (cap reports), `--ttl-days N`
(re-scrape mutable articles older than N days; `0` = always), `--output DIR`
(default `data/output`), `--throttle SECONDS`, `--no-discover` (skip
Coveo search-discovery step), `--headful`, `-v`.

## Automated runs (GitHub Actions)

`.github/workflows/scrape.yml` runs weekly (and on manual dispatch), scrapes,
and commits the refreshed `data/output/` back to the repo using the built-in
`GITHUB_TOKEN`. The repo is a full Linux runner, so Chromium and the 6-hour job
limit comfortably handle even a first full historical scrape.

## Notes & limitations

- F5 publishes no machine-readable (CSAF/JSON) feed, so rendered-page scraping
  is the only path; selectors may need updates if F5 redeploys the SPA.
- The EOL index (`K11478`) links to per-product articles that often describe EoL
  in prose rather than standard EoSD/EoTS tables, so the deep-follow is
  best-effort and contributes few extra records.
- Be polite: a throttle is applied between article loads by default.

## License & data sources

The **source code** in this repository is licensed under the **MIT License**
(see [`LICENSE`](LICENSE)). The MIT license covers the code only — it does **not**
cover the dataset under `data/output/`.

The **dataset** is derived from third-party sources, each governed by its own
terms — see [`NOTICE`](NOTICE) for full attributions and the disclaimer. In
short:

- **F5 advisory / EOL / compatibility content** (`my.f5.com`) is © F5, Inc. and
  subject to F5's Terms of Use. This project is **not affiliated with or endorsed
  by F5**, and adding a license here grants no rights in F5's content. Some
  fields contain verbatim F5 text (`description`, `impact`, `mitigation`,
  `recommended_actions`); reusing the dataset is your responsibility under F5's
  terms and applicable copyright law.
- **CISA KEV** — U.S. Government work, public domain.
- **EPSS** and **CVSS** — FIRST.org, used with attribution.
- **CVE** identifiers — CVE Program; "CVE" is a trademark of MITRE.

Provided **as is**, for informational/security-research use, with no warranty.
Always verify against the authoritative source before acting on this data.
