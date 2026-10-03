# f5scraper — F5 security, lifecycle, knowledge, and technical documentation

Builds a structured dataset from MyF5, F5 TechDocs, and CloudDocs:

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

3. **Full knowledge base** (`articles` command) — every my.f5.com K-article
   (~37k: Support Solutions, Known Issues, Knowledge, Security Advisories,
   Policies, Operations Guides, Videos) saved as a standalone HTML file, plus an
   index mapping each filename to a short description. No page rendering: the
   Coveo search API returns each article's full HTML body, so the whole KB is
   fetched in ~40 API calls (~5 minutes).
4. **New and updated articles** (`updates` command) — fetch only K-articles
   published or updated within a configurable window (30 days by default),
   using the same public Coveo backend as MyF5 search. Both `articles` and
   `updates` also produce structured metadata, a recent activity feed, and
   permanent revision history when an article changes.
5. **Technical documentation** (`docs` command) — manuals explaining traffic
   management, profiles, monitors, TLS, clustering, and authentication; iRules
   programming references; TMSH CLI and iControl REST references; architecture
   guides; administrator training labs; and AS3 automation documentation.
   Saves readable HTML and structured text, code examples, diagrams, applicable
   product versions, and chapter links. Images are downloaded for local use.

## Why a headless browser

`my.f5.com` is a Salesforce Lightning SPA. Article bodies — including every
`table.askf5table` we parse — render **inside shadow DOM**, so a plain HTTP
fetch returns only a loading shell and `page.content()` misses the content.
The vulnerability, lifecycle, and compatibility collectors render articles with
**Playwright (headless Chromium)** and extract the tables from shadow DOM;
parsing then happens in pure Python. The full KB and recent-article collectors
obtain HTML through Coveo, while technical documentation uses ordinary HTTP.

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
  all_articles/{Knumber}.html  # one per K-article: metadata header + F5's body verbatim
  all_articles.json      # {"{Knumber}.html": "short description"} for every file above
  article_metadata.json  # {"{Knumber}": metadata} for locally collected articles
  article_updates.json   # recent source publications/updates + observed changes
  article_history/{Knumber}/changes.json # observed new/updated/removed/restored events
  article_history/{Knumber}/{sha256}.html # preserved revisions, created on change
  docs.json              # technical documentation catalog, source scopes, and link graph
  docs/pages/{url-id}.html # readable documentation with locally mirrored images
  docs/pages/{url-id}.json # text, headings, code, diagrams, versions, source links
  docs/assets/           # images referenced by collected documentation
  docs/manifest.json     # documentation fetch timestamps; separate from CVE state
  docs/crawl.json        # pending URLs and page/image failures; completeness indicator
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
python -m f5scraper.cli articles             # full KB dump (not part of `all`)
python -m f5scraper.cli updates              # fetch KB articles published/updated in last 30 days
python -m f5scraper.cli updates --days 7     # smaller publication/change window
python -m f5scraper.cli updates --local      # build metadata/feed from existing HTML, offline
python -m f5scraper.cli docs                 # collect all configured technical documentation
python -m f5scraper.cli docs --doc-source manuals --doc-source architecture
python -m f5scraper.cli docs --doc-source irules --limit 100
```

Flags: `--refresh` (ignore cache), `--limit N` (cap reports/KB articles/docs fetches), `--ttl-days N`
(refresh content older than N days; default 7 for docs, 0/always otherwise), `--output DIR`
(default `data/output`), `--throttle SECONDS`, `--no-discover` (skip
Coveo search-discovery step), `--headful`, `-v`.

### Article metadata and history

`article_metadata.json` contains each article's title, document type, source
publication/update dates, status, applicable products and versions, description,
source URL, local filename, and SHA-256 hashes of the full HTML and body. It is
bootstrapped from the existing HTML files, so the current dataset can be indexed
with `updates --local` without downloading it again.

`article_updates.json` has two lists: `articles` contains current metadata for
articles F5 dates as recently published/updated; `changes` contains changes this
scraper actually observed. Each change includes its UTC `observed_at`, kind,
changed metadata fields, whether the body changed, old/new hashes, and paths to
the preserved HTML snapshots. F5's source dates and scraper observation times
are separate; the initial baseline does not create invented change events.

History keeps both sides of an update, even if F5 does not change its displayed
update date. Identical content produces no extra revision, and preserved history
is retained after an article is removed. Recent or limited fetches merge into
the existing indexes and never prune articles. Only a complete full `articles`
run can detect removals, with the existing protection against a sudden drop in
F5's index. Missing HTML bodies are skipped rather than replacing a saved copy.

The recent query relies on F5's source dates, so it can miss an undated edit to
an old article. Keep the daily full `articles` run to catch those edits. This
collector covers K-articles; the `docs` collector handles the selected manuals
and technical references described below.

### Technical documentation

Seven configurable sources are available: `manuals`, `irules`, `tmsh`,
`icontrol`, `architecture`, `labs`, and `as3`. The manual seeds cover LTM basics,
profiles, health monitors, TLS administration for 17.x and 21.x, device service
clustering, and APM authentication. Crawling follows chapter/reference links
within these selected manuals and documentation directories. It does not
expand into the entire F5 website or other product documentation versions.

Each page is keyed by a hash of its normalized source URL. Its JSON contains
full text, heading levels and paths, exact code examples, image descriptions
and local paths, Mermaid/inline SVG diagram definitions, breadcrumbs, source
links, and version metadata. The HTML preserves the documentation body and
tables, removes site navigation and scripts, and uses local image paths.
Mermaid diagrams are preserved as source definitions rather than rendered
graphics. PDF links and external resources are retained as links, not downloaded.
The AS3 API reference also retains its complete embedded OpenAPI definition in
`openapi`, including request/response schemas and examples hidden by page tabs.
Catalog `referring_urls` records incoming links; breadcrumbs and heading paths
describe hierarchy, since navigation links can form cycles.

F5 manuals often share one URL across many releases. `applies_to` retains the
publisher's explicit product/version lists; `url_version` records the URL label
separately. `documentation_version` is the reference project's version (for
example, TMSH or AS3), which is not necessarily a BIG-IP software version.
Unspecified versions remain null. Community/reference attribution is preserved
through source URLs, page text, and `publisher_product_labels`.

The collector uses ordinary HTTP without launching Chromium. Seeds are checked
each run to discover new chapters; other pages use a seven-day cache by default.
`--limit` caps page downloads, while cached pages still supply discovery links,
so repeated limited runs can continue filling the corpus. `--workers` controls
concurrency (default 4), and `--throttle` spaces all HTTP requests (default 1s).
Image downloads are cached; use `--refresh` to refresh saved images as well.

The catalog merges with earlier runs and keeps saved pages when a source fails.
`docs/crawl.json` explicitly reports pending URLs, failed pages, failed images,
and whether the selected crawl completed. No automatic document pruning occurs.

## Automated runs (GitHub Actions)

`.github/workflows/scrape.yml` runs weekly (and on manual dispatch), scrapes,
and commits the refreshed `data/output/` back to the repo using the built-in
`GITHUB_TOKEN`. The repo is a full Linux runner, so Chromium and the 6-hour job
limit comfortably handle even a first full historical scrape.

`.github/workflows/articles.yml` runs daily (02:30 UTC, and on manual dispatch),
re-fetches the full KB via `f5scraper.cli articles`, and commits only the
article files that changed plus their metadata, recent feed, and history. It
runs in its own concurrency group, so it never queues behind or displaces the
scrape jobs.

`.github/workflows/docs.yml` collects the technical documentation weekly and on
manual dispatch, commits documentation files and images, and reports source
counts plus incomplete downloads. It has its own concurrency group.

## Notes & limitations

- The advisory and lifecycle collectors parse rendered MyF5 articles;
  selectors may need updates if F5 redeploys the SPA.
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
- **F5 technical documentation** (`techdocs.f5.com`, `clouddocs.f5.com`, and
  linked F5 image assets) retains its original F5 or contributor ownership and
  terms. The repository's MIT license does not apply to copied documentation.
- **EPSS** and **CVSS** — FIRST.org, used with attribution.
- **CVE** identifiers — CVE Program; "CVE" is a trademark of MITRE.

Provided **as is**, for informational/security-research use, with no warranty.
Always verify against the authoritative source before acting on this data.
