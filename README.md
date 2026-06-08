# f5scraper — F5 vulnerability + EOL data scraper

Builds a structured JSON dataset from F5's support site (`my.f5.com`):

1. **Vulnerabilities** — every CVE / security exposure reached from the index
   article [K12201527](https://my.f5.com/manage/s/article/K12201527) →
   each **Quarterly Security Notification** report → each CVE's own article
   (severity, CVSS v3.1/v4.0 score + vector, affected products/versions,
   fixes, CWE, description).
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
(default `data/output`), `--throttle SECONDS`, `--headful`, `-v`.

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
