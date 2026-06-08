"""Headless-browser render layer for my.f5.com knowledge articles.

Why this exists: my.f5.com is a Salesforce Lightning SPA. The article body —
including every `table.askf5table` we care about — is rendered *inside the
shadow DOM* of a `lightning-formatted-rich-text` component. That means
`page.content()` (which serializes only the light DOM) returns nothing useful,
and a normal HTTP fetch returns just a loading shell.

So instead of returning HTML for offline parsing, `render_article` runs a
shadow-piercing JS routine (`_EXTRACT_JS`) in the page and returns fully
structured data: title, dates, body text, links, and every content table as a
grid of cells (with rowSpan/colSpan and `<sup>` footnotes stripped). Downstream
parsing in `parse.py` is then pure Python over that structure.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from playwright.async_api import async_playwright, Browser, Page, TimeoutError as PWTimeout

ARTICLE_URL = "https://my.f5.com/manage/s/article/{k}"

# A page is "ready" once the article body has rendered. The body — including the
# <h1> and every content table — lives inside a lightning-formatted-rich-text
# shadow root, so light-DOM selectors like "main h1" never match. We wait via a
# shadow-piercing function for at least one *content* table to appear. We must
# NOT key on the "askf5table" class: older articles render content tables as bare
# <table> with no class, and keying on the class made those time out (4x45s) and
# skip enrichment. This predicate mirrors isContentTable() in _EXTRACT_JS.
_READY_JS = r"""
() => {
  function isContentTable(el) {
    if (/askf5table/.test(el.className || '')) return true;
    let n = el;
    while (n) {
      if (n.tagName === 'LIGHTNING-FORMATTED-RICH-TEXT') return true;
      const root = n.getRootNode && n.getRootNode();
      n = n.parentElement || (root && root.host) || null;
    }
    return false;
  }
  function hasTable(root) {
    for (const el of (root.querySelectorAll ? root.querySelectorAll('*') : [])) {
      if (el.tagName === 'TABLE' && isContentTable(el)) return true;
      if (el.shadowRoot && hasTable(el.shadowRoot)) return true;
    }
    return false;
  }
  return hasTable(document.body);
}
"""

# The Salesforce community occasionally serves a "Sorry to interrupt / CSS Error"
# shell. We detect it and reload.
_CSS_ERROR_MARKERS = ("Sorry to interrupt", "CSS Error")

_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)

# Shadow-piercing extraction. Runs in the page; returns a JSON-serializable dict.
_EXTRACT_JS = r"""
() => {
  const SECTION_MAX = 130;

  // A content table is one inside the article body. Newer articles class theirs
  // "askf5table"; OLDER articles use bare <table> with no class. So we identify
  // content tables structurally: classed askf5table, OR descended from a
  // lightning-formatted-rich-text body (which excludes nav/footer layout
  // tables). Climbing crosses shadow boundaries via the host element.
  function isContentTable(el) {
    if (/askf5table/.test(el.className || '')) return true;
    let n = el;
    while (n) {
      if (n.tagName === 'LIGHTNING-FORMATTED-RICH-TEXT') return true;
      const root = n.getRootNode && n.getRootNode();
      n = n.parentElement || (root && root.host) || null;
    }
    return false;
  }

  // Collect all content tables in document order, descending into shadow roots.
  // Document order matters so each table's nearest preceding heading is found.
  function deepTables(root, acc) {
    const kids = root.querySelectorAll ? root.querySelectorAll('*') : [];
    for (const el of kids) {
      if (el.tagName === 'TABLE' && isContentTable(el)) acc.push(el);
      if (el.shadowRoot) deepTables(el.shadowRoot, acc);
    }
  }

  function firstLine(s) {
    return (s || '').replace(/ /g, ' ').trim().split('\n').map(x => x.trim()).filter(Boolean)[0] || '';
  }

  // Nearest preceding heading text for a table: scan previous siblings, then
  // climb to the parent and repeat. Skip elements that themselves contain a
  // table (those are wrappers, not headings).
  function sectionFor(table) {
    let node = table;
    for (let hops = 0; hops < 8 && node; hops++) {
      let sib = node.previousElementSibling;
      while (sib) {
        if (!sib.querySelector || !sib.querySelector('table')) {
          const t = firstLine(sib.textContent);
          if (t && t.length <= SECTION_MAX) return t;
        }
        sib = sib.previousElementSibling;
      }
      node = node.parentElement;
    }
    return null;
  }

  function cellData(td) {
    // Clone so we can strip <sup> footnote markers without mutating the page.
    const clone = td.cloneNode(true);
    clone.querySelectorAll('sup').forEach(s => s.remove());
    // Preserve line breaks as newlines so multi-value cells stay separable.
    clone.querySelectorAll('br').forEach(br => br.replaceWith('\n'));
    const text = (clone.textContent || '').replace(/ /g, ' ')
      .split('\n').map(x => x.trim()).filter(Boolean).join('\n');
    const links = Array.from(td.querySelectorAll('a')).map(a => ({
      text: (a.textContent || '').trim(),
      href: a.getAttribute('href'),
    }));
    return { text, rowspan: td.rowSpan || 1, colspan: td.colSpan || 1, links };
  }

  const tableEls = [];
  deepTables(document.body, tableEls);
  const tables = tableEls.map(t => {
    const rows = Array.from(t.querySelectorAll('tr')).map(tr =>
      Array.from(tr.querySelectorAll('th,td')).map(cellData)
    ).filter(r => r.length > 0);
    const header = rows.length ? rows[0].map(c => c.text) : [];
    return { section: sectionFor(t), header, rows };
  });

  const bodyText = (document.querySelector('main') || document.body).innerText || '';

  // <h1> lives in shadow DOM; find it with a shadow-piercing walk.
  let title = '';
  (function findH1(root) {
    if (title) return;
    const hs = root.querySelectorAll ? root.querySelectorAll('h1') : [];
    if (hs.length) { title = hs[0].textContent.trim(); return; }
    for (const el of (root.querySelectorAll ? root.querySelectorAll('*') : []))
      if (el.shadowRoot) findH1(el.shadowRoot);
  })(document);
  if (!title) title = document.title || '';

  function grabDate(label) {
    const m = bodyText.match(new RegExp(label + '\\s*:?\\s*([A-Z][a-z]{2} \\d{1,2}, \\d{4})'));
    return m ? m[1] : null;
  }

  // All anchors in the article, collected with a shadow-piercing walk (the
  // table links and related-article links are inside shadow roots). Deduped by
  // href+text.
  const seen = new Set();
  const links = [];
  (function walkLinks(root) {
    for (const el of (root.querySelectorAll ? root.querySelectorAll('*') : [])) {
      if (el.tagName === 'A') {
        const href = el.getAttribute('href');
        if (href) {
          const key = href + '|' + (el.textContent || '').trim();
          if (!seen.has(key)) { seen.add(key); links.push({ text: (el.textContent || '').trim(), href }); }
        }
      }
      if (el.shadowRoot) walkLinks(el.shadowRoot);
    }
  })(document.querySelector('main') || document.body);

  return {
    title,
    published: grabDate('Published Date'),
    updated: grabDate('Updated Date'),
    bodyText,
    tables,
    links,
    isErrorShell: /Sorry to interrupt|CSS Error/.test(bodyText) && tables.length === 0,
  };
}
"""


@dataclass
class ArticleSession:
    """Owns a single Playwright browser + page, reused across all article loads.

    Launching Chromium per-article would dominate runtime; one long-lived page
    navigated repeatedly is far cheaper. Use as an async context manager.
    """

    headless: bool = True
    throttle_seconds: float = 1.0
    nav_timeout_ms: int = 60_000
    ready_timeout_ms: int = 45_000
    max_reloads: int = 3

    _browser: Browser | None = None
    _page: Page | None = None
    _pw: Any = None

    async def __aenter__(self) -> "ArticleSession":
        self._pw = await async_playwright().start()
        self._browser = await self._pw.chromium.launch(headless=self.headless)
        context = await self._browser.new_context(user_agent=_USER_AGENT)
        self._page = await context.new_page()
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._browser:
            await self._browser.close()
        if self._pw:
            await self._pw.stop()

    async def render_article(self, k_number: str) -> dict[str, Any]:
        """Render an article and return the extracted structured dict.

        Retries the Salesforce "CSS Error" shell up to `max_reloads` times.
        Raises RuntimeError if the body never renders (fail loud — never return
        a half-rendered page).
        """
        assert self._page is not None, "session not started"
        url = ARTICLE_URL.format(k=k_number)
        last_err: Exception | None = None

        for attempt in range(self.max_reloads + 1):
            try:
                await self._page.goto(url, timeout=self.nav_timeout_ms, wait_until="domcontentloaded")
                await self._page.wait_for_function(_READY_JS, timeout=self.ready_timeout_ms)
                # Give shadow-DOM rich text a beat to finish populating.
                await self._page.wait_for_timeout(800)
                data = await self._page.evaluate(_EXTRACT_JS)
                if data.get("isErrorShell"):
                    raise RuntimeError("Salesforce CSS-error shell rendered")
                data["k_number"] = k_number
                data["url"] = url
                if self.throttle_seconds:
                    await asyncio.sleep(self.throttle_seconds)
                return data
            except (PWTimeout, RuntimeError) as e:  # noqa: PERF203 - retry loop
                last_err = e
                if attempt < self.max_reloads:
                    await self._page.wait_for_timeout(1500)
                    continue

        raise RuntimeError(f"Failed to render {k_number} after {self.max_reloads + 1} attempts: {last_err}")
