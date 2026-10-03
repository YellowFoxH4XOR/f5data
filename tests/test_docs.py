from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from f5scraper import docs


ROOT = "https://clouddocs.f5.com/test-docs/"
SOURCE = docs.DocSource("fixture", "manual", (ROOT,), (ROOT,))


def markup(title: str = "Traffic flow", links: str = "", extra: str = "") -> str:
    return f"""<html><head><title>{title}</title></head><body>
    <nav>UNRELATED SITE NAVIGATION</nav><article class="docs-container">
    <h1 id="root">{title}</h1><p>A sufficiently detailed explanation of how traffic flows.</p>
    <h2 id="pools">Pools<a class="headerlink">¶</a></h2><p>Healthy pool members receive traffic.</p>
    <h3 id="monitors">Monitors</h3><pre>when HTTP_REQUEST {{\n    pool app_pool\n}}</pre>
    {links}{extra}</article></body></html>"""


class ExtractionTests(unittest.TestCase):
    def test_content_examples_and_heading_hierarchy_are_preserved(self) -> None:
        text = markup(extra='<script>BAD_SCRIPT()</script><div class="mermaid">graph LR\nA--&gt;B</div>')
        doc = docs.parse_document(text, ROOT, SOURCE)
        self.assertNotIn("UNRELATED", doc["text"])
        self.assertNotIn("BAD_SCRIPT", doc["content_html"])
        self.assertNotIn("¶", doc["text"])
        self.assertEqual(doc["code_examples"][0]["text"], "when HTTP_REQUEST {\n    pool app_pool\n}")
        self.assertEqual(doc["headings"][-1]["path"], ["Traffic flow", "Pools"])
        self.assertEqual(doc["diagrams"], [{"format": "mermaid", "source": "graph LR\nA-->B"}])

    def test_explicit_applicable_versions_override_url_assumptions(self) -> None:
        text = """<html><head><title>BIG-IP Basics | BIG-IP Documentation</title>
        <meta name="product" content="BIG-IP Documentation"><meta name="product" content="BIG-IP LTM">
        <meta name="BIG-IP LTM" content="17.5.0"><meta name="BIG-IP LTM" content="21.0.0">
        <meta property="article:modified_time" content="2026-07-07T14:33:46-0400">
        </head><body><main><div class="card-section"><h2>Introduction to traffic management</h2>
        <p>Enough content to represent the table of contents for a technical manual.</p></div></main></body></html>"""
        doc = docs.parse_document(text, "https://techdocs.f5.com/en-us/bigip-14-1-0/manual.html", SOURCE)
        self.assertEqual(doc["url_version"], "14.1.0")
        self.assertEqual(doc["applies_to"], [{"product": "BIG-IP LTM", "versions": ["17.5.0", "21.0.0"]}])
        self.assertEqual(doc["title"], "BIG-IP Basics")
        self.assertEqual(doc["updated"], "2026-07-07T14:33:46-0400")

    def test_directory_aliases_fragments_and_scope_are_normalized(self) -> None:
        self.assertEqual(docs.normalize_url("index.html#pools", ROOT), ROOT)
        self.assertEqual(docs.normalize_url("child.html?q=1#pools", ROOT), ROOT + "child.html")
        self.assertIsNone(docs.normalize_url("javascript:alert(1)", ROOT))
        for url in [ROOT + "_static/script.html", ROOT + "search.html", ROOT + "guide.pdf",
                    "https://clouddocs.f5.com/another-guide/index.html"]:
            self.assertFalse(SOURCE.allows(url), url)
        self.assertTrue(SOURCE.allows(ROOT + "child.html"))

    def test_soft_404_and_salesforce_shell_are_rejected(self) -> None:
        for html in [markup("404 Page not found"), '<html><title>myF5</title><body>Loading</body></html>']:
            with self.assertRaises(ValueError):
                docs.parse_document(html, ROOT, SOURCE)

    def test_redoc_preserves_the_specification_and_hidden_examples_without_scripts(self) -> None:
        spec = {"openapi": "3.0.0", "info": {"title": "AS3", "version": "3.57.0"},
                "paths": {"/declare": {"post": {"summary": "Apply configuration"}}},
                "components": {"examples": {"declaration": {"value": {"class": "ADC", "name": "<example>"}}}}}
        state = json.dumps({"spec": {"data": spec}})
        text = ('<html><title>AS3 API</title><div id="redoc"><nav>API NAVIGATION</nav>'
                '<div class="api-content"><h1>AS3 API</h1>'
                '<p>Use POST to apply an application declaration to a target ADC.</p></div></div>'
                f'<script>const __redoc_state = {state}; BAD_SCRIPT();</script></html>')
        doc = docs.parse_document(text, ROOT, SOURCE)
        self.assertEqual(doc["openapi"], spec)
        self.assertEqual(doc["documentation_version"], "3.57.0")
        self.assertEqual(json.loads(doc["code_examples"][0]["text"]), {"class": "ADC", "name": "<example>"})
        self.assertNotIn("API NAVIGATION", doc["text"])
        self.assertNotIn("BAD_SCRIPT", docs._render(doc))
        self.assertIn("&lt;example&gt;", docs._render(doc))


class FetchTests(unittest.TestCase):
    def test_connection_reset_is_retried(self) -> None:
        response = MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b"Recovered document"
        response.url = ROOT
        response.headers.get_content_type.return_value = "text/html"
        with patch.object(docs.urllib.request, "urlopen", side_effect=[ConnectionResetError(54, "reset"), response]) as get, \
                patch.object(docs.time, "sleep"):
            self.assertEqual(docs.Fetcher(0).get(ROOT), (b"Recovered document", ROOT, "text/html"))
        self.assertEqual(get.call_count, 2)


class CrawlTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.output = Path(self.tmp.name)
        self.calls: list[str] = []
        self.responses = {}

    def get(self, url: str) -> tuple[bytes, str, str]:
        self.calls.append(url)
        value = self.responses[url]
        if isinstance(value, Exception):
            raise value
        if isinstance(value, tuple):
            return value
        return value.encode(), url, "text/html"

    async def collect(self, **options) -> dict:
        with patch.dict(docs.SOURCES, {"fixture": SOURCE}), patch.object(docs.Fetcher, "get", side_effect=self.get):
            return await docs.run(self.output, source_names=["fixture"], throttle=0, workers=2, **options)

    def load(self, name: str) -> dict:
        return json.loads((self.output / name).read_text())

    async def test_limit_then_cached_traversal_resumes_without_duplicates(self) -> None:
        self.responses = {
            ROOT: markup(links='<a href="child.html#pools">Child</a><a href="child.html#monitors">Same child</a>'),
            ROOT + "child.html": markup("Child", '<a href="last.html">Last</a>'),
            ROOT + "last.html": markup("Last"),
        }
        stats = await self.collect(limit=2)
        self.assertEqual(stats["documents"], 2)
        self.assertEqual(stats["pending"], 1)
        stats = await self.collect(limit=2)
        self.assertEqual(stats["documents"], 3)
        self.assertEqual(stats["cached"], 1)
        self.assertTrue(self.load("docs/crawl.json")["complete"])
        # A third pass refreshes only the seed, with unchanged semantic files.
        before = {p: p.stat().st_mtime_ns for p in (self.output / "docs/pages").glob("*")}
        stats = await self.collect()
        self.assertEqual(stats["changed"], 0)
        self.assertEqual(before, {p: p.stat().st_mtime_ns for p in before})
        self.assertEqual(self.calls.count(ROOT + "child.html"), 1)

    async def test_page_failure_preserves_prior_content_and_cached_links(self) -> None:
        self.responses = {ROOT: markup(links='<a href="child.html">Child</a>'), ROOT + "child.html": markup("Child")}
        await self.collect()
        index = self.load("docs.json")
        root_file = self.output / index["documents"][docs.document_id(ROOT)]["html_file"]
        original = root_file.read_text()
        self.responses[ROOT] = RuntimeError("upstream outage")
        stats = await self.collect(refresh=True)
        self.assertEqual(stats["documents"], 2)
        self.assertEqual(root_file.read_text(), original)
        self.assertEqual(stats["failed_pages"], 1)
        self.assertFalse(self.load("docs/crawl.json")["complete"])

    async def test_image_is_mirrored_once_and_html_uses_the_local_path(self) -> None:
        image_url = "https://clouddocs.f5.com/test-docs/diagram.png"
        self.responses = {ROOT: markup(extra='<img src="diagram.png" alt="Client to pool">'),
                          image_url: (b"PNG fixture bytes", image_url, "image/png")}
        await self.collect()
        doc = self.load(f"docs/pages/{docs.document_id(ROOT)}.json")
        local = doc["images"][0]["local_file"]
        self.assertEqual((self.output / local).read_bytes(), b"PNG fixture bytes")
        self.assertIn('../assets/' + Path(local).name,
                      (self.output / f"docs/pages/{docs.document_id(ROOT)}.html").read_text())
        await self.collect()
        self.assertEqual(self.calls.count(image_url), 1)

    async def test_external_links_and_redirects_cannot_expand_the_crawl(self) -> None:
        self.responses = {ROOT: markup(links='<a href="https://example.com/">External</a>'
                                            '<a href="https://clouddocs.f5.com/other/">Another collection</a>'
                                            '<a href="bad.html">Redirect</a>'),
                          ROOT + "bad.html": (markup("Other").encode(), "https://example.com/", "text/html")}
        stats = await self.collect()
        self.assertEqual(stats["documents"], 1)
        self.assertEqual(stats["failed_pages"], 1)
        self.assertNotIn("https://example.com/", self.calls)


if __name__ == "__main__":
    unittest.main()
