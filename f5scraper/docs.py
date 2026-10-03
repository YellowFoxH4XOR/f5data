"""Collect scoped F5 manuals, technical references, architecture, and labs.

These sites serve normal HTML, so this collector does not need Chromium.
Each page has readable HTML plus structured text, headings, code, diagrams,
version metadata, and links. Images are mirrored locally. Existing documents
are retained on failures and limited runs; cached links allow later runs to
continue discovering pages without refetching the whole corpus.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import http.client
import json
import logging
import re
import threading
import time
import urllib.error
import urllib.request
from collections import Counter, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup

from .cache import Cache

log = logging.getLogger("f5scraper.docs")
INDEX_FILE = "docs.json"
STATE_FILE = "docs/manifest.json"
REPORT_FILE = "docs/crawl.json"
_UA = "f5scraper/0.1 (public F5 technical documentation collector)"
_ASSET_HOSTS = {"clouddocs.f5.com", "techdocs.f5.com", "cdn.f5.com", "www.f5.com"}
_MAX_BYTES = 20 * 1024 * 1024
_STYLE = """body{max-width:1100px;margin:2rem auto;padding:0 1rem;font:16px/1.6 system-ui}
pre,.mermaid{white-space:pre-wrap;background:#f3f4f6;padding:1rem;overflow:auto}
img,svg{max-width:100%;height:auto}table{border-collapse:collapse}td,th{border:1px solid #ddd;padding:.5rem}
header{border-bottom:1px solid #ddd;margin-bottom:2rem}code{font-family:monospace}"""


def normalize_url(url: str, base: str = "") -> str | None:
    try:
        parts = urlsplit(urljoin(base, url))
        port = parts.port
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
        return None
    if port not in (None, 80, 443):
        return None
    path = parts.path or "/"
    if path.endswith("/index.html"):
        path = path[:-10]
    return urlunsplit(("https", parts.hostname.lower(), path, "", ""))


@dataclass(frozen=True)
class DocSource:
    name: str
    kind: str
    seeds: tuple[str, ...]
    prefixes: tuple[str, ...]

    def allows(self, url: str) -> bool:
        path = urlsplit(url).path
        if any(part in path.split("/") for part in ("_static", "_sources", "_downloads")):
            return False
        if path.rsplit("/", 1)[-1] in ("search.html", "genindex.html", "py-modindex.html"):
            return False
        if not (path.endswith(".html") or path.endswith("/")):
            return False
        return url in self.seeds or any(url.startswith(prefix) for prefix in self.prefixes)


_MANUALS = (
    "https://techdocs.f5.com/en-us/bigip-14-1-0/big-ip-local-traffic-management-basics-14-1-0.html",
    "https://techdocs.f5.com/en-us/bigip-16-1-0/big-ip-local-traffic-management-profiles-reference.html",
    "https://techdocs.f5.com/en-us/bigip-16-0-0/big-ip-local-traffic-manager-monitors-reference.html",
    "https://techdocs.f5.com/en-us/bigip-17-0-0/big-ip-system-ssl-administration.html",
    "https://techdocs.f5.com/en-us/bigip-21-0-0/big-ip-system-ssl-administration.html",
    "https://techdocs.f5.com/en-us/bigip-14-1-0/big-ip-device-service-clustering-administration-14-1-0.html",
    "https://techdocs.f5.com/en-us/bigip-16-1-0/big-ip-access-policy-manager-authentication-essentials.html",
)
SOURCES = {
    "manuals": DocSource("manuals", "manual", _MANUALS, tuple(url[:-5] + "/" for url in _MANUALS)),
    "irules": DocSource("irules", "programming_reference", ("https://clouddocs.f5.com/api/irules/",),
                        ("https://clouddocs.f5.com/api/irules/",)),
    "tmsh": DocSource("tmsh", "cli_reference", ("https://clouddocs.f5.com/cli/tmsh-reference/latest/",),
                      ("https://clouddocs.f5.com/cli/tmsh-reference/latest/",)),
    "icontrol": DocSource("icontrol", "api_reference", ("https://clouddocs.f5.com/api/icontrol-rest/",),
                          ("https://clouddocs.f5.com/api/icontrol-rest/",)),
    "architecture": DocSource("architecture", "architecture", (
        "https://clouddocs.f5.com/sslo-troubleshooting-guide/architecture.html",),
        ("https://clouddocs.f5.com/sslo-troubleshooting-guide/",)),
    "labs": DocSource("labs", "training_lab", (
        "https://clouddocs.f5.com/training/community/f5cert/html/class2/class2.html",),
        ("https://clouddocs.f5.com/training/community/f5cert/html/class2/",)),
    "as3": DocSource("as3", "automation_reference", (
        "https://clouddocs.f5.com/products/extensions/f5-appsvcs-extension/latest/",),
        ("https://clouddocs.f5.com/products/extensions/f5-appsvcs-extension/latest/",)),
}


def document_id(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()[:24]


def parse_document(markup: str, url: str, source: DocSource) -> dict[str, Any]:
    soup = BeautifulSoup(markup, "html.parser")
    page_title = soup.title.get_text(" ", strip=True) if soup.title else ""
    if re.search(r"\b(?:404|page not found|access denied|just a moment)\b", page_title, re.I):
        raise ValueError(f"documentation error page: {page_title}")
    content = soup.select_one("article.manual-chapter, article.docs-container, main .card-section, #redoc .api-content")
    if content is None or len(content.get_text(strip=True)) < 40:
        raise ValueError("no technical documentation body found")

    # Redoc's server-rendered page includes its complete OpenAPI definition.
    # Decode the JSON only; never execute the publisher's JavaScript. Keeping
    # the definition also preserves examples hidden by the interactive tabs.
    openapi = None
    for script in soup.select("script"):
        match = re.search(r"(?:const|let|var)\s+__redoc_state\s*=\s*", script.get_text())
        if match:
            state, _ = json.JSONDecoder().raw_decode(script.get_text()[match.end():])
            candidate = state.get("spec", {}).get("data", {})
            if isinstance(candidate, dict) and candidate.get("openapi") and candidate.get("paths"):
                openapi = candidate
            break

    # Extract applicability from F5's explicit product/version metadata. A
    # version in a URL is retained separately and never replaces these lists.
    product_labels = list(dict.fromkeys(m.get("content", "") for m in soup.select('meta[name="product"]')
                                       if m.get("content")))
    products = [label for label in product_labels if label != "BIG-IP Documentation"
                and re.match(r"^(?:BIG-IP\b|F5 BIG-IP\b|F5OS\b|NGINX\b|F5 SSL Orchestrator\b|F5 Distributed Cloud\b)", label)]
    applies_to = [{"product": product, "versions": list(dict.fromkeys(
        m.get("content", "") for m in soup.find_all("meta", attrs={"name": product}) if m.get("content")
    ))} for product in products]
    explicit_version = soup.select_one("button.dropbtn")
    version_meta = soup.select_one('meta[name="version"]')
    documentation_version = version_meta.get("content") or None if version_meta else None
    if openapi:
        documentation_version = openapi.get("info", {}).get("version") or documentation_version
    if explicit_version:
        match = re.search(r"\d+\.\d+\.\d+(?:\.\d+)?", explicit_version.get_text())
        if match:
            documentation_version = match.group()
    url_version = re.search(r"/bigip-(\d+(?:-\d+)+)/", url)
    if not documentation_version and source.name == "as3":
        # AS3's version selector is sometimes injected by JavaScript, but its
        # document header still states the actual extension version.
        match = re.search(r"(?:Extension|Version:)\s+(\d+\.\d+\.\d+)", soup.get_text(" "), re.I)
        documentation_version = match.group(1) if match else None
    crumbs = []
    for anchor in soup.select(".breadcrumb-layout a, .breadcrumb a, .wy-breadcrumbs a"):
        href = urljoin(url, anchor.get("href", ""))
        label = anchor.get_text(" ", strip=True)
        if label:
            crumbs.append({"title": label, "url": href})
    date_meta = soup.select_one('meta[property="article:modified_time"]')
    if date_meta is None:
        date_meta = soup.select_one('meta[name="updated_date"]')
    updated = date_meta.get("content") if date_meta else None

    # Preserve the publisher's HTML body while removing site navigation and
    # executable code. Paragraphs, tables, examples, inline SVG, and Mermaid
    # diagram definitions survive extraction.
    body = BeautifulSoup(str(content), "html.parser")
    for node in body.select("script, style, nav, .headerlink, .related, .sidebar, .version-warning"):
        node.decompose()
    if openapi:
        example_section = body.new_tag("section")
        heading = body.new_tag("h2", id="openapi-examples")
        heading.string = "OpenAPI examples"
        example_section.append(heading)
        for name, example in openapi.get("components", {}).get("examples", {}).items():
            if "value" not in example:
                continue
            heading = body.new_tag("h3")
            heading.string = name
            pre = body.new_tag("pre")
            pre.string = json.dumps(example["value"], ensure_ascii=False, indent=2)
            example_section.append(heading)
            example_section.append(pre)
        body.append(example_section)
    title_node = body.select_one("h1")
    title = title_node.get_text(" ", strip=True) if title_node else page_title.split(" | ")[0]
    headings = []
    stack: list[dict[str, Any]] = []
    for node in body.select("h1,h2,h3,h4,h5,h6"):
        level = int(node.name[1])
        while stack and stack[-1]["level"] >= level:
            stack.pop()
        anchor = node.get("id") or (node.parent.get("id") if node.parent else None)
        heading = {"title": node.get_text(" ", strip=True), "level": level,
                   "anchor": anchor, "path": [h["title"] for h in stack]}
        headings.append(heading)
        stack.append(heading)
    examples = []
    for pre in body.select("pre"):
        context = pre.find_previous(re.compile(r"^h[1-6]$"))
        examples.append({"text": pre.get_text(),
                         "section": context.get_text(" ", strip=True) if context else None})
    diagrams = [{"format": "mermaid", "source": node.get_text()}
                for node in body.select(".mermaid")]
    diagrams.extend({"format": "svg", "source": str(node)} for node in body.select("svg"))
    links = []
    for anchor in body.select("a[href]"):
        href = urljoin(url, anchor["href"])
        if urlsplit(href).scheme not in ("http", "https"):
            continue
        anchor["href"] = href
        links.append({"url": href, "title": anchor.get_text(" ", strip=True)})
    images = []
    for image in body.select("img[src]"):
        href = urljoin(url, image["src"])
        image["src"] = href
        # Use a single original image rather than publisher/CDN srcset variants.
        image.attrs.pop("srcset", None)
        images.append({"url": href, "alt": image.get("alt", ""), "local_file": None})
    document = {
        "id": document_id(url), "url": url, "source": source.name, "kind": source.kind,
        "title": title, "publisher_product_labels": product_labels,
        "applies_to": applies_to, "documentation_version": documentation_version,
        "url_version": url_version.group(1).replace("-", ".") if url_version else None,
        "updated": updated, "breadcrumbs": crumbs, "headings": headings,
        "text": body.get_text("\n", strip=True), "code_examples": examples,
        "diagrams": diagrams, "images": images, "links": links,
        "content_html": str(body),
    }
    if openapi:
        document["openapi"] = openapi
    return document


class Fetcher:
    """Bounded public HTTP downloads with a shared interval between requests."""

    def __init__(self, throttle: float) -> None:
        self.throttle = max(0.0, throttle)
        self.lock = threading.Lock()
        self.next_request = 0.0

    def get(self, url: str) -> tuple[bytes, str, str]:
        last_error: Exception | None = None
        for attempt in range(3):
            with self.lock:
                pause = max(0.0, self.next_request - time.monotonic())
                self.next_request = time.monotonic() + pause + self.throttle
            if pause:
                time.sleep(pause)
            try:
                request = urllib.request.Request(url, headers={"User-Agent": _UA})
                with urllib.request.urlopen(request, timeout=30) as response:
                    data = response.read(_MAX_BYTES + 1)
                    if len(data) > _MAX_BYTES:
                        raise ValueError("download exceeds 20 MiB limit")
                    return data, response.url, response.headers.get_content_type()
            except urllib.error.HTTPError as exc:
                if exc.code not in (429, 500, 502, 503, 504):
                    raise
                last_error = exc
            except (urllib.error.URLError, TimeoutError, ConnectionError, http.client.IncompleteRead) as exc:
                last_error = exc
            if attempt < 2:
                time.sleep(2 ** attempt)
        raise RuntimeError(f"download failed after 3 attempts: {last_error}")


def _fresh(entry: dict[str, Any], ttl_days: int) -> bool:
    if ttl_days <= 0:
        return False
    try:
        return datetime.now(timezone.utc) - datetime.fromisoformat(entry["fetched_at"]) < timedelta(days=ttl_days)
    except (KeyError, ValueError, TypeError):
        return False


def _write_bytes(path: Path, data: bytes) -> bool:
    if path.exists() and path.read_bytes() == data:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return True


async def _mirror_images(doc: dict[str, Any], cache: Cache, fetcher: Fetcher, *, refresh: bool) -> list[dict]:
    failures = []
    for image in doc["images"]:
        url = normalize_url(image["url"])
        if not url or urlsplit(url).hostname not in _ASSET_HOSTS:
            continue
        suffix = Path(urlsplit(url).path).suffix.lower()
        if suffix not in (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".avif"):
            suffix = ".image"
        rel = f"docs/assets/{document_id(url)}{suffix}"
        path = cache.dir / rel
        try:
            if refresh or not path.exists():
                data, final_url, content_type = await asyncio.to_thread(fetcher.get, url)
                if urlsplit(final_url).hostname not in _ASSET_HOSTS or not content_type.startswith("image/"):
                    raise ValueError("image URL returned a redirect or non-image response")
                _write_bytes(path, data)
            image["local_file"] = rel
        except Exception as exc:
            log.warning("docs: image %s: %s", url, exc)
            failures.append({"url": url, "error": str(exc)})
    return failures


def _render(doc: dict[str, Any]) -> str:
    body = BeautifulSoup(doc["content_html"], "html.parser")
    mirrored = {i["url"]: i["local_file"] for i in doc["images"] if i["local_file"]}
    for image in body.select("img[src]"):
        if image["src"] in mirrored:
            image["src"] = "../assets/" + Path(mirrored[image["src"]]).name
    esc = html.escape
    version = doc["documentation_version"] or "See product applicability metadata"
    spec = ("<details><summary>Complete OpenAPI specification</summary><pre>"
            + esc(json.dumps(doc["openapi"], ensure_ascii=False, indent=2)) + "</pre></details>"
            if doc.get("openapi") else "")
    return ("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
            f"<title>{esc(doc['title'])}</title><link rel=\"canonical\" href=\"{esc(doc['url'])}\">"
            f"<style>{_STYLE}</style></head><body><header><h1>{esc(doc['title'])}</h1>"
            f"<p>{esc(doc['kind'])} · {esc(version)}</p>"
            f"<a href=\"{esc(doc['url'])}\">Original F5 documentation</a></header>\n{body}\n{spec}</body></html>\n")


async def run(
    output_dir: Path, *, source_names: list[str] | None = None, limit: int | None = None,
    refresh: bool = False, ttl_days: int = 7, throttle: float = 1.0, workers: int = 4,
) -> dict[str, Any]:
    selected = [SOURCES[name] for name in (source_names or list(SOURCES))]
    cache = Cache(output_dir)
    previous = cache.read_json(INDEX_FILE) or {}
    index: dict[str, dict[str, Any]] = previous.get("documents", {})
    state: dict[str, dict[str, Any]] = cache.read_json(STATE_FILE) or {}
    fetcher = Fetcher(throttle)
    queue: deque[tuple[str, DocSource]] = deque()
    queued: set[str] = set()
    visited: set[str] = set()
    parents: dict[str, set[str]] = {}
    errors: list[dict[str, str]] = []
    asset_errors: list[dict] = []
    fetched = changed = cached = 0

    def enqueue(url: str, source: DocSource, parent: str | None = None) -> None:
        clean = normalize_url(url)
        if clean and source.allows(clean):
            if parent and parent != clean:
                parents.setdefault(clean, set()).add(parent)
            if clean not in queued:
                queued.add(clean)
                queue.append((clean, source))

    for source in selected:
        for seed in source.seeds:
            enqueue(seed, source)

    async def collect(url: str, source: DocSource) -> tuple[dict | None, bool]:
        nonlocal fetched, changed, cached
        entry = state.get(url, {})
        prior_id = entry.get("id", document_id(url))
        rel = f"docs/pages/{prior_id}.json"
        # Seed contents are refreshed every run so new chapters are discovered.
        if (not refresh and url not in source.seeds and _fresh(entry, ttl_days)
                and entry.get("assets_complete", True)):
            prior = cache.read_json(rel)
            if prior and (cache.dir / f"docs/pages/{prior_id}.html").exists():
                cached += 1
                return prior, False
        fetched += 1
        try:
            data, final, content_type = await asyncio.to_thread(fetcher.get, url)
            canonical = normalize_url(final)
            if not canonical or not source.allows(canonical) or content_type != "text/html":
                raise ValueError("documentation URL redirected outside its section or returned non-HTML")
            doc = parse_document(data.decode("utf-8"), canonical, source)
            failures = await _mirror_images(doc, cache, fetcher, refresh=refresh)
            asset_errors.extend(failures)
            page = _render(doc)
            doc.pop("content_html")
            # Observation time belongs in the crawl state, not semantic content.
            doc["content_hash"] = hashlib.sha256(page.encode()).hexdigest()
            pid = doc["id"]
            wrote_html = cache.write_text(f"docs/pages/{pid}.html", page)
            wrote_json = cache.write_json(f"docs/pages/{pid}.json", doc)
            changed += bool(wrote_html or wrote_json)
            state[url] = {"id": pid, "fetched_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
                          "assets_complete": not failures}
            return doc, True
        except Exception as exc:
            log.warning("docs: %s: %s", url, exc)
            errors.append({"url": url, "source": source.name, "error": str(exc)})
            # Follow cached links even if an upstream outage prevents refresh.
            return cache.read_json(rel), False

    def save() -> None:
        # Keep the previous catalog on limited runs and source failures. No
        # automatic removal: a vanished link is not proof a manual was retired.
        counts = Counter(d["source"] for d in index.values())
        sources = dict(previous.get("sources", {}))
        for source in selected:
            sources[source.name] = {"kind": source.kind, "seeds": list(source.seeds),
                                    "prefixes": list(source.prefixes), "document_count": counts[source.name]}
        cache.write_json(INDEX_FILE, {"document_count": len(index), "sources": sources, "documents": index})
        cache.write_json(STATE_FILE, state)
        cache.write_json(REPORT_FILE, {"selected_sources": [s.name for s in selected],
            "pending": [{"url": url, "source": source.name} for url, source in queue],
            "failed_pages": errors, "failed_images": asset_errors,
            "complete": not queue and not errors and not asset_errors})

    while queue:
        batch = []
        scheduled = 0
        while queue and len(batch) < workers:
            url, source = queue[0]
            entry = state.get(url, {})
            needs_fetch = (refresh or url in source.seeds or not _fresh(entry, ttl_days)
                           or not entry.get("assets_complete", True)
                           or not (cache.dir / f"docs/pages/{entry.get('id', document_id(url))}.json").exists()
                           or not (cache.dir / f"docs/pages/{entry.get('id', document_id(url))}.html").exists())
            if limit is not None and needs_fetch and fetched + scheduled >= limit:
                break
            queue.popleft()
            visited.add(url)
            batch.append((url, source))
            scheduled += needs_fetch
        if not batch:
            break
        documents = await asyncio.gather(*(collect(url, source) for url, source in batch))
        for (requested, source), (doc, _) in zip(batch, documents):
            if not doc:
                continue
            pid = doc["id"]
            # This is a link graph, not a parent hierarchy: references and
            # next/previous links can form cycles. Breadcrumbs and heading
            # paths preserve the publisher's actual document hierarchy.
            old = index.get(pid, {})
            old_parents = set(old.get("referring_urls", old.get("parent_urls", [])))
            index[pid] = {key: doc[key] for key in (
                "id", "url", "source", "kind", "title", "applies_to", "documentation_version",
                "url_version", "updated", "content_hash")}
            index[pid].update({"html_file": f"docs/pages/{pid}.html", "json_file": f"docs/pages/{pid}.json",
                               "referring_urls": sorted(old_parents | parents.get(requested, set()))})
            for link in doc["links"]:
                enqueue(link["url"], source, doc["url"])
        if len(visited) % 40 < len(batch):
            save()
            log.info("docs: %d pages visited, %d fetched, %d cached, %d changed, %d queued",
                     len(visited), fetched, cached, changed, len(queue))
    for entry in index.values():
        if "parent_urls" in entry:
            entry["referring_urls"] = entry.pop("parent_urls")
    # Incoming links discovered after the target was processed still belong in the graph.
    for url, incoming in parents.items():
        pid = state.get(url, {}).get("id", document_id(url))
        if pid in index:
            index[pid]["referring_urls"] = sorted(set(index[pid]["referring_urls"]) | incoming)
    save()
    summary = {"documents": len(index), "fetched": fetched, "cached": cached, "changed": changed,
               "pending": len(queue), "failed_pages": len(errors), "failed_images": len(asset_errors)}
    log.info("docs: %s", summary)
    return summary
