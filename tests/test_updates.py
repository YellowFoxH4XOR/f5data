from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from f5scraper import articles
from f5scraper.cache import Cache
from f5scraper.updates import ArticleHistory, metadata, metadata_from_html


def article(k: str = "K123", **values) -> dict:
    return {
        "k": k, "title": "A & B diagnostics", "doc_type": "Support Solution",
        "published": "2026-09-01", "updated": "2026-09-29", "status": "Final",
        "applies_to": ["BIG-IP LTM: 17.1.0, 17.5.0", "BIG-IP ASM"],
        "body": "<h2>Description</h2><p>A diagnostic example with enough prose for a summary.</p>",
        **values,
    }


def page(a: dict) -> tuple[str, str]:
    description = articles._description(a)
    return description, articles._render(a, description)


def result(a: dict, rowid: int) -> dict:
    return {"title": f"{a['k']}: {a['title']}", "raw": {
        "f5_kb_id": a["k"], "f5_title": a["title"], "rowid": rowid,
        "f5_document_type": [a["doc_type"]], "sfarticle_status__c": a["status"],
        "sfdetails__c": a["body"],
        "sfapplies_to_products__c": json.dumps([{"Product": p} for p in a["applies_to"]]),
    }}


class HistoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cache = Cache(Path(self.tmp.name))

    def history(self, at: str = "2026-10-03T00:00:00+00:00") -> ArticleHistory:
        return ArticleHistory(self.cache, observed_at=at)

    def store(self, a: dict, history: ArticleHistory | None = None) -> str:
        description, rendered = page(a)
        if history:
            history.record(a, description, rendered)
        self.cache.write_text(f"all_articles/{a['k']}.html", rendered)
        return rendered

    def events(self, k: str = "K123") -> list[dict]:
        return self.cache.read_json(f"article_history/{k}/changes.json") or []

    def test_existing_html_is_a_baseline_with_lossless_metadata(self) -> None:
        a = article()
        rendered = self.store(a)
        self.assertEqual(metadata(a, page(a)[0], rendered), metadata_from_html(a["k"], rendered))
        history = self.history()
        history.bootstrap()
        self.store(a, history)
        feed = history.save()
        self.assertEqual(feed["article_count"], 1)
        self.assertEqual(feed["change_count"], 0)
        self.assertFalse((self.cache.dir / "article_history").exists())

    def test_body_edit_with_unchanged_source_date_preserves_both_revisions(self) -> None:
        original = self.store(article())
        history = self.history()
        changed = self.store(article(body="<p>Updated diagnostic procedure.</p>"), history)
        history.save()
        event, = self.events()
        self.assertEqual(event["kind"], "updated")
        self.assertTrue(event["body_changed"])
        self.assertNotIn("updated", event["changed_fields"])
        self.assertEqual((self.cache.dir / event["previous_snapshot"]).read_text(), original)
        self.assertEqual((self.cache.dir / event["snapshot"]).read_text(), changed)
        # A later identical crawl must not rewrite history or change timestamps.
        later = self.history("2026-10-04T00:00:00+00:00")
        self.store(article(body="<p>Updated diagnostic procedure.</p>"), later)
        later.save()
        self.assertEqual(len(self.events()), 1)
        self.assertEqual(self.events()[0]["observed_at"], history.observed_at)

    def test_metadata_only_change_and_interrupted_retry_do_not_duplicate(self) -> None:
        self.store(article())
        history = self.history()
        a = article(status="In progress")
        description, rendered = page(a)
        history.record(a, description, rendered)
        # Simulate interruption before replacing the old canonical HTML.
        retry = self.history()
        self.store(a, retry)
        retry.save()
        event, = self.events()
        self.assertFalse(event["body_changed"])
        self.assertEqual(event["changed_fields"], ["status"])

    def test_new_removed_and_restored_retains_history(self) -> None:
        history = self.history()
        rendered = self.store(article(), history)
        history.remove("K123", rendered)
        (self.cache.dir / "all_articles/K123.html").unlink()
        history.save()
        restored = self.history("2026-10-04T00:00:00+00:00")
        self.store(article(), restored)
        restored.save()
        self.assertEqual([e["kind"] for e in self.events()], ["new", "removed", "restored"])
        self.assertEqual(len(list((self.cache.dir / "article_history/K123").glob("*.html"))), 1)

    def test_recent_feed_filters_source_dates_and_observations_separately(self) -> None:
        history = self.history()
        self.store(article(published="2020-01-01", updated="2020-01-02"), history)
        self.store(article("K456", published=None, updated="2026-10-01"), history)
        feed = history.save(days=7)
        self.assertEqual([a["k"] for a in feed["articles"]], ["K456"])
        self.assertEqual(len(feed["changes"]), 2)
        history.save(days=7)
        before = (self.cache.dir / "article_updates.json").stat().st_mtime_ns
        history.save(days=7)
        self.assertEqual((self.cache.dir / "article_updates.json").stat().st_mtime_ns, before)

    def test_stale_catalog_recovers_previous_metadata_from_canonical_file(self) -> None:
        old = article(status="In progress")
        self.store(article())
        history = self.history()
        history.bootstrap()
        history.save()
        original = self.store(old)
        recovered = self.history()
        self.store(article(), recovered)
        event, = self.events()
        self.assertEqual((self.cache.dir / event["previous_snapshot"]).read_text(), original)
        self.assertEqual(event["changed_fields"], ["status"])

    def test_interrupted_restore_is_still_a_single_restore_on_retry(self) -> None:
        history = self.history()
        rendered = self.store(article(), history)
        history.remove("K123", rendered)
        (self.cache.dir / "all_articles/K123.html").unlink()
        history.save()
        description, rendered = page(article())
        self.history().record(article(), description, rendered)
        retry = self.history()
        self.store(article(), retry)
        retry.save()
        self.assertEqual([e["kind"] for e in self.events()], ["new", "removed", "restored"])


class CollectionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.output = Path(self.tmp.name)
        self.cache = Cache(self.output)

    def seed(self, *items: dict) -> None:
        index = {}
        for a in items:
            description, rendered = page(a)
            self.cache.write_text(f"all_articles/{a['k']}.html", rendered)
            index[f"{a['k']}.html"] = description
        self.cache.write_json("all_articles.json", index)

    async def collect(self, pages: list[dict], **options) -> dict:
        with patch.object(articles, "_capture_coveo_token", new=AsyncMock(return_value="Bearer fixture")), \
             patch.object(articles, "_search_page", side_effect=pages), \
             patch.object(articles.time, "sleep"):
            return await articles.run(object(), self.output, **options)

    async def test_recent_and_limited_runs_keep_unseen_articles(self) -> None:
        self.seed(article("K1"), article("K2"))
        response = {"totalCount": 1, "results": [result(article("K3"), 3)]}
        await self.collect([response, {"results": []}], recent_only=True)
        self.assertEqual(len(self.cache.read_json("all_articles.json")), 3)
        await self.collect([{ "totalCount": 3, "results": [result(article("K4"), 4)]}], limit=1)
        self.assertEqual(len(self.cache.read_json("all_articles.json")), 4)
        self.assertTrue((self.output / "all_articles/K2.html").exists())

    async def test_complete_full_run_preserves_removed_article(self) -> None:
        self.seed(*(article(f"K{i}") for i in range(1, 12)))
        responses = [result(article(f"K{i}"), i) for i in range(1, 11)]
        stats = await self.collect([{ "totalCount": 10, "results": responses}, {"results": []}])
        self.assertEqual(stats["pruned"], 1)
        self.assertFalse((self.output / "all_articles/K11.html").exists())
        event, = self.cache.read_json("article_history/K11/changes.json")
        self.assertEqual(event["kind"], "removed")
        self.assertTrue((self.output / event["previous_snapshot"]).exists())

    async def test_sharp_index_drop_and_empty_body_never_delete_saved_articles(self) -> None:
        self.seed(article("K1"), article("K2"))
        stats = await self.collect([{ "totalCount": 1, "results": [result(article("K1"), 1)]}, {"results": []}])
        self.assertEqual(stats["pruned"], 0)
        original = (self.output / "all_articles/K1.html").read_text()
        stats = await self.collect([{ "totalCount": 2, "results": [result(article("K1", body=""), 1),
                                                                          result(article("K2"), 2)]}, {"results": []}])
        self.assertEqual(stats["pruned"], 0)
        self.assertEqual((self.output / "all_articles/K1.html").read_text(), original)

    async def test_stalled_cursor_raises_instead_of_looping(self) -> None:
        response = {"totalCount": 2, "results": [result(article(), 1)]}
        with self.assertRaisesRegex(RuntimeError, "cursor did not advance"):
            await self.collect([response, response], recent_only=True)

    def test_recent_query_keeps_date_group_and_rowid_cursor(self) -> None:
        with patch.object(articles, "_coveo_search", return_value={}) as search:
            articles._search_page("Bearer fixture", "123", 5, since="2026-09-03")
        query = search.call_args.kwargs["aq"]
        self.assertIn("(@f5_updated_published_date>=2026/09/03 OR @f5_original_published_date>=2026/09/03)", query)
        self.assertTrue(query.endswith("@rowid>123"))


if __name__ == "__main__":
    unittest.main()
