from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, call, patch

from f5scraper import cli


class LegacyCommandTests(unittest.TestCase):
    def invoke(self, command: str, *options: str) -> tuple[MagicMock, dict[str, AsyncMock]]:
        browser = MagicMock()
        session = object()
        browser.return_value.__aenter__ = AsyncMock(return_value=session)
        browser.return_value.__aexit__ = AsyncMock(return_value=False)
        collectors = {name: AsyncMock() for name in ("vulns", "eol", "compat", "articles", "docs")}
        self.session = session
        with patch.object(cli, "ArticleSession", browser), \
                patch.object(cli.vulns, "run", collectors["vulns"]), \
                patch.object(cli.eol, "run", collectors["eol"]), \
                patch.object(cli.compat, "run", collectors["compat"]), \
                patch.object(cli.articles, "run", collectors["articles"]), \
                patch.object(cli.docs, "run", collectors["docs"]), \
                patch.object(cli.logging, "basicConfig"), \
                patch("sys.argv", ["f5scraper", command, *options]):
            cli.main()
        return browser, collectors

    def test_existing_commands_keep_default_routes_and_options(self) -> None:
        routes = {"all": {"eol", "compat", "vulns"}, "vulns": {"vulns"},
                  "eol": {"eol"}, "compat": {"compat"}, "articles": {"articles"}}
        for command, expected in routes.items():
            with self.subTest(command=command):
                browser, collectors = self.invoke(command)
                browser.assert_called_once_with(headless=True, throttle_seconds=1.0)
                self.assertEqual({name for name, fn in collectors.items() if fn.await_count}, expected)
                for name in expected:
                    kwargs = {"refresh": False, "ttl_days": 0}
                    if name == "vulns":
                        kwargs.update(limit=None, no_discover=False)
                    elif name == "articles":
                        kwargs = {"limit": None, "recent_only": False, "days": 30}
                    self.assertEqual(collectors[name].await_args,
                                     call(self.session, Path("data/output"), **kwargs))

    def test_existing_flags_and_zero_limit_remain_accepted(self) -> None:
        browser, collectors = self.invoke("all", "--limit", "0", "--ttl-days", "12",
                                          "--refresh", "--no-discover", "--headful",
                                          "--throttle", "0.5", "--output", "/tmp/f5-cli-fixture")
        browser.assert_called_once_with(headless=False, throttle_seconds=0.5)
        collectors["vulns"].assert_awaited_once_with(
            self.session, Path("/tmp/f5-cli-fixture"), refresh=True, ttl_days=12,
            limit=0, no_discover=True)
        for name in ("eol", "compat"):
            collectors[name].assert_awaited_once_with(
                self.session, Path("/tmp/f5-cli-fixture"), refresh=True, ttl_days=12)
        _, collectors = self.invoke("articles", "--limit", "0")
        collectors["articles"].assert_awaited_once_with(
            self.session, Path("data/output"), limit=0, recent_only=False, days=30)

    def test_new_commands_still_require_a_positive_download_limit(self) -> None:
        for command in ("docs", "updates"):
            with self.subTest(command=command), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    self.invoke(command, "--limit", "0")
                self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
