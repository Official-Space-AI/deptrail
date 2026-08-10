"""Tests for the command line, the demo, and the HTML report.

The demo is the path an evaluator takes first, so it is asserted on its output
and on its exit code — a scan that finds credentials to rotate must say so in a
way a script can act on, without anyone reading prose.
"""
import json
import subprocess
from pathlib import Path

import pytest

from deptrail.cli import EXIT_BAD_INPUT, EXIT_CLEAN, EXIT_INCOMPLETE, EXIT_ROTATE, main
from deptrail.demo import build


class TestDemo:
    def test_demo_confirms_the_install_and_names_the_credentials(self, tmp_path, capsys):
        code = main(["demo", "--workdir", str(tmp_path / "demo")])
        out = capsys.readouterr().out
        assert code == EXIT_ROTATE
        # api-server ran `npm ci` on the exposing commit: the install is proven.
        assert "CONFIRMED  ] api-server" in out
        assert "NPM_TOKEN" in out and "DEPLOY_KEY" in out
        # That workflow never names AWS_ACCESS_KEY, so it is not on the list.
        assert "AWS_ACCESS_KEY" not in out.split("rotate")[1].split("caveats")[0]
        # web-frontend skipped over the window entirely.
        assert "web-frontend" not in out.split("timeline")[1].split("rotate")[0]

    def test_demo_distinguishes_a_workflow_that_installs_nothing(self, tmp_path, capsys):
        main(["demo", "--workdir", str(tmp_path / "demo")])
        out = capsys.readouterr().out
        assert "LIKELY     ] docs-site" in out
        # Its CI installs nothing, so the credential is a local-install candidate.
        assert "ALGOLIA_KEY" in out and "DEVELOPER" in out

    def test_demo_is_reproducible(self, tmp_path, capsys):
        main(["demo", "--workdir", str(tmp_path / "a")])
        first = capsys.readouterr().out
        main(["demo", "--workdir", str(tmp_path / "b")])
        second = capsys.readouterr().out
        assert _without_shas(first) == _without_shas(second)

    def test_demo_json_is_machine_readable(self, tmp_path, capsys):
        main(["demo", "--workdir", str(tmp_path / "demo"), "--format", "json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["worst_grade"] == "CONFIRMED"
        assert payload["exposed_repos"] == ["api-server", "docs-site"]
        rotate = {(r["repo"], r["secret"]) for r in payload["rotate"]}
        assert ("api-server", "NPM_TOKEN") in rotate
        assert payload["proves_absence"] is True

    def test_demo_html_is_one_self_contained_file(self, tmp_path, capsys):
        target = tmp_path / "report.html"
        main(["demo", "--workdir", str(tmp_path / "demo"), "--format", "html",
              "--output", str(target)])
        html = target.read_text()
        assert html.startswith("<!doctype html>") and html.rstrip().endswith("</html>")
        for external in ("<script", "src=", "href=", "@import"):
            assert external not in html, f"report must not fetch {external}"
        assert "NPM_TOKEN" in html and "CONFIRMED" in html

    def test_demo_repos_have_real_history(self, tmp_path):
        repos = dict(build(tmp_path / "demo"))
        log = subprocess.run(
            ["git", "-C", str(repos["api-server"]), "log", "--format=%cI"],
            check=True, capture_output=True, text=True,
        ).stdout.split()
        assert len(log) == 3 and log[-1].startswith("2025-11-20")


def _without_shas(text: str) -> str:
    """Commit hashes differ between builds; everything else must not."""
    return "\n".join(
        " ".join(w for w in line.split() if not _looks_like_sha(w))
        for line in text.splitlines()
    )


def _looks_like_sha(word: str) -> bool:
    stripped = word.strip("(),")
    return len(stripped) >= 8 and all(c in "0123456789abcdef" for c in stripped)


class TestScan:
    def test_local_repos_without_ci(self, tmp_path, capsys):
        repos = dict(build(tmp_path / "demo"))
        advisory = tmp_path / "demo" / "demo-advisory.json"
        from deptrail.demo import advisory_path
        advisory = advisory_path(tmp_path / "demo")
        code = main(["scan", "--ioc", str(advisory), "--repo", str(repos["api-server"]),
                     "--no-ci"])
        out = capsys.readouterr().out
        assert code == EXIT_ROTATE
        # Without CI evidence nothing can be confirmed, and nothing is cleared.
        assert "POSSIBLE" in out and "CONFIRMED" not in out
        assert "no credential could be named" in out or "rotate (" in out

    def test_clean_repo_exits_zero(self, tmp_path, capsys):
        repos = dict(build(tmp_path / "demo"))
        from deptrail.demo import advisory_path
        advisory = advisory_path(tmp_path / "demo")
        code = main(["scan", "--ioc", str(advisory), "--repo", str(repos["web-frontend"]),
                     "--no-ci"])
        assert code == EXIT_CLEAN
        assert "no exposure found" in capsys.readouterr().out

    def test_missing_repo_path_is_incomplete_not_clean(self, tmp_path, capsys):
        from deptrail.demo import advisory_path
        build(tmp_path / "demo")
        advisory = advisory_path(tmp_path / "demo")
        code = main(["scan", "--ioc", str(advisory), "--repo", str(tmp_path / "nope"),
                     "--no-ci"])
        assert code == EXIT_INCOMPLETE
        assert "cannot prove absence" in capsys.readouterr().out

    def test_malformed_advisory_is_rejected_with_the_field(self, tmp_path, capsys):
        bad = tmp_path / "bad.json"
        bad.write_text('{"schema_version": 1, "id": "x"}')
        code = main(["scan", "--ioc", str(bad), "--repo", str(tmp_path), "--no-ci"])
        assert code == EXIT_BAD_INPUT
        assert "advisory rejected" in capsys.readouterr().err

    def test_scan_without_targets_explains_itself(self, capsys):
        code = main(["scan", "--ioc", "example-demo"])
        assert code == EXIT_BAD_INPUT
        assert "--org or one or more --repo" in capsys.readouterr().err


class TestFeeds:
    def test_bundled_feeds_are_listed_with_coverage(self, capsys):
        assert main(["feeds"]) == EXIT_CLEAN
        out = capsys.readouterr().out
        assert "example-demo" in out and "complete" in out


class TestHelp:
    def test_bare_invocation_prints_help(self, capsys):
        assert main([]) == EXIT_BAD_INPUT
        assert "usage: deptrail" in capsys.readouterr().out
