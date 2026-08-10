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
        # The decision comes first: a consumer must not have to infer it.
        assert payload["decision"] == {
            "exit_code": EXIT_ROTATE, "rotation_required": True,
            "scan_complete": True, "worst_grade": "CONFIRMED",
        }
        assert payload["exposed_repos"] == ["api-server", "docs-site"]
        rotate = {(r["repo"], r["secret"]) for r in payload["rotate"]}
        assert ("api-server", "NPM_TOKEN") in rotate
        # The advisory travels with the verdict, so a report can be re-read later.
        assert payload["advisory"]["coverage"] == "complete"
        assert payload["advisory"]["window"]["start"].startswith("2025-11-24")

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
        assert "could not be named" in out or "rotate (" in out

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


class TestExitCodeContract:
    """codex/claude: every outcome maps to exactly one code, at the process boundary."""

    def _advisory(self, tmp_path):
        from deptrail.demo import advisory_path
        build(tmp_path / "demo")
        return advisory_path(tmp_path / "demo")

    def test_unnameable_credentials_still_exit_rotate(self, tmp_path, capsys):
        # No secrets provider: the credentials cannot be named, which is not safety.
        advisory = self._advisory(tmp_path)
        code = main(["scan", "--ioc", str(advisory), "--no-ci",
                     "--repo", str(tmp_path / "demo" / "api-server")])
        out = capsys.readouterr().out
        assert code == EXIT_ROTATE
        assert "could not be named" in out
        assert "rotate: nothing" not in out

    def test_clean_scan_says_nothing_to_rotate(self, tmp_path, capsys):
        advisory = self._advisory(tmp_path)
        code = main(["scan", "--ioc", str(advisory), "--no-ci",
                     "--repo", str(tmp_path / "demo" / "web-frontend")])
        assert code == EXIT_CLEAN
        assert "rotate: nothing" in capsys.readouterr().out

    def test_both_targets_is_rejected(self, tmp_path, capsys):
        advisory = self._advisory(tmp_path)
        code = main(["scan", "--ioc", str(advisory), "--org", "acme",
                     "--repo", str(tmp_path / "demo" / "api-server")])
        assert code == EXIT_BAD_INPUT
        assert "not both" in capsys.readouterr().err

    def test_missing_tool_is_bad_input_not_rotate(self, tmp_path, capsys, monkeypatch):
        advisory = self._advisory(tmp_path)
        monkeypatch.setenv("PATH", str(tmp_path / "empty"))  # no gh, no git
        code = main(["scan", "--ioc", str(advisory), "--org", "acme"])
        assert code in (EXIT_BAD_INPUT, EXIT_INCOMPLETE)
        assert code != EXIT_ROTATE

    def test_write_failure_is_not_a_verdict(self, tmp_path, capsys):
        advisory = self._advisory(tmp_path)
        code = main(["scan", "--ioc", str(advisory), "--no-ci", "--format", "json",
                     "--output", str(tmp_path / "nope" / "deep" / "r.json"),
                     "--repo", str(tmp_path / "demo" / "api-server")])
        assert code == EXIT_BAD_INPUT
        assert "could not write" in capsys.readouterr().err

    @pytest.mark.parametrize("fmt", ["text", "json", "html"])
    def test_output_works_for_every_format(self, tmp_path, fmt):
        advisory = self._advisory(tmp_path)
        target = tmp_path / f"report.{fmt}"
        main(["scan", "--ioc", str(advisory), "--no-ci", "--format", fmt,
              "--output", str(target), "--repo", str(tmp_path / "demo" / "api-server")])
        assert target.read_text(encoding="utf-8").strip()

    def test_report_does_not_blame_no_ci_when_it_was_not_given(self, tmp_path, capsys):
        advisory = self._advisory(tmp_path)
        main(["scan", "--ioc", str(advisory), "--format", "json",
              "--repo", str(tmp_path / "demo" / "api-server")])
        payload = json.loads(capsys.readouterr().out)
        evidence = " ".join(f for e in payload["timeline"] for f in e["evidence"])
        assert "--no-ci" not in evidence
        assert "no --slug" in evidence


class TestDemoSafety:
    def test_demo_refuses_to_delete_a_directory_it_did_not_create(self, tmp_path, capsys):
        (tmp_path / "api-server").mkdir()
        (tmp_path / "api-server" / "important.txt").write_text("mine")
        code = main(["demo", "--workdir", str(tmp_path)])
        assert code == EXIT_BAD_INPUT
        assert (tmp_path / "api-server" / "important.txt").read_text() == "mine"
        assert "not created by deptrail demo" in capsys.readouterr().err

    def test_demo_reuses_its_own_workdir(self, tmp_path, capsys):
        assert main(["demo", "--workdir", str(tmp_path / "demo")]) == EXIT_ROTATE
        capsys.readouterr()
        assert main(["demo", "--workdir", str(tmp_path / "demo")]) == EXIT_ROTATE

    def test_demo_ignores_the_users_git_config(self, tmp_path, capsys, monkeypatch):
        # A global config that would break or alter commits must not reach the demo.
        bad_config = tmp_path / "gitconfig"
        bad_config.write_text("[commit]\n\tgpgsign = true\n[user]\n\tname =\n")
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(bad_config))
        assert main(["demo", "--workdir", str(tmp_path / "demo")]) == EXIT_ROTATE


class TestOrgCacheSafety:
    """E10: a repository nobody looked at must never read as clean."""

    def _fake_gh(self, tmp_path, names, honor_limit=True):
        binhome = tmp_path / "bin"
        binhome.mkdir(exist_ok=True)
        listing = "\n".join(names)
        script = binhome / "gh"
        script.write_text(
            "#!/bin/bash\n"
            'if [ "$1" = "repo" ]; then\n'
            "  n=200; prev=\"\"; for a in \"$@\"; do [ \"$prev\" = \"--limit\" ] && n=\"$a\"; prev=\"$a\"; done\n"
            f'  printf "%s\\n" "{listing}" | head -n ' + ('"$n"' if honor_limit else "200") + "\n"
            "fi\nexit 0\n"
        )
        script.chmod(0o755)
        return binhome

    def _seed(self, cache: Path, org: str, name: str, remote: str | None = None):
        repo = cache / org / name
        repo.mkdir(parents=True)
        subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(repo), "remote", "add", "origin",
                        remote or f"https://github.com/{org}/{name}.git"],
                       check=True, capture_output=True)
        (repo / "README").write_text("x")
        for args in (["add", "-A"], ["commit", "-qm", "seed"]):
            subprocess.run(["git", "-C", str(repo), "-c", "user.email=a@b",
                            "-c", "user.name=a", *args], check=True, capture_output=True)
        return repo

    def _advisory(self, tmp_path):
        from deptrail.demo import advisory_path
        build(tmp_path / "demo")
        return advisory_path(tmp_path / "demo")

    def test_truncated_listing_cannot_report_clean(self, tmp_path, capsys, monkeypatch):
        advisory = self._advisory(tmp_path)
        binhome = self._fake_gh(tmp_path, [f"repo-{i}" for i in range(1, 6)])
        monkeypatch.setenv("PATH", f"{binhome}:{__import__('os').environ['PATH']}")
        cache = tmp_path / "cache"
        for i in (1, 2):
            self._seed(cache, "acme", f"repo-{i}")
        code = main(["scan", "--ioc", str(advisory), "--org", "acme", "--no-ci",
                     "--workdir", str(cache), "--limit", "2", "--format", "json"])
        payload = json.loads(capsys.readouterr().out)
        assert code == EXIT_INCOMPLETE
        assert payload["decision"]["scan_complete"] is False
        assert any("hit the --limit" in e for e in payload["errors"])

    def test_cache_belonging_to_another_org_is_refused(self, tmp_path, capsys, monkeypatch):
        advisory = self._advisory(tmp_path)
        binhome = self._fake_gh(tmp_path, ["api"])
        monkeypatch.setenv("PATH", f"{binhome}:{__import__('os').environ['PATH']}")
        cache = tmp_path / "cache"
        self._seed(cache, "acme", "api", remote="https://github.com/other/api.git")
        code = main(["scan", "--ioc", str(advisory), "--org", "acme", "--no-ci",
                     "--workdir", str(cache), "--format", "json"])
        payload = json.loads(capsys.readouterr().out)
        assert code in (EXIT_INCOMPLETE, EXIT_BAD_INPUT)
        assert any("points at" in e for e in payload["errors"])

    def test_failed_fetch_is_reported_not_ignored(self, tmp_path, capsys, monkeypatch):
        advisory = self._advisory(tmp_path)
        binhome = self._fake_gh(tmp_path, ["api"])
        monkeypatch.setenv("PATH", f"{binhome}:{__import__('os').environ['PATH']}")
        monkeypatch.setenv("GIT_TERMINAL_PROMPT", "0")
        cache = tmp_path / "cache"
        self._seed(cache, "acme", "api")  # remote does not exist, so fetch fails
        code = main(["scan", "--ioc", str(advisory), "--org", "acme", "--no-ci",
                     "--workdir", str(cache), "--format", "json"])
        payload = json.loads(capsys.readouterr().out)
        assert code == EXIT_INCOMPLETE
        assert any("fetch failed" in e for e in payload["errors"])


class TestReportEncoding:
    def test_non_ascii_report_is_written_as_utf8(self, tmp_path):
        from deptrail.demo import advisory_path
        build(tmp_path / "demo")
        advisory = advisory_path(tmp_path / "demo")
        target = tmp_path / "리포트.html"
        main(["scan", "--ioc", str(advisory), "--no-ci", "--format", "html",
              "--output", str(target), "--repo", str(tmp_path / "demo" / "api-server")])
        assert "→" in target.read_text(encoding="utf-8")

    def test_html_carries_the_advisory_window(self, tmp_path, capsys):
        main(["demo", "--workdir", str(tmp_path / "demo"), "--format", "html",
              "--output", str(tmp_path / "r.html")])
        html = (tmp_path / "r.html").read_text(encoding="utf-8")
        assert "installable window" in html and "2025-11-24" in html
        assert "coverage complete" in html


class TestShallowCheckout:
    """CI caught this: `actions/checkout` is shallow by default, and a shallow
    clone must never read as clean."""

    def test_shallow_clone_cannot_be_cleared(self, tmp_path, capsys):
        from deptrail.demo import advisory_path
        repos = dict(build(tmp_path / "demo"))
        advisory = advisory_path(tmp_path / "demo")
        shallow = tmp_path / "shallow"
        subprocess.run(["git", "clone", "-q", "--depth", "1",
                        f"file://{repos['web-frontend']}", str(shallow)],
                       check=True, capture_output=True)
        code = main(["scan", "--ioc", str(advisory), "--repo", str(shallow), "--no-ci"])
        out = capsys.readouterr().out
        # The same repository judged from full history exits 0 (see
        # test_clean_repo_exits_zero); truncated, it cannot be cleared.
        assert code == EXIT_ROTATE
        assert "shallow clone" in out and "cannot prove absence" in out
