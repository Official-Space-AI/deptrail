"""Tests for the command line, the demo, and the HTML report.

The demo is the path an evaluator takes first, so it is asserted on its output
and on its exit code — a scan that finds credentials to rotate must say so in a
way a script can act on, without anyone reading prose.
"""
import json
import os
import subprocess
from pathlib import Path

import pytest

from deptrail.cli import (
    EXIT_BAD_INPUT,
    EXIT_CLEAN,
    EXIT_INCOMPLETE,
    EXIT_ROTATE,
    EXIT_TRANSIENT,
    main,
)
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

    def test_demo_shows_the_repository_it_could_not_read(self, tmp_path, capsys):
        # mobile-app is locked with Yarn: neither cleared nor rotated, and named.
        main(["demo", "--workdir", str(tmp_path / "demo")])
        out = capsys.readouterr().out
        assert "not judged" in out and "mobile-app" in out
        assert "cannot prove absence" in out
        assert "EXPO_TOKEN" not in out, "an unread tree must not raise a credential"

    def test_demo_is_reproducible(self, tmp_path, capsys):
        main(["demo", "--workdir", str(tmp_path / "a")])
        first = capsys.readouterr().out
        main(["demo", "--workdir", str(tmp_path / "b")])
        second = capsys.readouterr().out
        assert _without_shas(first) == _without_shas(second)

    def test_demo_json_is_machine_readable(self, tmp_path, capsys):
        main(["demo", "--workdir", str(tmp_path / "demo"), "--format", "json"])
        payload = json.loads(capsys.readouterr().out)
        # The decision comes first: a consumer must not have to infer it. The demo
        # includes a Yarn repository, so the scan is deliberately not complete —
        # one credential list plus one honest gap is what a real incident looks like.
        assert payload["decision"] == {
            "exit_code": EXIT_ROTATE, "rotation_required": True,
            "scan_complete": False, "worst_grade": "CONFIRMED",
        }
        assert payload["not_judged"] == [
            "mobile-app: yarn.lock: Yarn lockfiles are not parsed yet, so the versions "
            "this tree installed were not judged"
        ]
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

    def test_missing_tool_is_transient_not_rotate_and_not_the_callers_fault(
            self, tmp_path, capsys, monkeypatch):
        # An absent git or gh is an environment that cannot answer. Exit 1 would read
        # as "rotate these credentials", 3 would blame the arguments, and 2 would say
        # the history was looked at.
        advisory = self._advisory(tmp_path)
        monkeypatch.setenv("PATH", str(tmp_path / "empty"))  # no gh, no git
        code = main(["scan", "--ioc", str(advisory), "--org", "acme"])
        assert code == EXIT_TRANSIENT
        assert code not in (EXIT_ROTATE, EXIT_CLEAN)

    def test_a_failed_tool_is_transient_on_the_repo_path_too(self, tmp_path, capsys,
                                                             monkeypatch):
        # The `--org` path raises before the scan, so it was already 4. The `--repo`
        # path — the one action.yml itself runs — absorbed the failure into the report
        # and left as 2, which the Action then passes off as a warning.
        advisory = self._advisory(tmp_path)
        monkeypatch.setenv("PATH", str(tmp_path / "empty"))  # no gh
        code = main(["scan", "--ioc", str(advisory), "--format", "json",
                     "--repo", str(tmp_path / "demo" / "web-frontend"),
                     "--slug", "acme/web-frontend"])
        payload = json.loads(capsys.readouterr().out)
        assert code == EXIT_TRANSIENT
        assert payload["could_not_run"], payload
        assert payload["decision"]["scan_complete"] is False

    def test_a_failed_call_is_transient_not_incomplete(self, tmp_path, capsys,
                                                       monkeypatch):
        # A `gh` that exists and fails is the other half of the contract: 2 says the
        # history was looked at and cannot be cleared, 4 says the call did not happen.
        advisory = self._advisory(tmp_path)
        binhome = tmp_path / "failing"
        binhome.mkdir()
        (binhome / "gh").write_text("#!/bin/sh\necho 'gh: API rate limit' >&2\nexit 1\n")
        (binhome / "gh").chmod(0o755)
        real = __import__("os").environ["PATH"]
        monkeypatch.setenv("PATH", f"{binhome}:{real}")
        code = main(["scan", "--ioc", str(advisory), "--format", "json",
                     "--repo", str(tmp_path / "demo" / "web-frontend"),
                     "--slug", "acme/web-frontend"])
        payload = json.loads(capsys.readouterr().out)
        assert code == EXIT_TRANSIENT
        assert any("CI runs unavailable" in t for t in payload["could_not_run"]), payload

    def test_an_unwritable_workdir_is_transient_not_a_traceback(self, tmp_path, capsys):
        # Letting an OSError escape means the interpreter exits 1, which this contract
        # reads as "rotate these credentials".
        advisory = self._advisory(tmp_path)
        blocker = tmp_path / "not-a-dir"
        blocker.write_text("i am a file")
        code = main(["scan", "--ioc", str(advisory), "--org", "acme",
                     "--workdir", str(blocker)])
        assert code == EXIT_TRANSIENT
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
        assert code != EXIT_CLEAN
        assert payload["decision"]["scan_complete"] is False
        # The truncation is the caller's to fix, so it stays an error rather than
        # something to retry. (This fixture's cached clones also cannot be refreshed,
        # which is what decides the exact non-zero code here.)
        assert any("hit the --limit" in e for e in payload["errors"])
        assert not any("hit the --limit" in t for t in payload["could_not_run"])

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
        # A fetch that failed is the tooling not answering, not a history that says
        # nothing: retrying may help, so it is 4 rather than 2.
        assert code == EXIT_TRANSIENT
        assert any("fetch failed" in t for t in payload["could_not_run"])


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


class TestUnreadableLockfileDialects:
    """#16: found by pointing the tool at repositories shaped unlike its fixtures.

    All three exited 0 with `rotate: nothing` before the fix, including the two
    that pinned the malicious version inside the window.
    """

    def _repo(self, tmp_path, name, files):
        """A one-commit repo dated inside the demo advisory's window."""
        repo = tmp_path / name
        repo.mkdir(parents=True)
        env = dict(os.environ)
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = "2025-11-25T12:00:00+00:00"

        def git(*args):
            subprocess.run(
                ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t",
                 *args], check=True, capture_output=True, env=env,
            )

        git("init", "-q")
        for path, body in files.items():
            target = repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(body)
        git("add", "-A")
        git("commit", "-qm", "init")
        return repo

    def _advisory(self, tmp_path):
        from deptrail.demo import advisory_path
        build(tmp_path / "demo")
        return advisory_path(tmp_path / "demo")

    def test_yarn_repository_cannot_be_cleared(self, tmp_path, capsys):
        advisory = self._advisory(tmp_path)
        repo = self._repo(tmp_path, "yarnapp", {
            "yarn.lock": '"chalk@^5.6.0":\n  version "5.6.1"\n',
            "package.json": '{"name":"app","dependencies":{"chalk":"^5.6.0"}}',
        })
        code = main(["scan", "--ioc", str(advisory), "--repo", str(repo), "--no-ci"])
        out = capsys.readouterr().out
        assert code == EXIT_INCOMPLETE
        assert "not judged" in out and "yarn.lock" in out
        assert "cannot prove absence" in out

    def test_shrinkwrap_repository_is_scanned_like_a_lockfile(self, tmp_path, capsys):
        advisory = self._advisory(tmp_path)
        repo = self._repo(tmp_path, "shrinkwrapped", {
            "npm-shrinkwrap.json": json.dumps({
                "name": "app", "lockfileVersion": 3,
                "packages": {"": {"dependencies": {"chalk": "^5.6.0"}},
                             "node_modules/chalk": {"version": "5.6.1"}},
            }),
        })
        code = main(["scan", "--ioc", str(advisory), "--repo", str(repo), "--no-ci"])
        out = capsys.readouterr().out
        assert code == EXIT_ROTATE
        assert "npm-shrinkwrap.json" in out
        assert "not judged" not in out

    def test_deno_lockfile_is_recognised(self, tmp_path, capsys):
        # Deno installs from the npm registry through npm: specifiers, so a name
        # missing from the table is a repository this tool would call clean.
        advisory = self._advisory(tmp_path)
        repo = self._repo(tmp_path, "denoapp", {"deno.lock": '{"version":"4"}'})
        code = main(["scan", "--ioc", str(advisory), "--repo", str(repo), "--no-ci"])
        assert code == EXIT_INCOMPLETE
        assert "deno.lock" in capsys.readouterr().out

    def test_an_incomplete_scan_is_not_painted_green(self, tmp_path):
        # The banner colour is read before the sentence next to it, so green must
        # mean a proven all-clear and nothing else.
        from deptrail.report import GRADE_COLOR
        from deptrail.grading import Grade
        advisory = self._advisory(tmp_path)
        repo = self._repo(tmp_path, "yarnapp2", {
            "yarn.lock": '"chalk@^5.6.0":\n  version "5.6.1"\n',
        })
        target = tmp_path / "r.html"
        main(["scan", "--ioc", str(advisory), "--repo", str(repo), "--no-ci",
              "--format", "html", "--output", str(target)])
        html = target.read_text(encoding="utf-8")
        banner = next(line for line in html.splitlines() if "class='banner'" in line)
        assert "cannot prove absence" in banner
        assert GRADE_COLOR[Grade.NO_EVIDENCE] not in banner, \
            "an incomplete scan must not wear the all-clear colour"

    def test_repository_with_nothing_to_read_is_genuinely_clean(self, tmp_path, capsys):
        advisory = self._advisory(tmp_path)
        repo = self._repo(tmp_path, "pythonapp", {"main.py": "print(1)\n"})
        code = main(["scan", "--ioc", str(advisory), "--repo", str(repo), "--no-ci"])
        out = capsys.readouterr().out
        assert code == EXIT_CLEAN
        # The distinction the old output could not make: this one really is clear.
        assert "not judged" not in out
        assert "cannot prove absence" not in out


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
        # The same repository judged from full history exits 0; truncated, it cannot be
        # cleared — and "could not prove absence" is what that is, not "rotate" (#20).
        assert code == EXIT_INCOMPLETE
        assert "shallow clone" in out and "cannot prove absence" in out
        assert "rotate: nothing" in out

    def test_deepening_a_clone_never_lowers_the_reported_risk(self, tmp_path, capsys):
        # The property this contract exists to remove: the truncated clone must not
        # look more urgent than the complete one it came from.
        from deptrail.demo import advisory_path
        repos = dict(build(tmp_path / "demo"))
        advisory = advisory_path(tmp_path / "demo")
        shallow = tmp_path / "shallow"
        subprocess.run(["git", "clone", "-q", "--depth", "1",
                        f"file://{repos['web-frontend']}", str(shallow)],
                       check=True, capture_output=True)
        truncated = main(["scan", "--ioc", str(advisory), "--repo", str(shallow),
                          "--no-ci"])
        capsys.readouterr()
        complete = main(["scan", "--ioc", str(advisory),
                         "--repo", str(repos["web-frontend"]), "--no-ci"])
        capsys.readouterr()
        assert (complete, truncated) == (EXIT_CLEAN, EXIT_INCOMPLETE)

    def test_an_incomplete_clone_can_be_accepted_on_purpose(self, tmp_path, capsys):
        # Off by default, mirroring OSV-Scanner's --allow-no-lockfiles: the caller may
        # take responsibility for the gap, and the report still names it.
        from deptrail.demo import advisory_path
        repos = dict(build(tmp_path / "demo"))
        advisory = advisory_path(tmp_path / "demo")
        shallow = tmp_path / "shallow"
        subprocess.run(["git", "clone", "-q", "--depth", "1",
                        f"file://{repos['web-frontend']}", str(shallow)],
                       check=True, capture_output=True)
        code = main(["scan", "--ioc", str(advisory), "--repo", str(shallow), "--no-ci",
                     "--allow-incomplete-history"])
        out = capsys.readouterr().out
        assert code == EXIT_CLEAN
        assert "shallow clone" in out, "the gap is accepted, not hidden"
        assert "allow-incomplete-history" in out


class TestAdvisoryAuthoring:
    """#29: hand-authoring the advisory was the first thing that stopped a new user, and
    it stopped them before the tool had done anything at all."""

    def test_a_fully_specified_init_is_valid_immediately(self, tmp_path, capsys):
        target = tmp_path / "incident.json"
        code = main(["advisory", "init", "--id", "GHSA-test-0001",
                     "--name", "chalk compromised",
                     "--package", "chalk", "--version", "5.6.1",
                     "--start", "2025-11-24T00:00:00+00:00",
                     "--end", "2025-11-26T23:59:59+00:00",
                     "--source", "https://example.test/advisory",
                     "--output", str(target)])
        assert code == EXIT_CLEAN
        assert "complete and valid" in capsys.readouterr().err
        assert main(["advisory", "validate", str(target)]) == EXIT_CLEAN

    def test_a_blank_template_does_not_validate(self, tmp_path, capsys):
        # A template that passed while still full of placeholders would be worse than no
        # template: the strict loader exists so a half-filled advisory cannot produce a
        # confident CLEAN.
        code = main(["advisory", "init"])
        out, err = capsys.readouterr()
        assert code == EXIT_CLEAN, "emitting a template is not a failure"
        assert "REPLACE-ME" in out
        assert "still to fill in" in err
        template = tmp_path / "blank.json"
        template.write_text(out)
        assert main(["advisory", "validate", str(template)]) == EXIT_BAD_INPUT

    def test_the_template_says_what_the_window_means(self, capsys):
        # Getting this backwards makes every scan return CLEAN, so it is written into the
        # file rather than left in the documentation.
        main(["advisory", "init"])
        out = capsys.readouterr().out
        assert "INSTALLABLE" in out
        assert "not the interval the attacker was active" in out

    def test_init_without_a_source_refuses_to_look_complete(self, tmp_path, capsys):
        # Provenance is not optional: a verdict is only as good as its advisory.
        code = main(["advisory", "init", "--id", "GHSA-test-0001",
                     "--name", "chalk compromised",
                     "--package", "chalk", "--version", "5.6.1",
                     "--start", "2025-11-24T00:00:00+00:00",
                     "--end", "2025-11-26T23:59:59+00:00"])
        out, err = capsys.readouterr()
        assert code == EXIT_CLEAN
        assert "still to fill in" in err
        assert "sources" in err

    def test_validate_explains_a_broken_advisory_and_names_the_docs(self, tmp_path, capsys):
        broken = tmp_path / "bad.json"
        broken.write_text('{"schema_version": 1, "id": "X", "summary": "oops"}')
        code = main(["advisory", "validate", str(broken)])
        err = capsys.readouterr().err
        assert code == EXIT_BAD_INPUT
        assert "unknown field(s) ['summary']" in err
        assert "docs/ioc-format.md" in err

    def test_validate_accepts_a_bundled_feed_by_name(self, capsys):
        assert main(["advisory", "validate", "example-demo"]) == EXIT_CLEAN
        out = capsys.readouterr().out
        assert "window" in out and "coverage" in out

    def test_validate_says_a_partial_feed_cannot_prove_absence(self, tmp_path, capsys):
        target = tmp_path / "partial.json"
        main(["advisory", "init", "--id", "GHSA-test-0002", "--name", "partial feed",
              "--package", "chalk", "--version", "5.6.1",
              "--start", "2025-11-24T00:00:00+00:00",
              "--end", "2025-11-26T23:59:59+00:00",
              "--source", "https://example.test/a", "--output", str(target)])
        capsys.readouterr()
        main(["advisory", "validate", str(target)])
        assert "absence of exposure will not be provable" in capsys.readouterr().out

    def test_a_rejected_advisory_tells_a_scan_user_where_to_look(self, tmp_path, capsys):
        broken = tmp_path / "bad.json"
        broken.write_text('{"nope": true}')
        code = main(["scan", "--ioc", str(broken), "--repo", ".", "--no-ci"])
        err = capsys.readouterr().err
        assert code == EXIT_BAD_INPUT
        assert "advisory validate" in err and "docs/ioc-format.md" in err

    def test_bare_advisory_prints_help_rather_than_a_traceback(self, capsys):
        assert main(["advisory"]) == EXIT_BAD_INPUT

    def test_a_placeholder_identity_is_not_an_identity(self, tmp_path, capsys):
        # Everything real except id and name: this validated and printed
        # "REPLACE-ME — REPLACE-ME" at exit 0, so the loader now knows the marker.
        main(["advisory", "init"])
        skeleton = json.loads(capsys.readouterr().out)
        skeleton["packages"][0].update(
            {"name": "chalk", "versions": ["5.6.1"],
             "sources": ["https://example.test/a"]})
        skeleton["sources"] = ["https://example.test/a"]
        skeleton["window"] = {"start": "2025-11-24T00:00:00+00:00",
                             "end": "2025-11-26T23:59:59+00:00"}
        half = tmp_path / "half.json"
        half.write_text(json.dumps(skeleton))
        assert main(["advisory", "validate", str(half)]) == EXIT_BAD_INPUT
        assert "REPLACE-ME" in capsys.readouterr().err

    def test_the_identity_is_never_derived_from_the_package(self, capsys):
        # There has been more than one chalk incident. Two of them must not be indexable
        # as the same advisory, because the report keys its verdict on this field.
        main(["advisory", "init", "--package", "chalk", "--version", "5.6.1"])
        first = json.loads(capsys.readouterr().out)
        main(["advisory", "init", "--package", "chalk", "--version", "5.6.3"])
        second = json.loads(capsys.readouterr().out)
        assert "REPLACE-ME" in first["id"], "an identity must be supplied, not invented"
        assert first["id"] == second["id"], "both are unfilled, and both say so"
        main(["advisory", "init", "--id", "GHSA-a", "--package", "chalk"])
        a = json.loads(capsys.readouterr().out)
        main(["advisory", "init", "--id", "GHSA-b", "--package", "chalk"])
        b = json.loads(capsys.readouterr().out)
        assert (a["id"], b["id"]) == ("GHSA-a", "GHSA-b")

    def test_every_version_given_is_kept(self, capsys):
        main(["advisory", "init", "--package", "chalk",
              "--version", "5.6.1", "--version", "5.6.2", "--version", "5.6.3"])
        written = json.loads(capsys.readouterr().out)
        assert written["packages"][0]["versions"] == ["5.6.1", "5.6.2", "5.6.3"]

    @pytest.mark.parametrize("path,expected", [
        ("nope/deep/a.json", EXIT_BAD_INPUT),   # the parent does not exist
        (".", EXIT_BAD_INPUT),                  # the target is a directory
    ])
    def test_a_path_that_cannot_work_is_the_callers_to_fix(self, tmp_path, path, expected):
        # Retrying cannot make either of these succeed, so they are not the retryable
        # code. That distinction is the whole point of having both (#20).
        target = tmp_path / path if path != "." else tmp_path
        assert main(["advisory", "init", "--output", str(target)]) == expected

    def test_the_docs_pointer_is_reachable_from_an_installed_copy(self, tmp_path, capsys):
        # An installed wheel has no `docs/` directory, so a repo-relative path is a dead
        # end for exactly the people who need it.
        from deptrail.cli import FORMAT_DOCS
        assert FORMAT_DOCS.startswith("https://")
        broken = tmp_path / "bad.json"
        broken.write_text("{}")
        main(["advisory", "validate", str(broken)])
        assert FORMAT_DOCS in capsys.readouterr().err

    def test_a_partial_advisory_from_init_really_cannot_prove_absence(self, tmp_path,
                                                                     capsys):
        # The generated default is `coverage: partial`, and this asserts what that costs
        # a real scan rather than trusting the field to mean something.
        advisory = tmp_path / "partial.json"
        main(["advisory", "init", "--id", "GHSA-p", "--name", "partial",
              "--package", "chalk", "--version", "5.6.1",
              "--start", "2025-11-24T00:00:00+00:00",
              "--end", "2025-11-26T23:59:59+00:00",
              "--source", "https://example.test/a", "--output", str(advisory)])
        capsys.readouterr()
        repo = tmp_path / "clean"
        repo.mkdir()
        subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True,
                       capture_output=True)
        (repo / "README.md").write_text("nothing to see")
        subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t",
                        "-c", "user.name=t", "add", "-A"], check=True,
                       capture_output=True)
        subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t",
                        "-c", "user.name=t", "commit", "-qm", "init"], check=True,
                       capture_output=True)
        code = main(["scan", "--ioc", str(advisory), "--repo", str(repo), "--no-ci",
                     "--format", "json"])
        payload = json.loads(capsys.readouterr().out)
        assert code == EXIT_INCOMPLETE
        assert payload["decision"]["scan_complete"] is False
        assert any("partial coverage" in c for c in payload["caveats"]), payload
