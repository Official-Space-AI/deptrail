"""Tests for taking a malicious version list from OSV instead of a keyboard.

The fixture records are trimmed copies of the live answers for the September 2025
compromise, so the ids, versions and aliases are OSV's own: chalk is MAL-2025-46969
with ["5.6.1"], debug MAL-2025-46974 with ["4.4.2"], ansi-styles MAL-2025-46967 with
["6.2.2"].
"""
import json
import socket
import subprocess
import sys
import tempfile
import urllib.request

import pytest

import deptrail.osv as osv
from deptrail.cli import EXIT_BAD_INPUT, EXIT_CLEAN, EXIT_TRANSIENT, main
from deptrail.fetch import FetchError
from deptrail.ioc import parse_advisory
from deptrail.osv import MALICIOUS_PREFIX, OsvError, malicious_releases

ANSWERS = {
    "chalk": {"vulns": [{
        "id": "MAL-2025-46969", "published": "2025-09-08T17:11:19Z",
        "aliases": ["GHSA-2v46-p5h4-248w"],
        "affected": [{"package": {"name": "chalk", "ecosystem": "npm"},
                      "versions": ["5.6.1"]}],
        "references": [{"url": "https://github.com/advisories/GHSA-2v46-p5h4-248w"}],
    }]},
    "debug": {"vulns": [{
        "id": "MAL-2025-46974", "published": "2025-09-08T17:11:19Z",
        "aliases": ["CVE-2025-59144"],
        "affected": [{"package": {"name": "debug", "ecosystem": "npm"},
                      "versions": ["4.4.2"]}],
        "references": [],
    }]},
    # Never compromised: OSV answers, with nothing malicious in it.
    "express": {"vulns": []},
}


def opener_for(answers):
    def opener(request, timeout=None):
        payload = json.loads(request.data.decode("utf-8"))
        name = payload["package"]["name"]

        class Body:
            def read1(self, size):
                return json.dumps(answers[name]).encode("utf-8") if not seen else b""

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        seen = []

        class Once(Body):
            def read1(self, size):
                if seen:
                    return b""
                seen.append(1)
                return json.dumps(answers[name]).encode("utf-8")

        return Once()
    return opener


class TestMaliciousReleases:
    def test_the_versions_come_from_the_record(self):
        (record,) = malicious_releases("chalk", opener=opener_for(ANSWERS))
        assert record.versions == ("5.6.1",)
        assert record.advisory_id == "MAL-2025-46969"
        assert record.aliases == ("GHSA-2v46-p5h4-248w",)
        assert record.source == "https://api.osv.dev/v1/vulns/MAL-2025-46969"

    def test_a_package_never_compromised_yields_nothing(self):
        # Not an error here: "OSV holds no malicious record" is a fact, and the caller
        # decides what it means. The command treats it as a stop.
        assert malicious_releases("express", opener=opener_for(ANSWERS)) == ()

    def test_only_malicious_records_are_read(self):
        # A CVE in a library that was never hijacked is a different tool's job, and
        # its affected range is not a list of malicious versions.
        answers = {"debug": {"vulns": [
            {"id": "CVE-2025-0001",
             "affected": [{"package": {"name": "debug", "ecosystem": "npm"},
                           "versions": ["1.0.0"]}]},
            ANSWERS["debug"]["vulns"][0],
        ]}}
        (record,) = malicious_releases("debug", opener=opener_for(answers))
        assert record.advisory_id.startswith(MALICIOUS_PREFIX)
        assert record.versions == ("4.4.2",)

    def test_another_packages_versions_are_not_borrowed(self):
        # One record can carry several `affected` entries.
        answers = {"chalk": {"vulns": [{
            "id": "MAL-2025-1", "affected": [
                {"package": {"name": "chalk", "ecosystem": "npm"}, "versions": ["5.6.1"]},
                {"package": {"name": "debug", "ecosystem": "npm"}, "versions": ["4.4.2"]},
            ]}]}}
        (record,) = malicious_releases("chalk", opener=opener_for(answers))
        assert record.versions == ("5.6.1",)

    def test_a_malicious_record_naming_no_version_stops_the_import(self):
        # Skipping it would drop the package from the advisory without saying so.
        answers = {"chalk": {"vulns": [{"id": "MAL-2025-2", "affected": []}]}}
        with pytest.raises(OsvError, match="names no affected version at all"):
            malicious_releases("chalk", opener=opener_for(answers))

    def test_a_whole_package_record_says_so_rather_than_the_opposite(self):
        """OSV writes "every version is malicious" as a range introduced at 0.

        Five of roughly forty consecutive MAL- records sampled from 2025-09 are this
        shape — it is how a typosquat is recorded. The refusal is right, because this
        schema matches by exact version; the earlier message was not, because it told
        the operator the record named *no* version and sent them to read one that
        names every one.
        """
        answers = {"arjvg": {"vulns": [{
            "id": "MAL-2025-47013",
            "affected": [{"package": {"name": "arjvg", "ecosystem": "npm"},
                          "ranges": [{"type": "SEMVER",
                                      "events": [{"introduced": "0"}]}]}],
        }]}}
        with pytest.raises(OsvError) as caught:
            malicious_releases("arjvg", opener=opener_for(answers))
        message = str(caught.value)
        assert "every version of this package is malicious" in message
        assert "names no affected version" not in message
        # The operator's next move, which differs from the other shape's.
        assert "registry.npmjs.org/arjvg" in message and "#68" in message

    def test_another_packages_range_does_not_make_this_one_whole_package(self):
        # One record can carry several `affected` entries. Reading the neighbour's
        # range would tell the operator every version of *this* package is malicious.
        answers = {"chalk": {"vulns": [{
            "id": "MAL-2025-4",
            "affected": [
                {"package": {"name": "chalk", "ecosystem": "npm"}},
                {"package": {"name": "arjvg", "ecosystem": "npm"},
                 "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]},
            ],
        }]}}
        with pytest.raises(OsvError, match="names no affected version at all"):
            malicious_releases("chalk", opener=opener_for(answers))

    def test_a_range_that_is_not_introduced_at_zero_is_the_other_shape(self):
        # A fixed range names a boundary, not the whole package, and this schema
        # cannot carry either — but the advice must not claim the wrong one.
        answers = {"chalk": {"vulns": [{
            "id": "MAL-2025-3",
            "affected": [{"package": {"name": "chalk", "ecosystem": "npm"},
                          "ranges": [{"type": "SEMVER",
                                      "events": [{"introduced": "5.0.0"}]}]}],
        }]}}
        with pytest.raises(OsvError, match="names no affected version at all"):
            malicious_releases("chalk", opener=opener_for(answers))

    @pytest.mark.parametrize("answer", [
        "not-an-object", {"vulns": "not-a-list"}, {"vulns": ["not-an-object"]},
    ])
    def test_an_answer_of_the_wrong_shape_is_refused(self, answer):
        with pytest.raises(OsvError):
            malicious_releases("chalk", opener=opener_for({"chalk": answer}))

    def test_a_failure_names_osv_rather_than_the_registry(self):
        """The transport is shared, so its messages take the source from here.

        Carried over from when it served only npm, an OSV outage told the responder
        the registry was at fault and offered them a packument size budget.
        """
        import deptrail.fetch as fetch

        class Big:
            def read1(self, size):
                return b"x" * 64

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        original = fetch.MAX_BYTES
        fetch.MAX_BYTES = 4
        try:
            with pytest.raises(OsvError, match="OSV sent more than"):
                malicious_releases("chalk", opener=lambda *a, **k: Big())
        finally:
            fetch.MAX_BYTES = original

    def test_the_status_survives_the_re_raise(self):
        def gone(request, timeout=None):
            raise urllib.error.HTTPError("u", 503, "Service Unavailable", {}, None)

        with pytest.raises(OsvError) as caught:
            malicious_releases("chalk", opener=gone)
        assert caught.value.status == 503

    def test_a_transport_failure_arrives_as_an_osv_error(self):
        def broken(request, timeout=None):
            raise urllib.error.URLError("no route")

        with pytest.raises(OsvError):
            malicious_releases("chalk", opener=broken)


class TestTheScanPathStillReachesNothing:
    """Two new modules, so the invariant needs re-proving rather than assuming."""

    def test_a_scan_imports_neither_osv_nor_the_transport(self):
        script = (
            "import sys\n"
            "from deptrail.cli import main\n"
            "main(['demo', '--workdir', sys.argv[1]])\n"
            "leaked = sorted(m for m in sys.modules if m in "
            "{'deptrail.osv', 'deptrail.fetch', 'deptrail.registry', 'deptrail.pnpmkeys', 'deptrail.pnpmlock'} "
            "or m.startswith('urllib.request'))\n"
            "sys.exit('imported: ' + ', '.join(leaked) if leaked else 0)\n"
        )
        with tempfile.TemporaryDirectory() as workdir:
            result = subprocess.run([sys.executable, "-c", script, workdir],
                                    capture_output=True, text=True)
        assert result.returncode == 0, result.stderr.strip() or result.stdout.strip()

    def test_no_scan_invocation_opens_a_socket(self, monkeypatch, tmp_path):
        calls = []
        monkeypatch.setattr(urllib.request, "urlopen",
                            lambda *a, **k: calls.append("urlopen"))
        monkeypatch.setattr(socket, "socket", lambda *a, **k: calls.append("socket"))
        main(["scan", "--ioc", "example-demo", "--repo", "."])
        main(["demo", "--workdir", str(tmp_path / "d")])
        assert calls == []


class TestDeriveFromOsv:
    def registry(self, monkeypatch):
        packuments = json.loads(
            (__import__("pathlib").Path(__file__).parent / "fixtures"
             / "packuments.json").read_text())

        def fetch(name, **kwargs):
            return packuments[name]

        monkeypatch.setattr("deptrail.registry.fetch_packument", fetch)

    def osv(self, monkeypatch, answers=None):
        answers = answers or ANSWERS
        monkeypatch.setattr(
            "deptrail.osv.malicious_releases",
            lambda name, **kwargs: malicious_releases(name, opener=opener_for(answers)))

    def test_the_version_list_is_never_typed(self, tmp_path, monkeypatch):
        self.registry(monkeypatch)
        self.osv(monkeypatch)
        out = tmp_path / "incident.json"
        code = main(["advisory", "derive", "--osv-package", "chalk",
                     "--id", "GHSA-x", "--name", "September 2025",
                     "--source", "https://example.test/writeup", "--output", str(out)])
        assert code == EXIT_CLEAN
        advisory = parse_advisory(out.read_text())
        assert advisory.packages[0].versions == ("5.6.1",)

    def test_the_record_is_cited_alongside_the_writeup(self, tmp_path, monkeypatch):
        self.registry(monkeypatch)
        self.osv(monkeypatch)
        out = tmp_path / "incident.json"
        main(["advisory", "derive", "--osv-package", "chalk", "--id", "GHSA-x",
              "--name", "n", "--source", "https://example.test/writeup",
              "--output", str(out)])
        sources = parse_advisory(out.read_text()).sources
        assert "https://example.test/writeup" in sources
        assert "https://api.osv.dev/v1/vulns/MAL-2025-46969" in sources

    def test_a_name_osv_holds_nothing_for_stops_the_import(self, tmp_path, monkeypatch):
        # "Silently contributed nothing" and "confirmed clean" are indistinguishable
        # in the output, which is the whole hazard.
        self.registry(monkeypatch)
        self.osv(monkeypatch)
        code = main(["advisory", "derive", "--osv-package", "express", "--id", "GHSA-x",
                     "--name", "n", "--source", "https://example.test/w"])
        assert code == EXIT_TRANSIENT

    def test_two_records_for_one_package_is_the_operators_call(self, tmp_path, monkeypatch):
        self.registry(monkeypatch)
        twice = {"chalk": {"vulns": [
            {"id": "MAL-2020-1", "affected": [
                {"package": {"name": "chalk", "ecosystem": "npm"},
                 "versions": ["5.6.0"]}]},
            ANSWERS["chalk"]["vulns"][0],
        ]}}
        self.osv(monkeypatch, twice)
        code = main(["advisory", "derive", "--osv-package", "chalk", "--id", "GHSA-x",
                     "--name", "n", "--source", "https://example.test/w"])
        assert code == EXIT_TRANSIENT

    def test_hand_named_versions_merge_with_osv_ones(self, tmp_path, monkeypatch):
        # An incident can have one package OSV has not caught up with.
        self.registry(monkeypatch)
        self.osv(monkeypatch)
        out = tmp_path / "incident.json"
        code = main(["advisory", "derive", "--osv-package", "chalk",
                     "--package", "ansi-styles@6.2.2", "--id", "GHSA-x", "--name", "n",
                     "--source", "https://example.test/w", "--output", str(out)])
        assert code == EXIT_CLEAN
        names = {p.name for p in parse_advisory(out.read_text()).packages}
        assert names == {"chalk", "ansi-styles"}

    def test_no_packages_from_either_source_is_the_callers_error(self, monkeypatch):
        self.registry(monkeypatch)
        code = main(["advisory", "derive", "--id", "GHSA-x", "--name", "n",
                     "--source", "https://example.test/w"])
        assert code == EXIT_BAD_INPUT
