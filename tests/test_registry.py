"""Tests for deriving window starts from the registry.

The fixture in `fixtures/packuments.json` is a real packument trimmed to the two
maps this module reads, so the timestamps and the withdrawn-version shape are the
registry's own rather than something convenient. `ansi-styles` is kept because it
carries two withdrawn versions, 6.2.2 from the September 2025 compromise and 2.2.0
from 2016 — withdrawn is not the same as malicious, and the fixture says so.
"""
import json
import socket
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import pytest

from deptrail.cli import main
from deptrail.registry import (
    RegistryError,
    fetch_packument,
    packument_url,
    publish_records,
    withdrawn_versions,
)

PACKUMENTS = json.loads((Path(__file__).parent / "fixtures" / "packuments.json").read_text())


def moment(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)


class TestTheScanPathNeverReachesTheNetwork:
    """The constraint this whole feature is built around (#10, #23 part 3).

    A verdict must not depend on a registry the incident may itself have taken down,
    and a window that differs between two runs of the same scan is not evidence.

    The first version of this class raised a marker from a patched socket and asserted
    the exit code was not 4. It could not fail: `scan_organization` wraps each repo in
    `except Exception` and files anything unrecognised into `report.errors`, which
    exits 2 — so adding a real `fetch_packument()` call to `history.scan_repo` left
    every test here green. A recorder cannot be swallowed that way, and the exit code
    is not what is being asserted.
    """

    @pytest.fixture
    def calls(self, monkeypatch):
        seen = []
        monkeypatch.setattr(urllib.request, "urlopen",
                            lambda request, timeout=None: seen.append(
                                getattr(request, "full_url", request)))
        monkeypatch.setattr(socket, "socket",
                            lambda *a, **k: seen.append("socket()"))
        return seen

    @pytest.mark.parametrize("argv", [
        ["demo"],
        ["scan", "--ioc", "example-demo", "--repo", "."],
        ["scan", "--ioc", "example-demo", "--repo", ".", "--slug", "o/r"],
        ["scan", "--ioc", "example-demo", "--repo", ".", "--format", "json"],
        ["scan", "--ioc", "example-demo", "--repo", ".", "--format", "html"],
        ["scan", "--ioc", "no-such-feed", "--repo", "."],
        ["advisory", "validate", "example-demo"],
        ["feeds"],
    ])
    def test_no_command_but_derive_makes_a_request(self, argv, calls, tmp_path):
        main(argv + (["--workdir", str(tmp_path / "d")] if argv[0] == "demo" else []))
        assert calls == []

    def test_that_check_would_notice_a_request_on_the_scan_path(self, calls, tmp_path,
                                                               monkeypatch):
        """The guard above is only worth having if it fails when the rule is broken.

        Stands in for the regression it exists to catch: a lookup added inside the
        history walk, which is where a future author would most plausibly put one.
        """
        import deptrail.org as org

        # `org` binds the name at import, so this is where the call actually happens.
        original = org.scan_repo

        def scan_repo(repo, query):
            from deptrail.registry import fetch_packument

            try:
                fetch_packument(query.package)
            except Exception:
                pass
            return original(repo, query)

        monkeypatch.setattr(org, "scan_repo", scan_repo)
        main(["demo", "--workdir", str(tmp_path / "d")])
        assert calls, "the recorder saw nothing while the scan path made a request"

    def test_a_scan_never_even_imports_urllib(self):
        """Checks the import graph rather than one call site.

        A call site can be added; this is the version of the invariant that notices.
        `registry` is imported inside `cmd_advisory_derive` for exactly this reason.
        """
        script = (
            "import sys\n"
            "from deptrail.cli import main\n"
            "main(['demo', '--workdir', sys.argv[1]])\n"
            "leaked = sorted(m for m in sys.modules\n"
            "                if m.startswith('urllib.request') or m == 'deptrail.registry')\n"
            "sys.exit('imported: ' + ', '.join(leaked) if leaked else 0)\n"
        )
        with tempfile.TemporaryDirectory() as workdir:
            result = subprocess.run([sys.executable, "-c", script, workdir],
                                    capture_output=True, text=True)
        assert result.returncode == 0, result.stderr.strip() or result.stdout.strip()

    def test_replacing_urlopen_alone_is_enough(self, monkeypatch):
        """Pins the call-time lookup of the opener.

        With it bound as a default argument this fails while everything else passes,
        because the other tests also patch `socket.socket` — a guard whose two halves
        cover for each other proves only that one of them works.
        """
        seen = []

        def opener(request, timeout=None):
            seen.append(request.full_url)
            raise AssertionError("urlopen was reached")

        monkeypatch.setattr(urllib.request, "urlopen", opener)
        with pytest.raises(AssertionError, match="urlopen was reached"):
            fetch_packument("chalk")
        assert seen == [packument_url("chalk")]


class TestPublishTimes:
    def test_the_time_entry_outlives_the_version(self):
        # The measured fact the derivation rests on: 5.6.1 is gone from `versions`
        # and still dated in `time`.
        packument = PACKUMENTS["chalk"]
        assert "5.6.1" not in packument["versions"]
        (record,) = publish_records(packument, "chalk", ("5.6.1",))
        assert record.published_at == moment("2025-09-08T13:13:05.239Z")
        assert record.still_served is False

    def test_a_version_still_served_is_marked_as_such(self):
        (record,) = publish_records(PACKUMENTS["chalk"], "chalk", ("5.6.2",))
        assert record.still_served is True

    def test_a_version_the_registry_never_published_stops_the_import(self):
        # Dropping it and carrying on would leave a malicious version out of the
        # advisory, and a missing version reads as CLEAN months later.
        with pytest.raises(RegistryError) as caught:
            publish_records(PACKUMENTS["chalk"], "chalk", ("5.6.1", "5.6.999"))
        assert "5.6.999" in str(caught.value)
        assert "never published" in str(caught.value)

    @pytest.mark.parametrize("packument,missing", [
        ({"versions": {}}, "time"),
        ({"time": {}}, "versions"),
    ])
    def test_a_packument_missing_a_map_is_refused(self, packument, missing):
        with pytest.raises(RegistryError) as caught:
            publish_records(packument, "chalk", ("5.6.1",))
        assert missing in str(caught.value)

    @pytest.mark.parametrize("stamp", ["not-a-date", "2025-09-08T13:13:05", 17, None])
    def test_an_unusable_publish_time_is_refused(self, stamp):
        packument = {"time": {"1.0.0": stamp}, "versions": {}}
        with pytest.raises(RegistryError):
            publish_records(packument, "chalk", ("1.0.0",))

    def test_withdrawn_is_not_the_same_as_malicious(self):
        # 2.2.0 was withdrawn in 2016 and has nothing to do with the 2025 incident,
        # which is why this list cross-checks a version list and never replaces it.
        assert withdrawn_versions(PACKUMENTS["ansi-styles"]) == ("2.2.0", "6.2.2")


class TestPackumentUrl:
    @pytest.mark.parametrize("name,expected", [
        ("chalk", "https://registry.npmjs.org/chalk"),
        ("@babel/core", "https://registry.npmjs.org/%40babel%2Fcore"),
    ])
    def test_a_scoped_name_is_escaped_whole(self, name, expected):
        # The slash belongs to the name, not to the path.
        assert packument_url(name) == expected


class TestFetchFailures:
    def _opener(self, error):
        def opener(request, timeout=None):
            raise error
        return opener

    def test_an_absent_package_says_so(self):
        error = urllib.error.HTTPError("u", 404, "Not Found", {}, None)
        with pytest.raises(RegistryError) as caught:
            fetch_packument("nope", opener=self._opener(error))
        assert "no such package" in str(caught.value)

    def test_a_missing_ca_bundle_is_not_reported_as_an_outage(self):
        # Python installed from python.org ships no CA bundle until its own
        # Install Certificates step is run, and "could not reach the registry" sends
        # the reader to look at a firewall that is fine.
        import ssl

        error = urllib.error.URLError(ssl.SSLCertVerificationError("bad cert"))
        with pytest.raises(RegistryError) as caught:
            fetch_packument("chalk", opener=self._opener(error))
        assert "CA bundle" in str(caught.value)
        assert "SSL_CERT_FILE" in str(caught.value)

    def test_a_response_that_is_not_json_is_refused(self):
        class Body:
            def read(self):
                return b"<html>maintenance</html>"

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        with pytest.raises(RegistryError) as caught:
            fetch_packument("chalk", opener=lambda *a, **k: Body())
        assert "could not be read as JSON" in str(caught.value)
