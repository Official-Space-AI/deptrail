"""Tests for deriving window starts from the registry.

The fixture in `fixtures/packuments.json` is a real packument trimmed to the two
maps this module reads, so the timestamps and the withdrawn-version shape are the
registry's own rather than something convenient. `ansi-styles` is kept because it
carries two withdrawn versions, 6.2.2 from the September 2025 compromise and 2.2.0
from 2016 — withdrawn is not the same as malicious, and the fixture says so.
"""
import json
import socket
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import pytest

from deptrail.cli import EXIT_BAD_INPUT, EXIT_CLEAN, EXIT_TRANSIENT, main
from deptrail.ioc import parse_advisory
from deptrail.registry import (
    PublishRecord,
    RegistryError,
    advisory_from_records,
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

    A verdict must not depend on a registry the incident may itself have taken
    down, and a window that differs between two runs of the same scan is not
    evidence. Before this module there was no `urllib` anywhere in `src/`, so the
    property held by accident; this is what keeps it.
    """

    def test_a_full_scan_completes_with_every_socket_dead(self, tmp_path, monkeypatch):
        def no_sockets(*args, **kwargs):
            raise AssertionError("the scan path opened a socket")

        monkeypatch.setattr(socket, "socket", no_sockets)
        monkeypatch.setattr(urllib.request, "urlopen", no_sockets)
        # The demo is the whole judgment flow on the production code path: advisory
        # load, history walk, grading, rotation, rendering.
        assert main(["demo", "--workdir", str(tmp_path / "demo")]) != EXIT_TRANSIENT

    def test_the_guard_above_has_teeth(self, monkeypatch):
        """The scan test only means something if these patches really stop a request.

        A guard that cannot fail is not a guard, and this one nearly could not: the
        opener used to be a default argument, captured at import, so replacing
        `urllib.request.urlopen` did not reach it.
        """
        def no_sockets(*args, **kwargs):
            raise AssertionError("the scan path opened a socket")

        monkeypatch.setattr(socket, "socket", no_sockets)
        monkeypatch.setattr(urllib.request, "urlopen", no_sockets)
        with pytest.raises(AssertionError, match="opened a socket"):
            fetch_packument("chalk")

    def test_replacing_urlopen_alone_is_enough(self, monkeypatch):
        """Pins the call-time lookup, which the socket patch would otherwise hide.

        With the opener bound as a default argument this test fails while every
        other one still passes, because they also patch `socket.socket` — a guard
        whose two halves cover for each other proves only that one of them works.
        """
        seen = []

        def opener(request, timeout=None):
            seen.append(request.full_url)
            raise AssertionError("urlopen was reached")

        monkeypatch.setattr(urllib.request, "urlopen", opener)
        with pytest.raises(AssertionError, match="urlopen was reached"):
            fetch_packument("chalk")
        assert seen == [packument_url("chalk")]

    def test_the_socket_patch_alone_stops_a_real_request(self, monkeypatch):
        # urllib reaches the network through socket.create_connection, which looks
        # `socket.socket` up on the module — so patching it covers any future caller,
        # not only one that goes through this module's injectable opener.
        def no_sockets(*args, **kwargs):
            raise AssertionError("the scan path opened a socket")

        monkeypatch.setattr(socket, "socket", no_sockets)
        # It stops the request below urllib, so the marker escapes rather than being
        # wrapped — which is the point: nothing on the way down can swallow it.
        with pytest.raises(AssertionError, match="opened a socket"):
            fetch_packument("chalk")


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
        assert "not JSON" in str(caught.value)


class TestAssembly:
    def records(self):
        return (
            PublishRecord("ansi-styles", "6.2.2", moment("2025-09-08T13:12:10.343Z"), False),
            PublishRecord("debug", "4.4.2", moment("2025-09-08T13:12:39.973Z"), False),
            PublishRecord("chalk", "5.6.1", moment("2025-09-08T13:13:05.239Z"), False),
        )

    def build(self, records=None):
        return advisory_from_records(
            records or self.records(), identifier="GHSA-x", name="September 2025",
            sources=("https://example.test/advisory",),
        )

    def test_the_result_survives_the_strict_loader(self):
        advisory = parse_advisory(json.dumps(self.build()))
        assert advisory.id == "GHSA-x"
        assert len(advisory.packages) == 3

    def test_the_advisory_window_opens_at_the_earliest_publish(self):
        advisory = parse_advisory(json.dumps(self.build()))
        assert advisory.window.start == moment("2025-09-08T13:12:10.343Z")

    def test_each_later_publish_becomes_its_own_wave(self):
        advisory = parse_advisory(json.dumps(self.build()))
        by_name = {p.name: p for p in advisory.packages}
        # The earliest package inherits the advisory window; repeating it would read
        # as a second wave at the same instant, which the loader rejects.
        assert by_name["ansi-styles"].window is None
        assert by_name["debug"].window.start == moment("2025-09-08T13:12:39.973Z")
        assert by_name["chalk"].window.start == moment("2025-09-08T13:13:05.239Z")

    def test_versions_published_together_share_one_entry(self):
        together = moment("2025-09-08T13:12:10.343Z")
        records = (PublishRecord("chalk", "5.6.1", together, False),
                   PublishRecord("chalk", "5.6.3", together, False))
        advisory = parse_advisory(json.dumps(self.build(records)))
        assert len(advisory.packages) == 1
        assert advisory.packages[0].versions == ("5.6.1", "5.6.3")

    def test_every_end_is_unknown_rather_than_guessed(self):
        body = self.build()
        advisory = parse_advisory(json.dumps(body))
        assert advisory.window.end is None
        assert advisory.window.provenance.end.kind == "unknown"
        assert advisory.window.provenance.start.kind == "derived"
        for package in body["packages"]:
            if "window" in package:
                assert package["window"]["end"] is None
                assert package["window"]["provenance"]["end"]["kind"] == "unknown"

    def test_the_start_cites_the_document_it_was_read_from(self):
        advisory = parse_advisory(json.dumps(self.build()))
        assert advisory.window.provenance.start.source == packument_url("ansi-styles")

    def test_nothing_to_derive_from_is_refused(self):
        with pytest.raises(RegistryError):
            advisory_from_records((), identifier="x", name="y", sources=("https://a.test",))

    def test_a_version_still_served_is_described_as_still_installable(self):
        records = (PublishRecord("chalk", "5.6.2", moment("2025-09-08T13:12:10.343Z"), True),)
        body = self.build(records)
        assert "still being served" in body["packages"][0]["notes"]


class TestDeriveCommand:
    def fake_registry(self, monkeypatch):
        def fetch(name, **kwargs):
            if name not in PACKUMENTS:
                raise RegistryError(f"{name}: the registry has no such package")
            return PACKUMENTS[name]

        monkeypatch.setattr("deptrail.cli.fetch_packument", fetch)

    def test_it_writes_an_advisory_a_scan_can_load(self, tmp_path, monkeypatch):
        self.fake_registry(monkeypatch)
        out = tmp_path / "incident.json"
        code = main(["advisory", "derive", "--package", "chalk@5.6.1",
                     "--id", "GHSA-x", "--name", "September 2025",
                     "--source", "https://example.test/a", "--output", str(out)])
        assert code == EXIT_CLEAN
        advisory = parse_advisory(out.read_text())
        assert advisory.window.start == moment("2025-09-08T13:13:05.239Z")
        assert advisory.window.end is None

    def test_a_registry_that_cannot_answer_is_transient_not_a_verdict(self, tmp_path, monkeypatch):
        self.fake_registry(monkeypatch)
        code = main(["advisory", "derive", "--package", "no-such-pkg@1.0.0",
                     "--id", "GHSA-x", "--name", "n", "--source", "https://example.test/a"])
        assert code == EXIT_TRANSIENT

    @pytest.mark.parametrize("spec", ["chalk", "@scope/only", "chalk@", "@1.0.0"])
    def test_a_malformed_spec_is_the_callers_error(self, spec, monkeypatch):
        self.fake_registry(monkeypatch)
        code = main(["advisory", "derive", "--package", spec,
                     "--id", "GHSA-x", "--name", "n", "--source", "https://example.test/a"])
        assert code == EXIT_BAD_INPUT

    def test_no_packages_at_all_is_the_callers_error(self, monkeypatch):
        self.fake_registry(monkeypatch)
        code = main(["advisory", "derive", "--id", "GHSA-x", "--name", "n",
                     "--source", "https://example.test/a"])
        assert code == EXIT_BAD_INPUT

    def test_a_file_of_specs_is_read_with_comments_and_blanks(self, tmp_path, monkeypatch):
        self.fake_registry(monkeypatch)
        listing = tmp_path / "versions.txt"
        listing.write_text("# the September 2025 wave\nchalk@5.6.1\n\n"
                           "ansi-styles@6.2.2   # withdrawn same day\n")
        out = tmp_path / "incident.json"
        code = main(["advisory", "derive", "--packages-from", str(listing),
                     "--id", "GHSA-x", "--name", "n",
                     "--source", "https://example.test/a", "--output", str(out)])
        assert code == EXIT_CLEAN
        advisory = parse_advisory(out.read_text())
        assert {p.name for p in advisory.packages} == {"chalk", "ansi-styles"}

    def test_the_same_version_twice_is_not_a_second_wave(self, tmp_path, monkeypatch):
        self.fake_registry(monkeypatch)
        out = tmp_path / "incident.json"
        code = main(["advisory", "derive", "--package", "chalk@5.6.1",
                     "--package", "chalk@5.6.1", "--id", "GHSA-x", "--name", "n",
                     "--source", "https://example.test/a", "--output", str(out)])
        assert code == EXIT_CLEAN
        advisory = parse_advisory(out.read_text())
        assert advisory.packages[0].versions == ("5.6.1",)
