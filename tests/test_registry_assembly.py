"""Tests for assembling an advisory out of registry publish times, and for the
`advisory derive` command that writes it.

The fixture in `fixtures/packuments.json` is a real packument trimmed to the two
maps this module reads, so the timestamps and the withdrawn-version shape are the
registry's own rather than something convenient. `ansi-styles` is kept because it
carries two withdrawn versions, 6.2.2 from the September 2025 compromise and 2.2.0
from 2016 — withdrawn is not the same as malicious, and the fixture says so.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from deptrail.cli import EXIT_BAD_INPUT, EXIT_CLEAN, EXIT_TRANSIENT, main
from deptrail.ioc import parse_advisory
from deptrail.registry import (
    PublishRecord,
    RegistryError,
    advisory_from_records,
    packument_url,
)

PACKUMENTS = json.loads((Path(__file__).parent / "fixtures" / "packuments.json").read_text())


def moment(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)


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

    def test_each_publish_becomes_its_own_wave(self):
        advisory = parse_advisory(json.dumps(self.build()))
        by_name = {p.name: p for p in advisory.packages}
        assert by_name["ansi-styles"].window.start == moment("2025-09-08T13:12:10.343Z")
        assert by_name["debug"].window.start == moment("2025-09-08T13:12:39.973Z")
        assert by_name["chalk"].window.start == moment("2025-09-08T13:13:05.239Z")

    def test_every_package_cites_the_packument_it_was_read_from(self):
        """Not the one that happened to sort first.

        Two packages published in the same millisecond both used to inherit the
        advisory window, whose provenance names a single packument — so one package's
        start was sourced to a document it was never read from. A scripted
        mass-publish makes that tie ordinary rather than exotic.
        """
        together = moment("2025-09-08T13:12:10.343Z")
        records = (PublishRecord("ansi-styles", "6.2.2", together, False),
                   PublishRecord("debug", "4.4.2", together, False))
        advisory = parse_advisory(json.dumps(self.build(records)))
        for package in advisory.packages:
            assert package.window.provenance.start.source == packument_url(package.name)

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

    def test_the_note_splits_served_from_withdrawn_per_version(self):
        # One entry can list several versions, so a single "this version is..."
        # sentence was false for half of a mixed wave.
        together = moment("2025-09-08T13:12:10.343Z")
        records = (PublishRecord("colors", "1.4.1", together, False),
                   PublishRecord("colors", "1.4.2", together, True))
        notes = self.build(records)["packages"][0]["notes"]
        assert "Still served" in notes and "1.4.2" in notes.split("Still served")[1]
        assert "No longer served" in notes and "1.4.1" in notes.split("No longer served")[1]

    def test_the_note_dates_its_own_claim(self):
        # "no longer served" is true at an instant; without it a reader months later
        # cannot weigh the bound it describes.
        body = advisory_from_records(
            self.records(), identifier="X", name="n", sources=("https://a.test/x",),
            derived_at=datetime(2026, 8, 19, 12, tzinfo=timezone.utc))
        assert "2026-08-19T12:00:00+00:00" in body["packages"][0]["notes"]


class TestDeriveCommand:
    def fake_registry(self, monkeypatch):
        def fetch(name, **kwargs):
            if name not in PACKUMENTS:
                raise RegistryError(f"{name}: the registry has no such package")
            return PACKUMENTS[name]

        monkeypatch.setattr("deptrail.registry.fetch_packument", fetch)

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


class TestTheDeriveCommandsGuards:
    """The four CLI-side fixes review asked for, none of which any test pinned.

    Each was verified by hand and then left unprotected: deleting any of them kept
    the whole suite green. These are the regression tests, one per fix.
    """

    @pytest.fixture
    def registry(self, monkeypatch):
        fetched = []

        def fetch(name, **kwargs):
            fetched.append(name)
            if name not in PACKUMENTS:
                raise RegistryError(f"{name}: the registry has no such package")
            return PACKUMENTS[name]

        monkeypatch.setattr("deptrail.registry.fetch_packument", fetch)
        return fetched

    def derive(self, tmp_path, *extra, output=True):
        argv = ["advisory", "derive", "--id", "GHSA-x", "--name", "n",
                "--source", "https://example.test/a", *extra]
        if output:
            argv += ["--output", str(tmp_path / "incident.json")]
        return main(argv)

    def test_a_byte_order_mark_does_not_become_part_of_the_name(self, tmp_path, registry):
        # A BOM survives str.strip(), so the first entry became '\ufeffchalk' — a 404
        # whose message says "check the spelling" while the file plainly reads chalk.
        listing = tmp_path / "versions.txt"
        listing.write_bytes(b"\xef\xbb\xbfchalk@5.6.1\n")
        assert self.derive(tmp_path, "--packages-from", str(listing)) == EXIT_CLEAN
        assert registry == ["chalk"]

    def test_a_bad_source_is_rejected_before_any_request(self, tmp_path, registry):
        # It used to surface after every fetch, as "a bug in the importer".
        code = main(["advisory", "derive", "--package", "chalk@5.6.1", "--id", "GHSA-x",
                     "--name", "n", "--source", "not-a-url"])
        assert code == EXIT_BAD_INPUT
        assert registry == []

    def test_an_uppercase_name_is_refused_without_suggesting_a_different_package(
            self, tmp_path, registry, capsys):
        # JSONStream and jsonstream are two live packages that both publish a 1.0.3,
        # so "npm names are lowercase" is advice that names the wrong one and reports
        # CLEAN.
        code = self.derive(tmp_path, "--package", "JSONStream@1.3.5")
        assert code == EXIT_BAD_INPUT
        message = capsys.readouterr().err
        assert "#60" in message and "different package" in message
        assert registry == []

    def test_the_lecture_is_not_appended_to_unrelated_failures(self, tmp_path, registry,
                                                               capsys):
        code = main(["advisory", "derive", "--package", "chalk@5.6.1", "--id", "GHSA-x",
                     "--name", "n", "--source", "not-a-url"])
        assert code == EXIT_BAD_INPUT
        assert "#60" not in capsys.readouterr().err

    @pytest.mark.parametrize("kind", ["missing", "directory"])
    def test_a_path_that_is_wrong_is_the_callers_move(self, tmp_path, registry, kind):
        target = tmp_path / "nope.txt" if kind == "missing" else tmp_path
        assert self.derive(tmp_path, "--packages-from", str(target)) == EXIT_BAD_INPUT

    def test_whitespace_inside_a_spec_is_caught_before_the_request(self, tmp_path,
                                                                   registry):
        # The probe validated the stripped name while the fetch used the raw one, so
        # this passed the check and came back 404 at exit 4.
        assert self.derive(tmp_path, "--package", "chalk @5.6.1") == EXIT_BAD_INPUT
        assert registry == []
