"""Tests for advisory parsing, validation, and bundled feeds.

The validation tests are the point of this module: on incident day a feed is
typed by hand under pressure, so every malformed shape must fail loudly with the
offending field path rather than scan for the wrong thing.
"""
import json
from datetime import datetime, timedelta, timezone

import pytest

from deptrail.ioc import (
    SCHEMA_VERSION,
    Advisory,
    IocError,
    bundled_feeds,
    load_advisory,
    parse_advisory,
)

MINIMAL = {
    "schema_version": SCHEMA_VERSION,
    "id": "GHSA-test",
    "name": "Test incident",
    "ecosystem": "npm",
    "coverage": "complete",
    "window": {"start": "2025-11-24T00:00:00+00:00", "end": "2025-11-26T23:59:59+00:00"},
    "packages": [
        {"name": "chalk", "versions": ["5.6.1"], "sources": ["https://example.test/advisory"]}
    ],
    "sources": ["https://example.test/advisory"],
}


def advisory_with(**overrides) -> str:
    return json.dumps({**MINIMAL, **overrides})


def package_with(**overrides) -> str:
    return advisory_with(packages=[{**MINIMAL["packages"][0], **overrides}])


class TestHappyPath:
    def test_minimal_advisory(self):
        adv = parse_advisory(advisory_with())
        assert isinstance(adv, Advisory)
        assert adv.id == "GHSA-test" and adv.coverage == "complete"
        assert adv.packages[0].versions == ("5.6.1",)
        assert adv.coverage_warning is None

    def test_queries_map_one_per_package(self):
        adv = parse_advisory(advisory_with(packages=[
            {"name": "chalk", "versions": ["5.6.1"], "sources": ["https://a.test"]},
            {"name": "debug", "versions": ["4.4.2", "4.4.3"], "sources": ["https://a.test"]},
        ]))
        queries = adv.queries()
        assert [q.package for q in queries] == ["chalk", "debug"]
        assert queries[1].malicious_versions == frozenset({"4.4.2", "4.4.3"})
        assert all(q.window_start == adv.window[0] for q in queries)

    def test_package_window_overrides_advisory_window(self):
        adv = parse_advisory(package_with(
            window={"start": "2025-12-01T00:00:00+00:00", "end": "2025-12-02T00:00:00+00:00"}
        ))
        query = adv.queries()[0]
        assert query.window_start == datetime(2025, 12, 1, tzinfo=timezone.utc)
        assert query.window_start != adv.window[0]

    def test_partial_coverage_carries_a_warning(self):
        adv = parse_advisory(advisory_with(coverage="partial"))
        assert adv.is_partial
        assert "absence of exposure is not evidence" in adv.coverage_warning

    def test_non_utc_offset_preserved(self):
        adv = parse_advisory(advisory_with(window={
            "start": "2025-11-24T09:00:00+09:00", "end": "2025-11-24T18:00:00+09:00",
        }))
        assert adv.window[0].utcoffset() == timedelta(hours=9)

    def test_z_suffix_accepted(self):
        adv = parse_advisory(advisory_with(window={
            "start": "2025-11-24T00:00:00Z", "end": "2025-11-26T23:59:59Z",
        }))
        assert adv.window[0] == datetime(2025, 11, 24, tzinfo=timezone.utc)


class TestWindowBounds:
    def test_bare_date_rejected_with_guidance(self):
        # A published date does not say which instants it covers; the transcriber
        # decides that, and the decision must be visible in the feed.
        with pytest.raises(IocError, match="no time of day"):
            parse_advisory(advisory_with(window={"start": "2025-11-24", "end": "2025-11-26"}))

    def test_offset_without_time_of_day_rejected(self):
        with pytest.raises(IocError, match="no time of day"):
            parse_advisory(advisory_with(window={
                "start": "2025-11-24+09:00", "end": "2025-11-26T00:00:00+09:00",
            }))

    def test_naive_timestamp_rejected(self):
        with pytest.raises(IocError, match="missing UTC offset"):
            parse_advisory(advisory_with(window={
                "start": "2025-11-24T00:00:00", "end": "2025-11-26T00:00:00+00:00",
            }))

    def test_inverted_window_rejected(self):
        with pytest.raises(IocError, match="start is after its end"):
            parse_advisory(advisory_with(window={
                "start": "2025-11-26T00:00:00+00:00", "end": "2025-11-24T00:00:00+00:00",
            }))

    def test_garbage_timestamp_rejected(self):
        with pytest.raises(IocError, match="not an ISO-8601 timestamp"):
            parse_advisory(advisory_with(window={"start": "last tuesday", "end": "today"}))

    def test_window_missing_end(self):
        with pytest.raises(IocError, match="missing 'end'"):
            parse_advisory(advisory_with(window={"start": "2025-11-24T00:00:00+00:00"}))


class TestFailLoud:
    def test_unknown_advisory_field_is_an_error(self):
        with pytest.raises(IocError, match="unknown field"):
            parse_advisory(advisory_with(windwo={"start": "x", "end": "y"}))

    def test_unknown_package_field_is_an_error(self):
        with pytest.raises(IocError, match=r"packages\[0\]: unknown field"):
            parse_advisory(package_with(verisons=["5.6.1"]))

    def test_wrong_schema_version(self):
        with pytest.raises(IocError, match="schema_version"):
            parse_advisory(advisory_with(schema_version=2))

    def test_missing_required_field(self):
        payload = {k: v for k, v in MINIMAL.items() if k != "coverage"}
        with pytest.raises(IocError, match="missing required field 'coverage'"):
            parse_advisory(json.dumps(payload))

    def test_bad_coverage_value(self):
        with pytest.raises(IocError, match="coverage"):
            parse_advisory(advisory_with(coverage="mostly"))

    def test_non_npm_ecosystem_rejected(self):
        with pytest.raises(IocError, match="only 'npm'"):
            parse_advisory(advisory_with(ecosystem="PyPI"))

    def test_empty_packages_rejected(self):
        with pytest.raises(IocError, match="non-empty array"):
            parse_advisory(advisory_with(packages=[]))

    def test_package_without_sources_rejected(self):
        payload = {k: v for k, v in MINIMAL["packages"][0].items() if k != "sources"}
        with pytest.raises(IocError, match="missing required field 'sources'"):
            parse_advisory(advisory_with(packages=[payload]))

    def test_empty_versions_rejected(self):
        with pytest.raises(IocError, match="must not be empty"):
            parse_advisory(package_with(versions=[]))

    def test_duplicate_versions_rejected(self):
        with pytest.raises(IocError, match="duplicate versions"):
            parse_advisory(package_with(versions=["5.6.1", "5.6.1"]))

    def test_duplicate_package_entries_rejected(self):
        with pytest.raises(IocError, match="duplicate entry"):
            parse_advisory(advisory_with(packages=[MINIMAL["packages"][0]] * 2))

    def test_non_string_version_rejected(self):
        with pytest.raises(IocError, match="non-empty strings"):
            parse_advisory(package_with(versions=[561]))

    def test_not_json(self):
        with pytest.raises(IocError, match="not valid JSON"):
            parse_advisory("{ nope")

    def test_root_must_be_object(self):
        with pytest.raises(IocError, match="must be a JSON object"):
            parse_advisory("[]")

    def test_missing_file_lists_bundled_feeds(self, tmp_path):
        with pytest.raises(IocError, match="bundled feeds"):
            load_advisory(tmp_path / "nope.json")


class TestBundledFeeds:
    def test_every_bundled_feed_parses(self):
        assert bundled_feeds()
        for name in bundled_feeds():
            advisory = load_advisory(name)
            assert advisory.packages and advisory.sources

    def test_every_bundled_entry_carries_a_source_url(self):
        for name in bundled_feeds():
            advisory = load_advisory(name)
            for pkg in advisory.packages:
                assert pkg.sources, f"{name}:{pkg.name} has no source"
                assert all(s.startswith("http") for s in pkg.sources)

    def test_real_incident_feeds_declare_partial_coverage(self):
        # Excerpts must not let a CLEAN verdict imply completeness.
        advisory = load_advisory("tanstack-2026-05")
        assert advisory.is_partial and advisory.coverage_warning

    def test_demo_feed_matches_the_poc_scenario(self):
        advisory = load_advisory("example-demo")
        query = advisory.queries()[0]
        assert query.package == "chalk"
        assert query.malicious_versions == frozenset({"5.6.1"})

    def test_load_by_path_and_by_name_agree(self, tmp_path):
        from deptrail.ioc import FEEDS_DIR
        by_name = load_advisory("example-demo")
        by_path = load_advisory(FEEDS_DIR / "example-demo.json")
        assert by_name == by_path
