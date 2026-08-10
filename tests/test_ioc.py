"""Tests for advisory parsing, validation, and bundled feeds.

The validation tests are the point of this module: on incident day a feed is
typed by hand under pressure, so every malformed shape must fail loudly with the
offending field path rather than scan for the wrong thing.
"""
import json
import re
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

    def test_plan_maps_one_query_per_package(self):
        adv = parse_advisory(advisory_with(packages=[
            {"name": "chalk", "versions": ["5.6.1"], "sources": ["https://a.test"]},
            {"name": "debug", "versions": ["4.4.2", "4.4.3"], "sources": ["https://a.test"]},
        ]))
        queries = adv.plan().queries
        assert [q.package for q in queries] == ["chalk", "debug"]
        assert queries[1].malicious_versions == frozenset({"4.4.2", "4.4.3"})
        assert all(q.window_start == adv.window[0] for q in queries)

    def test_package_window_narrows_within_advisory_window(self):
        adv = parse_advisory(package_with(
            window={"start": "2025-11-25T00:00:00+00:00", "end": "2025-11-25T12:00:00+00:00"}
        ))
        query = adv.plan().queries[0]
        assert query.window_start == datetime(2025, 11, 25, tzinfo=timezone.utc)
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

    def test_missing_path_does_not_fall_back_to_a_bundled_feed(self, tmp_path):
        # A path that does not exist is an error, never a silent substitution.
        (tmp_path / "example-demo.json").write_text("{ broken")
        with pytest.raises(IocError, match="not found"):
            load_advisory(tmp_path / "nope.json")

    def test_unknown_bundled_name_lists_available_feeds(self):
        with pytest.raises(IocError, match="available:"):
            load_advisory("no-such-feed")


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

    def test_partial_feeds_cannot_imply_completeness(self):
        # Any feed shipped as an excerpt must carry the caveat into the report.
        for name in bundled_feeds():
            advisory = load_advisory(name)
            assert (advisory.coverage_warning is not None) == advisory.is_partial

    def test_demo_feed_matches_the_poc_scenario(self):
        advisory = load_advisory("example-demo")
        query = advisory.plan().queries[0]
        assert query.package == "chalk"
        assert query.malicious_versions == frozenset({"5.6.1"})

    def test_load_by_path_and_by_name_agree(self, tmp_path):
        from deptrail.ioc import FEEDS_DIR
        by_name = load_advisory("example-demo")
        by_path = load_advisory(FEEDS_DIR / "example-demo.json")
        assert by_name == by_path


class TestNameAndVersionShape:
    """Review regressions: a token that cannot match a lockfile must not scan silently."""

    @pytest.mark.parametrize("name", [" chalk", "chalk ", "chalk\n", "\xa0chalk"])
    def test_surrounding_whitespace_is_stripped(self, name):
        adv = parse_advisory(package_with(name=name))
        assert adv.packages[0].name == "chalk"
        assert adv.plan().queries[0].package == "chalk"

    @pytest.mark.parametrize("name,hint", [
        ("chalk@5.6.1", "put the version in 'versions'"),
        ("Chalk", "lowercase"),
        ("cha lk", "whitespace"),
        ("chalk/", "not a valid npm package name"),
    ])
    def test_unmatchable_names_rejected_with_a_hint(self, name, hint):
        with pytest.raises(IocError, match=re.escape(hint)):
            parse_advisory(package_with(name=name))

    def test_scoped_name_accepted(self):
        adv = parse_advisory(package_with(name="@mistralai/mistralai"))
        assert adv.packages[0].name == "@mistralai/mistralai"

    @pytest.mark.parametrize("version", ["^5.6.1", "~5.6", ">=5.0.0", "5.x", "*", "latest", "v5.6.1"])
    def test_ranges_and_tags_rejected(self, version):
        with pytest.raises(IocError, match="not an exact SemVer version"):
            parse_advisory(package_with(versions=[version]))

    @pytest.mark.parametrize("version", ["５.６.１", "1.0", "01.2.3", "1.2.3-+", "1.2", ""])
    def test_versions_no_lockfile_can_contain_are_rejected(self, version):
        # Each of these passed a looser check and then matched nothing: a CLEAN
        # verdict for a repo that may well have been exposed.
        with pytest.raises(IocError):
            parse_advisory(package_with(versions=[version]))

    @pytest.mark.parametrize("version", ["5.6.1", "0.0.1", "1.2.3-beta.1", "1.2.3+build.5"])
    def test_exact_versions_accepted(self, version):
        assert parse_advisory(package_with(versions=[version])).packages[0].versions == (version,)

    def test_whitespace_only_name_rejected(self):
        with pytest.raises(IocError, match="must not be empty"):
            parse_advisory(package_with(name="   "))


class TestProvenanceAndAmbiguity:
    def test_non_url_source_rejected(self):
        with pytest.raises(IocError, match="not an http"):
            parse_advisory(package_with(sources=["vendor blog"]))

    def test_duplicate_json_key_rejected(self):
        payload = (
            '{"schema_version": 1, "id": "x", "name": "x", "ecosystem": "npm",'
            ' "coverage": "complete",'
            ' "window": {"start": "2025-11-24T00:00:00+00:00", "end": "2025-11-25T00:00:00+00:00"},'
            ' "window": {"start": "2020-01-01T00:00:00+00:00", "end": "2020-01-02T00:00:00+00:00"},'
            ' "packages": [{"name": "chalk", "versions": ["5.6.1"], "sources": ["https://a.test"]}],'
            ' "sources": ["https://a.test"]}'
        )
        with pytest.raises(IocError, match="duplicate JSON key"):
            parse_advisory(payload)

    def test_schema_version_true_rejected(self):
        with pytest.raises(IocError, match="integer"):
            parse_advisory(advisory_with(schema_version=True))

    def test_schema_version_float_rejected(self):
        with pytest.raises(IocError, match="integer"):
            parse_advisory(advisory_with(schema_version=1.0))

    def test_package_window_outside_advisory_window_rejected(self):
        with pytest.raises(IocError, match="not inside the advisory window"):
            parse_advisory(package_with(
                window={"start": "2020-01-01T00:00:00+00:00", "end": "2020-01-02T00:00:00+00:00"}
            ))

    def test_two_waves_of_one_package_are_expressible(self):
        adv = parse_advisory(advisory_with(packages=[
            {"name": "chalk", "versions": ["5.6.1"], "sources": ["https://a.test"],
             "window": {"start": "2025-11-24T00:00:00+00:00", "end": "2025-11-24T12:00:00+00:00"}},
            {"name": "chalk", "versions": ["5.6.3"], "sources": ["https://a.test"],
             "window": {"start": "2025-11-26T00:00:00+00:00", "end": "2025-11-26T12:00:00+00:00"}},
        ]))
        assert len(adv.plan()) == 2

    def test_same_package_twice_with_same_window_rejected(self):
        with pytest.raises(IocError, match="duplicate entry"):
            parse_advisory(advisory_with(packages=[MINIMAL["packages"][0]] * 2))

    def test_window_field_paths_are_exact(self):
        with pytest.raises(IocError, match=r"advisory\.window\.start"):
            parse_advisory(advisory_with(window={"start": "nonsense", "end": "2025-11-25T00:00:00+00:00"}))

    def test_unknown_key_inside_window_blamed_on_the_window(self):
        with pytest.raises(IocError, match=r"advisory\.window: unknown field"):
            parse_advisory(advisory_with(window={
                "start": "2025-11-24T00:00:00+00:00", "end": "2025-11-25T00:00:00+00:00",
                "timezone": "KST",
            }))


class TestBoundPrecision:
    @pytest.mark.parametrize("bound", ["2025-11-24T10:15+00:00", "2025-11-24T10+00:00"])
    def test_missing_seconds_rejected(self, bound):
        # fromisoformat would zero-fill, silently moving the edge of the window.
        with pytest.raises(IocError, match="omits seconds"):
            parse_advisory(advisory_with(window={
                "start": "2025-11-24T00:00:00+00:00", "end": bound,
            }))

    def test_negative_zero_offset_rejected(self):
        with pytest.raises(IocError, match="offset unknown"):
            parse_advisory(advisory_with(window={
                "start": "2025-11-24T00:00:00-00:00", "end": "2025-11-25T00:00:00+00:00",
            }))


class TestReservedNames:
    @pytest.mark.parametrize("name", ["node_modules", "favicon.ico"])
    def test_names_npm_reserves_are_rejected(self, name):
        with pytest.raises(IocError, match="reserves"):
            parse_advisory(package_with(name=name))

    def test_over_length_name_rejected(self):
        with pytest.raises(IocError, match="at most 214"):
            parse_advisory(package_with(name="a" * 215))


class TestQueryPlan:
    def test_partial_coverage_travels_with_the_queries(self):
        plan = parse_advisory(advisory_with(coverage="partial")).plan()
        assert plan.coverage_warning and not plan.proves_absence
        assert len(plan) == len(plan.queries) == 1

    def test_complete_coverage_may_prove_absence(self):
        plan = parse_advisory(advisory_with(coverage="complete")).plan()
        assert plan.coverage_warning is None and plan.proves_absence

    def test_entries_carry_their_provenance(self):
        plan = parse_advisory(json.dumps(MINIMAL)).plan()
        entry = plan.entries[0]
        assert entry.sources == entry.package.sources
        assert entry.query.package == entry.package.name
