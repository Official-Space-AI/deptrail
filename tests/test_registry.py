"""Tests for deriving window starts from the registry.

The fixture in `fixtures/packuments.json` is a real packument trimmed to the two
maps this module reads, so the timestamps and the withdrawn-version shape are the
registry's own rather than something convenient. `ansi-styles` is kept because it
carries two withdrawn versions, 6.2.2 from the September 2025 compromise and 2.2.0
from 2016 — withdrawn is not the same as malicious, and the fixture says so.
"""
import gzip
import http.client
import json
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import pytest

import deptrail.fetch as fetch
import deptrail.registry as registry
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

    What this recorder does *not* see, since #27: `git ls-remote`, which the walk runs
    to learn which branches the remote has. It is a subprocess, so no in-process patch
    of `urlopen` or `socket` observes it — and it is meant to be there. The rule it
    still enforces is the one about *values*: no scan reads the registry, so no verdict
    moves because a third party answered. `tests/conftest.py` keeps the git call itself
    off the network during tests, and `tests/test_history.py` pins what it does when the
    remote cannot be reached.
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

        def scan_repo(repo, query, coverage_cache=None, trusted_url=None,
                      authenticate=True):
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

    def test_a_legacy_rekeying_is_dated_from_the_earlier_entry(self):
        # npm re-keyed express 1.0.0beta as 1.0.0-beta and dated the new key at the
        # re-keying. Taking the later one starts the window two and a half years after
        # the artifact was installable, so an install in between reports CLEAN.
        packument = {
            "name": "express",
            "time": {"1.0.0-beta": "2013-08-28T17:04:36.588Z",
                     "1.0.0beta": "2010-12-29T19:38:25.450Z"},
            "versions": {"1.0.0-beta": {}},
        }
        (record,) = publish_records(packument, "express", ("1.0.0-beta",))
        assert record.published_at == moment("2010-12-29T19:38:25.450Z")
        assert record.dated_from == "1.0.0beta"

    def test_a_hyphen_collision_between_two_real_releases_is_not_a_rekeying(self):
        """The rule that makes the previous test safe.

        Folding hyphens away also conflates `X.Y.Z-N` with `X.Y.ZN`, and `x.y.z-0` is
        what `npm version prerelease` emits — so this collides on live data.
        `phantomjs` publishes both `1.9.20` and `1.9.2-0`, 934 days apart, with
        different shasums. Treating the older as a re-keying would open the window
        two and a half years early and print a re-keying claim about a package npm
        never re-keyed. Both being in `versions` is what tells them apart.
        """
        packument = {
            "name": "phantomjs",
            "time": {"1.9.20": "2016-03-31T00:00:00.000Z",
                     "1.9.2-0": "2013-09-09T00:00:00.000Z"},
            "versions": {"1.9.20": {}, "1.9.2-0": {}},
        }
        (record,) = publish_records(packument, "phantomjs", ("1.9.20",))
        assert record.published_at == moment("2016-03-31T00:00:00.000Z")
        assert record.dated_from == "1.9.20"

    def test_a_packument_for_another_package_is_refused(self):
        # A mirror alias, a redirect or a poisoned cache would otherwise date one
        # package's versions from another's document.
        with pytest.raises(RegistryError, match="instead"):
            publish_records({"name": "evil", "time": {"1.0.0": "2020-01-01T00:00:00.000Z"},
                             "versions": {}}, "chalk", ("1.0.0",))

    def test_withdrawn_is_not_the_same_as_malicious(self):
        # 2.2.0 was withdrawn in 2016 and has nothing to do with the 2025 incident,
        # which is why this list cross-checks a version list and never replaces it.
        assert withdrawn_versions(PACKUMENTS["ansi-styles"]) == ("2.2.0", "6.2.2")


class TestBoundedRead:
    """The chunked read itself, which nothing exercised.

    Every test that fed `fetch_packument` a body used an object exposing only
    `read`, so the `read1` loop — with the deadline, the size cap and the
    stopped-early handler in it — never ran once. Disabling both limits left the
    whole suite green.
    """

    def opener(self, response):
        return lambda request, timeout=None: response

    class Response:
        """Delivers a body in pieces, the way a socket does."""

        def __init__(self, *chunks, error=None, pause=0.0):
            self.chunks, self.error, self.pause = list(chunks), error, pause

        def read1(self, size):
            if self.error:
                raise self.error
            if self.pause:
                time.sleep(self.pause)
            return self.chunks.pop(0) if self.chunks else b""

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def test_the_limits_are_values_that_can_actually_bite(self):
        """The tests below patch these, so they pass whatever the real numbers are.

        Raising `MAX_BYTES` to a terabyte or `DEADLINE` to a year left every one of
        them green while the production limits stopped limiting anything. The bounds
        here are the reasoning, not a restatement: the largest packument measured is
        `debug` at 195,840 bytes, so the cap must leave room to grow and still be a
        cap; the deadline must outlast a slow but real transfer and still expire
        inside an operator's patience.
        """
        # next is 31,118,994 bytes today and grows about 4.8MB a year, so the cap has
        # to sit well clear of it: an earlier 32MiB was already 92.7% consumed.
        assert 64 * 1024 * 1024 <= fetch.MAX_BYTES <= 1024 * 1024 * 1024
        # Long enough that a 31MB packument over a slow link finishes, short enough
        # that a trickle does not hold the importer for an afternoon.
        assert 300 <= fetch.DEADLINE <= 3600
        # TIMEOUT is the stall budget and has to expire long before the total one.
        assert 5 <= fetch.TIMEOUT <= 120
        assert fetch.TIMEOUT < fetch.DEADLINE

    def test_a_body_arriving_in_pieces_is_assembled(self):
        response = self.Response(b'{"na', b'me": "ch', b'alk"}')
        assert fetch_packument("chalk", opener=self.opener(response)) == {"name": "chalk"}

    @pytest.mark.parametrize("shape,expected", [
        ("oversized", "the registry sent more than"),
        ("truncated", "the registry declared"),
        ("dropped", "the registry stopped sending early"),
    ])
    def test_a_body_failure_names_the_registry_not_the_module(self, shape, expected,
                                                              monkeypatch):
        """Every message the transport emits has to name the caller's own system.

        `fetch.py` serves OSV as well, and these strings were carried over from when
        it did not: an OSV outage reported that npm was at fault and handed the
        responder a packument size budget with nothing to do with the failure.
        """
        class Truncated(self.Response):
            headers = {"Content-Length": "99"}

        if shape == "oversized":
            # Only here: a 4-byte cap would trip before the truncation check.
            monkeypatch.setattr(fetch, "MAX_BYTES", 4)
        response = {
            "oversized": lambda: self.Response(b"x" * 16),
            "truncated": lambda: Truncated(b"short"),
            "dropped": lambda: self.Response(error=TimeoutError("timed out")),
        }[shape]()
        with pytest.raises(RegistryError, match=expected):
            fetch_packument("chalk", opener=self.opener(response))

    def test_a_body_over_the_cap_is_refused(self, monkeypatch):
        monkeypatch.setattr(fetch, "MAX_BYTES", 8)
        response = self.Response(b"x" * 6, b"x" * 6)
        with pytest.raises(RegistryError, match="more than the"):
            fetch_packument("chalk", opener=self.opener(response))

    def test_the_cap_is_the_largest_body_still_accepted(self, monkeypatch):
        # Pins `>` rather than `>=`: exactly MAX_BYTES is fine, one more is not.
        monkeypatch.setattr(fetch, "MAX_BYTES", 17)
        exact = self.Response(b'{"name": "chalk"}')
        assert fetch_packument("chalk", opener=self.opener(exact)) == {"name": "chalk"}
        monkeypatch.setattr(fetch, "MAX_BYTES", 16)
        with pytest.raises(RegistryError, match="more than the"):
            fetch_packument("chalk", opener=self.opener(self.Response(b'{"name": "chalk"}')))

    def test_a_response_that_never_ends_is_given_up_on(self, monkeypatch):
        # urllib's timeout is per socket operation, so a trickle resets it forever;
        # this is the wall clock that makes the docstring's promise true.
        monkeypatch.setattr(fetch, "DEADLINE", 0.05)
        response = self.Response(*[b" "] * 1000, pause=0.02)
        with pytest.raises(RegistryError, match="still sending"):
            fetch_packument("chalk", opener=self.opener(response))

    def test_a_truncated_body_is_refused_rather_than_parsed(self):
        """`read1` returns what arrived, so a cut-short body simply ends.

        `read()` would have raised IncompleteRead here; without this check the
        truncation is silent and surfaces later as bad JSON, or worse as a packument
        that parsed as far as it got.
        """
        class Short(self.Response):
            headers = {"Content-Length": "99"}

        with pytest.raises(RegistryError, match="declared 99 bytes and sent"):
            fetch_packument("chalk", opener=self.opener(Short(b'{"name": "chalk"}')))

    def test_the_fallback_path_enforces_the_cap_too(self, monkeypatch):
        # "The fallback is only for tests" is the assumption that stops being true.
        monkeypatch.setattr(fetch, "MAX_BYTES", 4)

        asked = []

        class OnlyRead:
            def read(self, size=-1):
                asked.append(size)
                return b"x" * 16

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        with pytest.raises(RegistryError, match="more than the"):
            fetch_packument("chalk", opener=lambda *a, **k: OnlyRead())
        # Bounded at the call, not merely rejected afterwards: an unbounded read pulls
        # the whole body into memory first, which is the thing the cap exists to stop.
        assert asked == [fetch.MAX_BYTES + 1]

    def test_a_connection_that_goes_quiet_leaves_as_a_registry_error(self):
        """The stall case, which TIMEOUT catches rather than the deadline.

        Measured against a local server that sends a header and then stops: with
        TIMEOUT=2.0 the next read raises TimeoutError after 2.0s. An explicit idle
        budget on top of it was unreachable — the check sits before the blocking call
        and every chunk resets it — so this is the path that actually runs.
        """
        response = self.Response(error=TimeoutError("timed out"))
        with pytest.raises(RegistryError, match="stopped sending early"):
            fetch_packument("chalk", opener=self.opener(response))

    def test_the_socket_timeout_is_resolved_when_called(self, monkeypatch):
        # `timeout=TIMEOUT` as a default captured it at import, so lowering TIMEOUT had
        # no effect — including in the test written to prove a stall is caught, which
        # then hung past its own deadline. Same defect as the opener, one line apart.
        seen = {}
        monkeypatch.setattr(fetch, "TIMEOUT", 1.5)

        def opener(request, timeout=None):
            seen["timeout"] = timeout
            raise AssertionError("stop")

        with pytest.raises(AssertionError):
            fetch_packument("chalk", opener=opener)
        assert seen["timeout"] == 1.5

    def test_a_connection_dropped_mid_read_is_not_a_traceback(self):
        # IncompleteRead is an HTTPException, so it is caught by neither `main()` nor
        # the JSON handler, and used to leave as exit 1 — "rotate these credentials".
        response = self.Response(error=http.client.IncompleteRead(b"partial", 99992))
        with pytest.raises(RegistryError, match="stopped sending early"):
            fetch_packument("chalk", opener=self.opener(response))

    # Built inside the test rather than passed as a parameter: pytest puts a
    # parameter into the test id, and a 200,000-byte id overflowed Windows' 32,767
    # character environment-variable limit, taking the whole job down with
    # "previous item was not torn down properly".
    @pytest.mark.parametrize("shape", ["gzip", "not-utf-8", "deeply-nested"])
    def test_a_body_python_cannot_decode_is_not_a_traceback(self, shape):
        # gzip and non-UTF-8 raise UnicodeDecodeError, which is a ValueError but not a
        # JSONDecodeError; deep nesting raises RecursionError. All three escaped as a
        # traceback, and this contract reads a traceback as exit 1 — "rotate".
        body = {
            "gzip": lambda: gzip.compress(b'{"time":{}}'),
            "not-utf-8": lambda: b'{"time":' + bytes([0xff, 0xfe]) + b"}",
            "deeply-nested": lambda: b"[" * 100_000 + b"]" * 100_000,
        }[shape]()
        with pytest.raises(RegistryError, match="could not be read as JSON"):
            fetch_packument("chalk", opener=self.opener(self.Response(body)))


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

    def test_the_status_survives_the_re_raise(self):
        """The discriminator `FetchError` exists to carry.

        `RegistryError(str(e))` dropped it, so `.status` was always None and the
        `e.status == 404` branch one frame up could never have fired for any other
        caller — silently, with no test failing.
        """
        error = urllib.error.HTTPError("u", 503, "Service Unavailable", {}, None)
        with pytest.raises(RegistryError) as caught:
            fetch_packument("chalk", opener=self._opener(error))
        assert caught.value.status == 503

    def test_a_failure_names_the_registry_rather_than_the_module(self):
        # `fetch.py` serves OSV too, so its messages take the source from the caller.
        # Carried over verbatim, they told an OSV outage that npm was at fault.
        error = urllib.error.HTTPError("u", 500, "Server Error", {}, None)
        with pytest.raises(RegistryError, match="the registry answered HTTP 500"):
            fetch_packument("chalk", opener=self._opener(error))

    def test_an_absent_package_says_so(self):
        error = urllib.error.HTTPError("u", 404, "Not Found", {}, None)
        with pytest.raises(RegistryError) as caught:
            fetch_packument("nope", opener=self._opener(error))
        assert "no such package" in str(caught.value)

    def test_a_missing_ca_bundle_is_not_reported_as_an_outage(self):
        # Python installed from python.org ships no CA bundle until its own
        # Install Certificates step is run, and "could not reach it" sends
        # the reader to look at a firewall that is fine.
        import ssl

        error = urllib.error.URLError(ssl.SSLCertVerificationError("bad cert"))
        with pytest.raises(RegistryError) as caught:
            fetch_packument("chalk", opener=self._opener(error))
        assert "CA bundle" in str(caught.value)
        assert "SSL_CERT_FILE" in str(caught.value)

    def test_a_response_that_is_not_json_is_refused(self):
        class Body:
            # No `read1`, which is the fallback path an injected opener takes.
            def read(self, size=-1):
                return b"<html>maintenance</html>"

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        with pytest.raises(RegistryError) as caught:
            fetch_packument("chalk", opener=lambda *a, **k: Body())
        assert "could not be read as JSON" in str(caught.value)
