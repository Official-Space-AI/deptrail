"""The pnpm key splitter, checked against real keys rather than against its author.

A package key renamed is a compromised version this tool does not find, or a clean one
it accuses, so the tests here are mostly real keys with the split the measured
specification says is correct. ``tests/fixtures/pnpm-keys/real-keys.json`` holds one
verbatim key per combination of (lockfile version, section, status, origin, where the
version came from, peers, patched) observed across 4,424 real lockfiles -- 83 rows --
each with its entry body and, for 9.0 snapshots, the ``packages:`` body it reads its
version from. The expectations were produced by the reference implementation that four
independent oracles (dependency edges, tarball filenames, key-versus-body, the live
registry) agreed with on 3,124,858 rows, and this module was then shown to match it
row for row. So the fixture is not "what the code returns"; it is what the oracles
returned, frozen.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import pytest

from deptrail.pnpmkeys import (NOT_NPM, NPM, OTHER_REGISTRY, SOURCE, UNKNOWN, KeyRecord,
                               UnsupportedLockfileVersion, band_of, split_key,
                               suffix_groups)
from deptrail.yamlsubset import load_documents

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
REAL = json.loads(FIXTURES.joinpath("pnpm-keys", "real-keys.json").read_text(encoding="utf-8"))


def _id(row):
    return f"{row['lockfileVersion']}:{row['section']}:{row['key'][:48]}"


class TestRealKeys:
    @pytest.mark.parametrize("row", REAL, ids=_id)
    def test_every_observed_shape_splits_as_the_oracles_said(self, row):
        record = split_key(row["lockfileVersion"], row["key"], row["entry"], row["packages"])
        want = row["expect"]
        got = {"status": record.status, "name": record.name, "version": record.version,
               "version_from": record.version_from, "origin": record.origin,
               "patched": record.patched, "peers": list(record.peers), "reason": record.reason}
        assert got == want, row["key"]

    def test_the_fixture_still_covers_every_band_status_and_origin(self):
        """A differential fixture asserts nothing on its own; this is what stops it being
        trimmed to the easy rows. Counts are the measured ones, pinned."""
        assert len(REAL) == 83
        bands = {band_of(r["lockfileVersion"]) for r in REAL}
        assert bands == {"v5", "v6", "v9"}
        versions = {str(r["lockfileVersion"]) for r in REAL}
        assert {"5", "5.1", "5.2", "5.3", "5.3-inlineSpecifiers", "5.4", "6.0", "6.1", "9.0"} <= versions
        statuses = {r["expect"]["status"] for r in REAL}
        assert statuses == {NPM, SOURCE, NOT_NPM, OTHER_REGISTRY, UNKNOWN}
        origins = {r["expect"]["origin"] for r in REAL}
        assert {"registry", "registry-host", "git", "local-dir", "local-tarball",
                "remote-tarball", "jsr", "runtime"} <= origins
        assert any(r["expect"]["peers"] for r in REAL)
        assert any(r["expect"]["patched"] for r in REAL)
        assert any(r["section"] == "snapshots" for r in REAL)

    def test_no_real_row_is_unknown_for_a_reason_the_grammar_should_have_handled(self):
        """The only acceptable reasons for an unknown are the ones the specification
        lists: a key the body cannot name, and a 5.x/6.x key inside a 9.0 document."""
        reasons = {r["expect"]["reason"] for r in REAL if r["expect"]["status"] == UNKNOWN}
        allowed = {"key is not a registry identity and the body has no name",
                   "v5/v6-style key in a document declaring lockfileVersion 9.0",
                   "body names the package but records no version"}
        assert reasons <= allowed, reasons - allowed


class TestTheThreeGrammars:
    """The same package written three ways, so a parser written against one version
    alone reads nothing from the other two."""

    @pytest.mark.parametrize("version,key", [
        ("5.4", "/chalk/5.6.1"), ("6.0", "/chalk@5.6.1"), ("9.0", "chalk@5.6.1"),
        (5, "/chalk/5.6.1"), ("5.3-inlineSpecifiers", "/chalk/5.6.1"), ("6.1", "/chalk@5.6.1"),
    ])
    def test_a_plain_package(self, version, key):
        record = split_key(version, key, {}, {})
        assert (record.status, record.name, record.version) == (NPM, "chalk", "5.6.1")

    @pytest.mark.parametrize("version,key", [
        ("5.4", "/@babel/core/7.22.10"), ("6.0", "/@babel/core@7.22.10"), ("9.0", "@babel/core@7.22.10"),
    ])
    def test_a_scoped_package(self, version, key):
        record = split_key(version, key, {}, {})
        assert (record.name, record.version) == ("@babel/core", "7.22.10")

    def test_an_unsupported_version_is_refused_rather_than_guessed(self):
        for version in (7, "8.0", "10", "", None, "x"):
            with pytest.raises(UnsupportedLockfileVersion):
                band_of(version)


class TestPeerSuffixes:
    """The version before the suffix is the installed version -- measured four ways,
    zero counterexamples -- and the suffix is context, never identity."""

    @pytest.mark.parametrize("version,key,name,ver,peers", [
        ("5.4", "/acorn-jsx/5.3.2_acorn@8.9.0", "acorn-jsx", "5.3.2", ()),
        ("6.0", "/react-dom@18.2.0_react@18.2.0", "react-dom", "18.2.0", ()),
        ("6.0", "/vite@4.4.9_@types+node@20.4.7+sass@1.65.1", "vite", "4.4.9", ()),
        ("6.0", "/@vitejs/plugin-react@4.0.4_vite@4.4.9", "@vitejs/plugin-react", "4.0.4", ()),
        ("6.0", "/@algolia/autocomplete-core@1.9.3(algoliasearch@4.13.1)",
         "@algolia/autocomplete-core", "1.9.3", ("algoliasearch@4.13.1",)),
        ("9.0", "acorn-jsx@5.3.2(acorn@8.9.0)", "acorn-jsx", "5.3.2", ("acorn@8.9.0",)),
        ("9.0", "@nuxt/nitro-server@4.5.0(04fce615bf33c904ce4a75031b50d534)",
         "@nuxt/nitro-server", "4.5.0", ("04fce615bf33c904ce4a75031b50d534",)),
        ("9.0", "vite@5.0.0(@types/node@20.4.7)(sass@1.65.1)", "vite", "5.0.0",
         ("@types/node@20.4.7", "sass@1.65.1")),
    ])
    def test_the_peer_never_becomes_the_version(self, version, key, name, ver, peers):
        """`rsplit('@')` turned `(algoliasearch@4.13.1)` into a finding against the
        peer's version 4.13.1 -- both hiding the vulnerable package and accusing the
        peer."""
        record = split_key(version, key, {}, {})
        assert (record.name, record.version, record.peers) == (name, ver, peers)

    def test_a_name_with_an_underscore_is_not_a_suffix(self):
        assert split_key("5.4", "/string_decoder/1.1.1", {}, {}).name == "string_decoder"
        assert split_key("5.4", "/@types/babel__core/7.1.19", {}, {}).name == "@types/babel__core"
        assert split_key("6.0", "/string_decoder@1.1.1", {}, {}).name == "string_decoder"

    def test_a_stacked_suffix_is_cut_at_the_first_underscore(self):
        """`rsplit` returns `0.6.10_bccowfhumyeojfpizsad764w2m` on the three stacked
        keys in the corpus -- not semver, so the package vanishes into `unknown`."""
        record = split_key("5.4", "/x/0.6.10_bccowfhumyeojfpizsad764w2m_react@18.0.0", {}, {})
        assert (record.status, record.version) == (NPM, "0.6.10")
        record = split_key("6.0", "/x@0.6.10_bccowfhumyeojfpizsad764w2m_react@18.0.0", {}, {})
        assert (record.status, record.version) == (NPM, "0.6.10")

    def test_the_version_at_sign_is_the_first_after_the_scope_not_the_last(self):
        """A scoped 6.x key with a peer holds three `@`; the last one belongs to the
        peer. `rfind` renames `@vitejs/plugin-react` to `@vitejs/plugin-react@4.0.4_vite`."""
        record = split_key("6.0", "/@vitejs/plugin-react@4.0.4_vite@4.4.9", {}, {})
        assert (record.name, record.version) == ("@vitejs/plugin-react", "4.0.4")
        record = split_key("6.0", "/react-dom@18.2.0_react@18.2.0", {}, {})
        assert (record.name, record.version) == ("react-dom", "18.2.0")
        record = split_key("9.0", "@scope/name@1.0.0", {}, {})
        assert (record.name, record.version) == ("@scope/name", "1.0.0")

    def test_too_few_segments_is_not_an_identity(self):
        """`/chalk` and `/@scope/name` have no version segment; reading them as an
        identity would invent one from whatever came next."""
        assert split_key("5.4", "/chalk", {}, {}).status == UNKNOWN
        assert split_key("5.4", "/@scope/name", {}, {}).status == UNKNOWN
        assert split_key("6.0", "/@scope", {}, {}).status == UNKNOWN
        assert split_key("6.0", "/@1.0.0", {}, {}).status == UNKNOWN

    def test_a_host_is_any_first_segment_pnpm_could_have_encoded(self):
        """`chalk/5.6.1` is not `host=chalk` because what follows (`5.6.1`) has no name
        segment -- not because `chalk` lacks a dot. pnpm's parser has no dot rule, and
        `verdaccio+4873` is a real registry host."""
        assert split_key("5.4", "chalk/5.6.1", {}, {}).status == UNKNOWN
        for host in ("localhost+4873", "verdaccio+4873", "registry.npmmirror.com", "127.0.0.1+4873"):
            record = split_key("5.4", f"{host}/chalk/5.6.1", {}, {})
            assert (record.status, record.name, record.version, record.origin) == (NPM, "chalk", "5.6.1", "registry-host"), host
        record = split_key("6.0", "registry.npmmirror.com/immer@10.0.3", {}, {})
        assert (record.status, record.name, record.version) == (NPM, "immer", "10.0.3")
        # `:` is not pnpm's port encoding (`+` is), so this is not a host shape at all.
        assert split_key("5.4", "registry.example.com:4873/chalk/5.6.1", {}, {}).status == UNKNOWN

    def test_a_patch_hash_is_recorded_and_not_a_peer(self):
        record = split_key("9.0", "lodash@4.17.21(patch_hash=abc123)", {}, {})
        assert (record.patched, record.peers, record.version) == (True, (), "4.17.21")
        record = split_key("6.0", "/lodash@4.17.21(patch_hash=abc123)", {}, {})
        assert (record.patched, record.peers) == (True, ())

    def test_a_parenthesis_inside_a_url_is_not_a_suffix(self):
        """The suffix scan is balanced and backward, like pnpm's own `indexOfPeersSuffix`.

        It peels every trailing `(...)` group and stops at the first character that is
        not a closer, so a parenthesis inside a URL is safe as long as something follows
        it -- which in a URL something always does. `key.split("(")[0]` would cut the URL
        at `(q` instead; it happens to work on 6.x and breaks on 9.0.
        """
        base, groups = suffix_groups("x@https://h/p(q)r(a@1)(b@2)")
        assert (base, groups) == ("x@https://h/p(q)r", ["a@1", "b@2"])
        base, groups = suffix_groups("x@https://h/p(q)")
        assert (base, groups) == ("x@https://h/p", ["q"]), (
            "a trailing group is a group; nothing in the grammar can tell it from a peer")

    def test_an_unbalanced_parenthesis_is_unknown_not_a_crash(self):
        record = split_key("9.0", "x@1.0.0)", {}, {})
        assert record.status == UNKNOWN and "unbalanced" in record.reason


class TestTheBodyOutranksTheKeyBefore9:
    def test_a_host_prefixed_key_can_name_an_alias(self):
        """Measured on rushstack: the key says `@scope/testDep`, the body says
        `pad-left`, and the body is what was installed."""
        entry = {"name": "pad-left", "version": "2.1.0"}
        record = split_key("5.3", "example.pkgs.visualstudio.com/@scope/testDep/2.1.0", entry, {})
        assert (record.name, record.version, record.version_from) == ("pad-left", "2.1.0", "body")
        assert record.origin == "registry-host"

    def test_without_a_body_the_key_is_trusted(self):
        record = split_key("5.3", "registry.npmjs.org/@foo/bar/1.1.0", {}, {})
        assert (record.name, record.version, record.version_from) == ("@foo/bar", "1.1.0", "key")

    def test_a_body_with_a_name_but_no_version_is_unknown(self):
        record = split_key("5.4", "/chalk/5.6.1", {"name": "chalk"}, {})
        assert record.status == UNKNOWN and "no version" in record.reason

    def test_a_6x_document_may_carry_a_5x_key(self):
        assert split_key("6.0", "/chalk/5.6.1", {}, {}).name == "chalk"
        assert split_key("5.4", "/chalk@5.6.1", {}, {}).name == "chalk"


class TestTheBodyIsOnlyTrustedWhenItIsText:
    """The reader hands every scalar over as a string, so a non-string `name` or
    `version` is a mapping or a list -- a malformed entry. `str()` of it was being
    written into the record: `"{'x': 1}"` where a version belongs never matches an
    advisory, which is a clean verdict manufactured from garbage. Found by the
    independent codex review."""

    @pytest.mark.parametrize("entry,field", [
        ({"name": "chalk", "version": {"x": 1}}, "version"),
        ({"name": ["chalk"], "version": "5.6.1"}, "name"),
        ({"name": "chalk", "version": ["5.6.1"]}, "version"),
    ])
    def test_a_structured_name_or_version_in_a_5x_body_is_unknown(self, entry, field):
        record = split_key("5.4", "/chalk/5.6.1", entry, {})
        assert record.status == UNKNOWN and record.name is None and record.version is None
        assert f"body {field} is a" in record.reason and "not a string" in record.reason

    def test_a_structured_version_in_a_9_packages_body_is_unknown(self):
        record = split_key("9.0", "chalk@5.6.1(x@1)", {}, {"chalk@5.6.1": {"version": {"x": 1}}})
        assert (record.status, record.name, record.version) == (UNKNOWN, "chalk", None)
        assert "not a string" in record.reason
        record = split_key("9.0", "chalk@5.6.1", {"version": ["5.6.1"]}, {})
        assert record.status == UNKNOWN

    def test_the_body_version_really_is_the_one_returned(self):
        """Every real row has body.version == key.version, so a mutant returning the key's
        version with the body's label passed the whole corpus. Pinned with a disagreement."""
        record = split_key("5.3", "registry.npmjs.org/q/1.5.1", {"name": "q", "version": "1.5.2"}, {})
        assert (record.version, record.version_from) == ("1.5.2", "body")
        record = split_key("9.0", "chalk@5.6.1(supports-color@9.0.0)", {}, {"chalk@5.6.1": {"version": "5.6.2"}})
        assert (record.version, record.version_from) == ("5.6.2", "packages-body")


class TestABlankBodyIsNotAnIdentity:
    """``version: ''`` outranked the key in 5.x/6.x and produced a row whose version is
    the empty string, which no advisory names: a clean verdict from a malformed body."""

    @pytest.mark.parametrize("value", ["''", '""', "'   '"])
    def test_a_blank_body_version_is_unknown_before_nine(self, value):
        entry = {"name": "chalk", "version": value.strip("'\"")}
        record = split_key("6.0", "/chalk@5.6.1", entry)
        assert record.status == UNKNOWN
        assert record.reason == "body version is blank"

    def test_a_blank_body_name_is_unknown_before_nine(self):
        record = split_key("5.4", "/chalk/5.6.1", {"name": "", "version": "5.6.1"})
        assert record.status == UNKNOWN and record.reason == "body name is blank"

    def test_a_whitespace_recorded_version_is_unknown_in_nine(self):
        record = split_key("9.0", "chalk@5.6.1", {"version": "  "}, {})
        assert record.status == UNKNOWN and record.reason == "recorded version is blank"

    def test_an_empty_recorded_version_in_nine_falls_back_to_the_key(self):
        """``''`` is falsy, so 9.0 never read it as a version in the first place."""
        record = split_key("9.0", "chalk@5.6.1", {"version": ""}, {})
        assert (record.status, record.version, record.version_from) == (NPM, "5.6.1", "key")

    @pytest.mark.parametrize("body, reason", [
        ({"name": "chalk ", "version": "5.6.1"}, "body name 'chalk ' is not a name"),
        ({"name": "not a name at all", "version": "5.6.1"}, "body name 'not a name at all' is not a name"),
        ({"name": "(root)", "version": "5.6.1"}, "body name '(root)' is not a name"),
        ({"name": "chalk", "version": "not a version"}, "body version 'not a version' is not a version"),
        ({"name": "chalk\n", "version": "5.6.1"}, "body name 'chalk\\n' is not a name"),
        ({"name": "chalk", "version": "5.6.1\n"}, "body version '5.6.1\\n' is not a version"),
    ])
    def test_a_body_that_is_not_an_identity_does_not_outrank_the_key(self, body, reason):
        record = split_key("6.0", "/chalk@5.6.1", body)
        assert (record.status, record.reason) == (UNKNOWN, reason)

    def test_a_nine_recorded_version_that_is_not_semver_is_unknown(self):
        record = split_key("9.0", "chalk@5.6.1", {"version": "not a version"}, {})
        assert (record.status, record.reason) == (UNKNOWN, "recorded version 'not a version' is not a version")

    def test_a_git_row_keeps_the_version_pnpm_recorded_even_when_it_is_a_git_spec(self):
        """pnpm's own fixture ``fixtures-with-non-package-dep``: a repository with no
        package.json version gets its git spec recorded as the version. The row is
        ``source`` and never answers for a registry version, so the odd string costs
        nothing; refusing it made the whole lockfile unreadable."""
        key = "github.com/denolib/camelcase/aeb6b15f9c9957c8fa56f9731e914c4d8a6d2f2b"
        body = {"resolution": {"tarball": "https://codeload.github.com/denolib/camelcase/tar.gz/"
                                          "aeb6b15f9c9957c8fa56f9731e914c4d8a6d2f2b"},
                "name": "camelcase",
                "version": "denolib/camelcase#aeb6b15f9c9957c8fa56f9731e914c4d8a6d2f2b"}
        record = split_key("5.4", key, body)
        assert (record.status, record.name, record.version, record.origin) == (
            SOURCE, "camelcase", "denolib/camelcase#aeb6b15f9c9957c8fa56f9731e914c4d8a6d2f2b", "git")
        nine = split_key("9.0", "camelcase@https://codeload.github.com/denolib/camelcase/tar.gz/aeb6b15f",
                         {}, {"camelcase@https://codeload.github.com/denolib/camelcase/tar.gz/aeb6b15f": body})
        assert (nine.status, nine.version) == (SOURCE, body["version"])

    @pytest.mark.parametrize("version, key", [("9.0", "chalk@5.6.1\n"), ("6.0", "/chalk@5.6.1\n"),
                                              ("5.4", "/chalk/5.6.1\n")])
    def test_a_key_with_a_trailing_newline_is_not_a_version(self, version, key):
        """``$`` matches before a trailing newline; ``fullmatch`` does not."""
        record = split_key(version, key, {}, {})
        assert record.status == UNKNOWN


class TestPatchedIsAStringBoolean:
    """The reader delivers `patched: true` as the string `"true"`; `bool("false")` is
    True. Real lockfiles only ever write `true` (241 rows, 106 files), so nothing was
    wrong in the field -- but the rule was wrong in principle and had no test."""

    @pytest.mark.parametrize("value,expected", [("true", True), ("false", False), ("True", True), ("0", False), ("yes", True), (True, True), (False, False)])
    def test_every_spelling(self, value, expected):
        assert split_key("6.0", "/lodash@4.17.21", {"patched": value}, {}).patched is expected


class TestNineSnapshotsReadPackages:
    """A 9.0 `snapshots:` key has no version of its own; it comes from `packages[base]`."""

    def test_a_url_in_the_key_is_not_the_version(self):
        """86 rows across 46 repositories returned the URL as the version of `vue`."""
        packages = {"vue@https://pkg.pr.new/vue@e1bc0eb": {"version": "3.5.13",
                    "resolution": {"tarball": "https://pkg.pr.new/vue@e1bc0eb"}}}
        record = split_key("9.0", "vue@https://pkg.pr.new/vue@e1bc0eb(typescript@5.0.0)", {}, packages)
        assert (record.status, record.name, record.version, record.origin) == (SOURCE, "vue", "3.5.13", "remote-tarball")
        assert record.version_from == "packages-body"

    def test_the_first_at_sign_wins_over_the_last(self):
        packages = {"@vioxen/subscription-runtime@git+https://git@github.com:777genius/ar.git#abc":
                    {"version": "0.1.0-main.28", "resolution": {"type": "git", "commit": "abc"}}}
        record = split_key("9.0", "@vioxen/subscription-runtime@git+https://git@github.com:777genius/ar.git#abc", {}, packages)
        assert (record.name, record.version, record.origin) == ("@vioxen/subscription-runtime", "0.1.0-main.28", "git")

    def test_the_suffixed_key_is_looked_up_by_its_base(self):
        packages = {"chalk@5.6.1": {"version": "5.6.1"}}
        record = split_key("9.0", "chalk@5.6.1(supports-color@9.0.0)", {}, packages)
        assert (record.version, record.version_from) == ("5.6.1", "packages-body")

    def test_a_5x_key_inside_a_9_document_is_refused_per_key(self):
        """Never guessed at: a document can genuinely mix both shapes, so a per-key
        fallback would misparse the majority. The caller holding the whole document
        decides whether *every* key refused this way."""
        record = split_key("9.0", "/legacy-package/1.2.3_peer@2.0.0", {}, {})
        assert record.status == UNKNOWN and "lockfileVersion 9.0" in record.reason


class TestShapesThatAreNotAnNpmPackage:
    def test_a_local_directory_is_not_npm_and_is_never_given_a_version(self):
        """Zero of 870 directory entries record a version; inventing `0.0.0` would be a
        finding against a path."""
        entry = {"name": "@vitejs/test-aliased-module", "resolution": {"directory": "playground/alias/dir/module", "type": "directory"}}
        record = split_key("6.0", "file:playground/alias/dir/module", entry, {})
        assert (record.status, record.name, record.version, record.origin) == (NOT_NPM, "@vitejs/test-aliased-module", None, "local-dir")
        record = split_key("9.0", "@vitejs/test-aliased-module@file:playground/alias/dir/module",
                           {"resolution": {"directory": "playground/alias/dir/module", "type": "directory"}}, {})
        assert (record.status, record.name, record.version) == (NOT_NPM, "@vitejs/test-aliased-module", None)

    def test_a_nameless_directory_is_not_npm_with_no_name(self):
        """A third state, distinct from "npm package" and from "unreadable"."""
        record = split_key("5.4", "file:../nameless-package", {"version": "1.0.0", "resolution": {"directory": "../nameless-package", "type": "directory"}}, {})
        assert (record.status, record.name) == (NOT_NPM, None)

    def test_a_local_tarball_is_a_published_artifact(self):
        entry = {"name": "my-tarball-pkg", "version": "2.3.4", "resolution": {"tarball": "file:my-tarball-pkg-2.3.4.tgz"}}
        record = split_key("6.0", "file:my-tarball-pkg-2.3.4.tgz", entry, {})
        assert (record.status, record.version, record.origin) == (SOURCE, "2.3.4", "local-tarball")
        packages = {"@sveltejs/kit@file:packages/sveltejs-kit-2.21.1.tgz": {"version": "2.21.1", "resolution": {"tarball": "file:packages/sveltejs-kit-2.21.1.tgz"}}}
        record = split_key("9.0", "@sveltejs/kit@file:packages/sveltejs-kit-2.21.1.tgz(svelte@5.0.0)", {}, packages)
        assert (record.status, record.name, record.version) == (SOURCE, "@sveltejs/kit", "2.21.1")

    def test_a_git_dependency_without_a_recorded_version_is_unknown(self):
        record = split_key("5.4", "github.com/owner/repo/7e4fef9abcdef", {}, {})
        assert record.status == UNKNOWN and record.origin == "git"

    def test_jsr_is_another_registry(self):
        record = split_key("9.0", "@jsr/std__assert@1.0.19", {}, {})
        assert (record.status, record.origin, record.version) == (OTHER_REGISTRY, "jsr", "1.0.19")

    def test_a_runtime_is_not_npm(self):
        record = split_key("9.0", "node@runtime:26.7.0", {}, {})
        assert (record.status, record.name, record.version, record.origin) == (NOT_NPM, "node", "26.7.0", "runtime")

    def test_a_named_registry_alias_is_read_but_flagged(self):
        """Eight rows in one file of uncertain provenance; low confidence, documented."""
        assert split_key("9.0", "chalk@npmjs:5.3.0", {}, {}).status == NPM
        record = split_key("9.0", "semver@verdaccio:7.6.3", {}, {})
        assert (record.status, record.origin) == (OTHER_REGISTRY, "named-registry:verdaccio")


class TestAgainstTheFixtureLockfiles:
    """End to end through the reader, on the lockfile slices already in the tree."""

    @pytest.mark.parametrize("name,first_key,expected", [
        ("pnpm-v5.4.yaml", "/@algolia/autocomplete-core/1.6.3", ("@algolia/autocomplete-core", "1.6.3")),
        ("pnpm-v5.3-prettier.yaml", "/@types/node/18.15.0", ("@types/node", "18.15.0")),
        ("pnpm-v6.0.yaml", "/@aashutoshrathi/word-wrap@1.2.6", ("@aashutoshrathi/word-wrap", "1.2.6")),
        ("pnpm-v9.yaml", "@aashutoshrathi/word-wrap@1.2.6", ("@aashutoshrathi/word-wrap", "1.2.6")),
    ])
    def test_the_first_package_of_each_fixture(self, name, first_key, expected):
        document = load_documents(FIXTURES.joinpath("yaml", name).read_text(encoding="utf-8"))[0]
        packages = document["packages"]
        assert first_key in packages
        record = split_key(document["lockfileVersion"], first_key, packages[first_key], packages)
        assert (record.status, record.name, record.version) == (NPM, *expected)

    # Two fixtures hold keys the declared grammar refuses on purpose: a 9.0 header over
    # seven 6.x keys, and a 9.0 document with two legacy keys among eleven. The document
    # reader (``pnpmlock``) decides what becomes of those; here they are pinned so the
    # splitter keeps refusing them per key.
    UNKNOWN_BY_DESIGN = {"pnpm-v9-header-lies.yaml": 7, "pnpm-v9-mixed-keys.yaml": 2}

    def test_every_key_in_every_fixture_splits_to_a_known_status(self):
        for path in sorted(FIXTURES.joinpath("yaml").glob("pnpm-*.yaml")):
            unknown = 0
            for document in load_documents(path.read_text(encoding="utf-8")):
                packages = document.get("packages") or {}
                for section in (packages, document.get("snapshots") or {}):
                    for key, entry in section.items():
                        record = split_key(document["lockfileVersion"], key, entry, packages)
                        if record.status == UNKNOWN:
                            unknown += 1
                            assert path.name in self.UNKNOWN_BY_DESIGN, (path.name, key, record.reason)
            assert unknown == self.UNKNOWN_BY_DESIGN.get(path.name, 0), path.name


# ---------------------------------------------------------------------------------------
# Inputs derived from the grammar rather than from the corpus, each protecting a guard the
# 83-row fixture cannot see. From the independent test-quality review: 57 targeted mutants,
# 35 survived the suite as it then stood, 31 of them are killed below. Grouped by the line
# each protects; the expected values are the module's measured output, cross-checked
# against the specification and pnpm's own `dependency-path` where it answers.
# ---------------------------------------------------------------------------------------

class TestAVersionWithoutANameIsNotAnIdentity:
    """pnpmkeys.py:210 (`at <= 0`), :302-305 (`at < 1`), :307-308 (implausible key)."""

    @pytest.mark.parametrize("version,key", [("6.0", "/1.0.0"), ("9.0", "1.0.0")])
    def test_a_bare_semver_is_not_read_as_a_package_named_1_0_dot(self, version, key):
        record = split_key(version, key, {}, {})
        assert (record.status, record.name) == (UNKNOWN, None)

    @pytest.mark.parametrize("key", ["chalk", "@scope"])
    def test_v9_without_a_separator_names_that_reason_and_leaks_no_name(self, key):
        record = split_key("9.0", key, {}, {})
        assert (record.status, record.name) == (UNKNOWN, None)
        assert record.reason.startswith("no name@version separator")

    @pytest.mark.parametrize("key", ["a/b@1.0.0", "@scope/a/b@1.0.0", "chalk@"])
    def test_v9_implausible_names_and_empty_versions_are_refused(self, key):
        record = split_key("9.0", key, {}, {})
        assert (record.status, record.name) == (UNKNOWN, None)
        assert record.reason.startswith("implausible key")


class TestAHostIsWhateverPnpmWrites:
    """`_host_split` (`fullmatch` at the host, no dot rule).

    pnpm's own `dependency-path.parse` has no "must contain a dot" rule, and
    `encode-registry` writes `http://verdaccio:4873` as `verdaccio+4873` -- a Docker
    service name, ordinary in CI. A first version required a dot and demoted every such
    registry to a tarball of unknown provenance; two independent reviews found it.
    """

    @pytest.mark.parametrize("version,key,name", [
        ("5.4", "verdaccio+4873/e2e-verdaccio/1.0.0", "e2e-verdaccio"),
        ("5.4", "verdaccio+4873/@myorg/pkg/1.0.0", "@myorg/pkg"),
        ("6.0", "nexus+8081/@myorg/pkg@1.0.0(react@18.2.0)", "@myorg/pkg"),
        ("5.4", "127.0.0.1+4873/x/1.0.0", "x"),
        ("5.4", "notahost/chalk/5.6.1", "chalk"),
    ])
    def test_a_dotless_host_is_a_registry_host(self, version, key, name):
        record = split_key(version, key, {}, {})
        assert (record.status, record.name, record.version, record.origin) == (NPM, name, "1.0.0" if "1.0.0" in key else "5.6.1", "registry-host")

    def test_a_colon_port_is_not_pnpms_host_encoding(self):
        assert split_key("5.4", "registry.example.com:4873/chalk/5.6.1", {}, {}).status == UNKNOWN

    def test_band_of_tolerates_surrounding_whitespace(self):
        assert band_of(" 5.4 ") == "v5"


class TestNoVersionIsNeverTheStringNone:
    """pnpmkeys.py:274-276, :337-339, :344-346 -- deleting any of them returns
    status `source` with the literal string 'None' as the version."""

    def test_v5v6_non_identity_key_with_a_named_but_unversioned_body(self):
        record = split_key("5.4", "github.com/owner/repo/7e4fef9abcdef", {"name": "repo"}, {})
        assert (record.status, record.name, record.version, record.origin) == (UNKNOWN, "repo", None, "git")
        assert record.reason == "body names the package but records no version"

    def test_v9_local_tarball_without_a_version(self):
        record = split_key("9.0", "xlsx@file:vendor/xlsx-0.20.3.tgz", {}, {})
        assert (record.status, record.version, record.origin) == (UNKNOWN, None, "local-tarball")
        assert record.reason == "local tarball with no version recorded"

    @pytest.mark.parametrize("key,origin", [
        ("vue@https://pkg.pr.new/vue@e1bc0eb", "remote-tarball"),
        ("x@git+https://github.com/o/r.git#abc", "git"),
        ("ags@https://codeload.github.com/aylur/ags/tar.gz/e169694", "git"),
    ])
    def test_v9_git_or_url_without_a_version(self, key, origin):
        record = split_key("9.0", key, {}, {})
        assert (record.status, record.version, record.origin) == (UNKNOWN, None, origin)
        assert record.reason == f"no version recorded for a {origin} dependency"


class TestTheProtocolTail:
    """pnpmkeys.py:348-364 and :248-249."""

    @pytest.mark.parametrize("key,alias", [("x@link:../foo", "link"), ("x@workspace:*", "workspace"),
                                           ("x@npm:other@1.0.0", "npm")])
    def test_an_unrecognised_protocol_is_unknown_even_with_a_body_version(self, key, alias):
        record = split_key("9.0", key, {"version": "1.0.0"}, {})
        assert (record.status, record.version, record.origin) == (UNKNOWN, None, "protocol:" + alias)
        assert record.reason.startswith("unrecognised protocol version")

    def test_a_version_part_that_is_nothing_recognisable_trusts_only_the_body(self):
        record = split_key("9.0", "x@1.0", {"version": "1.0.0"}, {})
        assert (record.status, record.version, record.version_from, record.origin) == (SOURCE, "1.0.0", "packages-body", "unknown")
        record = split_key("9.0", "x@1.0", {}, {})
        assert record.status == UNKNOWN and record.reason.startswith("version part is neither semver")

    @pytest.mark.parametrize("version,key", [("6.0", "/x@1.0.0)"), ("5.4", "/x/1.0.0)")])
    def test_an_unbalanced_parenthesis_is_unknown_not_a_crash_before_9_too(self, version, key):
        record = split_key(version, key, {}, {})
        assert record.status == UNKNOWN and "unbalanced" in record.reason


class TestTheBodyVersionOutranksTheKeyVersion:
    """pnpmkeys.py:265 and :324 -- the only inputs on which the rule's *version* half can fail."""

    def test_v5_host_key_with_a_body_that_disagrees_on_the_version(self):
        record = split_key("5.3", "registry.npmjs.org/q/1.5.1", {"name": "q", "version": "1.5.2"}, {})
        assert (record.version, record.version_from) == ("1.5.2", "body")

    def test_v9_snapshot_whose_packages_body_disagrees_with_the_key(self):
        record = split_key("9.0", "chalk@5.6.1(supports-color@9.0.0)", {}, {"chalk@5.6.1": {"version": "5.6.2"}})
        assert (record.version, record.version_from) == ("5.6.2", "packages-body")


class TestOriginFromTheResolutionBody:
    """pnpmkeys.py:221-233 (_origin_of), each clause on its own."""

    @pytest.mark.parametrize("version,key,entry", [
        ("6.0", "jihulab.com/james-curtis/vscode-loc/ddd7174069c9d981d0bacbc23fe74de3112ec706",
         {"name": "vscode-loc", "version": "0.0.0",
          "resolution": {"commit": "ddd7174069c9d981d0bacbc23fe74de3112ec706",
                         "repo": "https://jihulab.com/james-curtis/vscode-loc", "type": "git"}}),
        ("5.3", "git@bitbucket.org+my-org/my-bitbucket-project/6104ae42cd32c3d724036d3964678f197b2c9cdb",
         {"name": "my-bitbucket-package", "version": "1.0.0",
          "resolution": {"commit": "6104ae42cd32c3d724036d3964678f197b2c9cdb",
                         "repo": "git@bitbucket.org:my-org/my-bitbucket-project.git", "type": "git"}}),
    ])
    def test_a_git_host_outside_the_allow_list_is_git_by_its_resolution(self, version, key, entry):
        """Verbatim from the corpus (21 rows: jihulab.com, git@bitbucket.org+...)."""
        record = split_key(version, key, entry, {})
        assert (record.status, record.name, record.version, record.origin) == (SOURCE, entry["name"], entry["version"], "git")

    @pytest.mark.parametrize("resolution", [{"directory": "../pkg"}, {"type": "directory"}])
    def test_a_directory_is_known_by_either_field(self, resolution):
        record = split_key("5.4", "file:../pkg", {"name": "pkg", "resolution": resolution}, {})
        assert (record.status, record.origin) == (NOT_NPM, "local-dir")
        assert record.reason == "local directory link, not a published artifact"

    def test_a_codeload_tarball_is_git_whatever_the_key_says(self):
        entry = {"name": "repo", "version": "1.0.0",
                 "resolution": {"tarball": "https://codeload.github.com/owner/repo/tar.gz/abc123"}}
        assert split_key("5.4", "git@github.com+owner/repo/abc123", entry, {}).origin == "git"

    def test_a_remote_tarball_is_known_from_the_body_without_a_name(self):
        entry = {"resolution": {"tarball": "https://github.com/visionmedia/dox/tarball/master"}}
        record = split_key("5.4", "@github.com/visionmedia/dox/tarball/master", entry, {})
        assert (record.status, record.origin) == (UNKNOWN, "remote-tarball")

    def test_a_url_key_is_a_remote_tarball_even_without_a_resolution(self):
        assert split_key("5.4", "https://example.com/x-1.0.0.tgz", {"name": "x", "version": "1.0.0"}, {}).origin == "remote-tarball"

    def test_a_non_mapping_resolution_is_ignored_not_a_crash(self):
        assert split_key("5.4", "file:x", {"name": "x", "resolution": "garbage"}, {}).status == UNKNOWN
        assert split_key("9.0", "x@1.0.0", {"resolution": "garbage"}, {}).status == NPM


class TestNineFileAndGitSubClauses:
    """pnpmkeys.py:332-343."""

    def test_a_directory_with_a_version_is_still_not_npm(self):
        entry = {"version": "1.0.0", "resolution": {"type": "directory", "directory": "../dir"}}
        record = split_key("9.0", "x@file:../dir", entry, {})
        assert (record.status, record.version, record.origin) == (NOT_NPM, None, "local-dir")

    def test_a_bare_file_path_with_no_body_at_all_is_a_directory(self):
        record = split_key("9.0", "x@file:../dir", {}, None)
        assert (record.status, record.origin) == (NOT_NPM, "local-dir")

    def test_a_tgz_is_a_tarball_by_key_or_by_resolution(self):
        assert split_key("9.0", "x@file:vendor/pkg.tgz", {}, {}).origin == "local-tarball"
        assert split_key("9.0", "x@file:vendor/pkg", {"resolution": {"tarball": "file:vendor/pkg.tgz"}}, {}).origin == "local-tarball"

    @pytest.mark.parametrize("key,repo", [("x@ssh://git@host/r.git#abc", "ssh://git@host/r.git"),
                                          ("x@https://github.com/o/r.git#abc", "https://github.com/o/r.git")])
    def test_type_git_makes_a_git_origin_whatever_the_url_scheme(self, key, repo):
        entry = {"version": "1.0.0", "resolution": {"type": "git", "repo": repo, "commit": "abc"}}
        record = split_key("9.0", key, entry, {})
        assert (record.status, record.origin) == (SOURCE, "git")

    def test_a_codeload_url_is_git(self):
        entry = {"version": "3.1.0", "resolution": {"tarball": "https://codeload.github.com/aylur/ags/tar.gz/e169694"}}
        assert split_key("9.0", "ags@https://codeload.github.com/aylur/ags/tar.gz/e169694", entry, {}).origin == "git"

    def test_jsr_is_known_by_its_tarball_host_too(self):
        entry = {"resolution": {"tarball": "https://npm.jsr.io/~/11/@jsr/std__fs/1.0.24.tgz"}}
        record = split_key("9.0", "std__fs@1.0.24", entry, {})
        assert (record.status, record.origin) == (OTHER_REGISTRY, "jsr")


class TestMetadata:
    """pnpmkeys.py:250 (patched from the body alone) and :134 (nested groups)."""

    def test_a_5x_patch_is_known_only_from_the_body(self):
        key = "/sirv/2.0.2_w6q35pvk7bmykgqf2hieut43iq"
        assert split_key("5.4", key, {"patched": "true"}, {}).patched is True
        assert split_key("5.4", key, {}, {}).patched is False

    def test_nested_groups_are_peeled_as_one(self):
        assert suffix_groups("a@1.0.0(b@2.0.0(c@3.0.0))(d@4.0.0)") == ("a@1.0.0", ["b@2.0.0(c@3.0.0)", "d@4.0.0"])


class TestTheRegexGuardsInTheV5AndV6Parsers:
    """pnpmkeys.py:186-187 (`_NAME` half) and :214-215 (a line no existing test executes)."""

    def test_v6_rejects_a_non_semver_version(self):
        record = split_key("6.0", "/x@notsemver", {}, {})
        assert (record.status, record.name, record.version) == (UNKNOWN, None, None)

    @pytest.mark.parametrize("version,key", [("5.4", "/a b/1.0.0"), ("6.0", "/a b@1.0.0"), ("5.4", "/a@b/1.0.0")])
    def test_a_name_with_whitespace_or_a_stray_at_sign_is_not_a_name(self, version, key):
        assert split_key(version, key, {}, {}).status == UNKNOWN

class TestTheScanPathStillReachesNothing:
    def test_a_scan_does_not_import_the_splitter(self):
        """Nothing wires this in yet; when something does, it must be the lockfile
        parser and not the scan path importing it for free."""
        script = (
            "import sys, tempfile\n"
            f"sys.path[:0] = {sys.path!r}\n"
            "from deptrail.cli import main\n"
            "with tempfile.TemporaryDirectory() as d: main(['demo', '--workdir', d])\n"
            "sys.exit('imported' if 'deptrail.pnpmkeys' in sys.modules else 0)\n"
        )
        result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
        assert result.returncode == 0, result.stdout.strip() or result.stderr.strip()
