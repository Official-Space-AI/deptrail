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

    def test_a_host_needs_a_dot_or_to_be_localhost(self):
        """`chalk/5.6.1` (no leading slash, no dot) is not `host=chalk`; it is not a
        registry shape at all and falls through to the body."""
        assert split_key("5.4", "chalk/5.6.1", {}, {}).status == UNKNOWN
        record = split_key("5.4", "localhost+4873/chalk/5.6.1", {}, {})
        assert (record.status, record.name, record.origin) == (NPM, "chalk", "registry-host")
        record = split_key("6.0", "registry.npmmirror.com/immer@10.0.3", {}, {})
        assert (record.status, record.name, record.version) == (NPM, "immer", "10.0.3")

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

    def test_every_key_in_every_fixture_splits_to_a_known_status(self):
        for path in sorted(FIXTURES.joinpath("yaml").glob("pnpm-*.yaml")):
            for document in load_documents(path.read_text(encoding="utf-8")):
                packages = document.get("packages") or {}
                for section in (packages, document.get("snapshots") or {}):
                    for key, entry in section.items():
                        record = split_key(document["lockfileVersion"], key, entry, packages)
                        assert record.status != UNKNOWN, (path.name, key, record.reason)


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
