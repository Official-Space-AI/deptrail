"""The Yarn Berry reader: a whole ``yarn.lock`` (Yarn 2+) into a ``LockfileModel``.

What is tested is the document semantics on the shapes Berry really writes: identity
from ``resolution`` and never from the key, the locator protocols, aliasing through
the descriptor index, and the truncation guard. ``yarn-berry-babel-slice.lock`` is
``babel/babel``'s lockfile trimmed to eight entries -- a workspace root, two ``link:``
entries, an aliased row, a ``patch:`` row and three plain rows; the other two fixtures
are npm-only slices used by the YAML reader's own tests.
"""
from __future__ import annotations

import pathlib
import subprocess
import sys
import textwrap

import pytest

from deptrail.lockfile import NPM, ROOT, SOURCE, LockfileParseError
from deptrail.yarnberry import parse_yarn_berry_lockfile

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "yaml"

# Every real Berry lockfile records the project itself as a workspace entry, and the
# reader treats a document without one as truncated, so the shared head carries a
# minimal root the way the wild does.
HEAD = """\
            __metadata:
              version: 8
              cacheKey: 10

            "root@workspace:.":
              version: 0.0.0-use.local
              resolution: "root@workspace:."
              languageName: unknown
              linkType: soft

"""


def parse(text: str):
    return parse_yarn_berry_lockfile(textwrap.dedent(text))


def rows(model):
    return sorted((p.name, p.version, p.origin) for p in model.packages)


class TestWhatARowBecomes:
    def test_a_registry_row_is_named_by_its_resolution(self):
        model = parse(HEAD + """\
            "chalk@npm:^5.0.0, chalk@npm:^5.2.0":
              version: 5.6.1
              resolution: "chalk@npm:5.6.1"
              checksum: abc
              languageName: node
              linkType: hard
            """)
        assert rows(model) == [("chalk", "5.6.1", NPM)]
        assert model.packages[0].path == "chalk@npm:5.6.1"
        assert model.versions_of("chalk") == {"5.6.1"}
        assert model.unread == []

    def test_an_aliased_descriptor_is_the_package_it_resolves_to(self):
        """The key asks for an alias; the resolution answers with the real package."""
        model = parse(HEAD + """\
            "execa@npm:safe-execa@^0.1.2":
              version: 0.1.2
              resolution: "safe-execa@npm:0.1.2"
              languageName: node
              linkType: hard
            """)
        assert rows(model) == [("safe-execa", "0.1.2", NPM)]
        assert model.versions_of("execa") == set()

    def test_a_patch_row_is_the_artifact_it_patches(self):
        model = parse(HEAD + """\
            "fsevents@patch:fsevents@npm%3A2.3.3#optional!builtin<compat/fsevents>":
              version: 2.3.3
              resolution: "fsevents@patch:fsevents@npm%3A2.3.3#optional!builtin<compat/fsevents>::version=2.3.3&hash=df0bf1"
              languageName: node
              linkType: hard
            """)
        assert rows(model) == [("fsevents", "2.3.3", NPM)]

    def test_a_patch_of_a_patch_unwraps_to_the_bottom(self):
        """Three real rows wrap a patch in a patch."""
        model = parse(HEAD + """\
            "chalk@patch:chalk@patch%3Achalk@npm%253A5.6.1%23one.patch#two.patch":
              version: 5.6.1
              resolution: "chalk@patch:chalk@patch%3Achalk@npm%253A5.6.1%23one.patch#two.patch"
              languageName: node
              linkType: hard
            """)
        assert rows(model) == [("chalk", "5.6.1", NPM)]

    def test_a_git_or_https_row_is_source(self):
        model = parse(HEAD + """\
            "left-pad@https://github.com/left-pad/left-pad.git#commit=abc123":
              version: 1.3.0
              resolution: "left-pad@https://github.com/left-pad/left-pad.git#commit=abc123"
              languageName: node
              linkType: hard
            """)
        assert rows(model) == [("left-pad", "1.3.0", SOURCE)]
        assert model.versions_of("left-pad") == set(), "a git checkout is not the registry artifact"

    def test_a_workspace_entry_is_the_project_and_its_edges_are_roots(self):
        model = parse(HEAD + """\
            "app@workspace:.":
              version: 0.0.0-use.local
              resolution: "app@workspace:."
              dependencies:
                chalk: "npm:^5.0.0"
              languageName: unknown
              linkType: soft

            "chalk@npm:^5.0.0":
              version: 5.6.1
              resolution: "chalk@npm:5.6.1"
              languageName: node
              linkType: hard

            "local-tool@portal:./tools/local-tool::locator=app%40workspace%3A.":
              version: 0.0.0-use.local
              resolution: "local-tool@portal:./tools/local-tool::locator=app%40workspace%3A."
              dependencies:
                picocolors: "npm:^1.0.0"
              languageName: node
              linkType: soft

            "picocolors@npm:^1.0.0":
              version: 1.1.1
              resolution: "picocolors@npm:1.1.1"
              languageName: node
              linkType: hard
            """)
        assert rows(model) == [("chalk", "5.6.1", NPM), ("picocolors", "1.1.1", NPM)]
        assert model.root_deps == {"chalk", "picocolors"}, "a portal is the project too"
        assert model.chain_to("chalk") == ["chalk"]
        assert model.unread == []

    def test_a_condition_entry_is_a_switch_not_an_artifact(self):
        """Its variants are rows of their own; the switch contributes edges only."""
        model = parse(HEAD + """\
            "globals@condition:BABEL_8_BREAKING?^13.5.0:^11.1.0#365c0f":
              version: 0.0.0-condition-365c0f
              resolution: "globals@condition:BABEL_8_BREAKING?^13.5.0:^11.1.0#365c0f"
              dependencies:
                globals-BABEL_8_BREAKING-false: "npm:globals@^11.1.0"
                globals-BABEL_8_BREAKING-true: "npm:globals@^13.5.0"
              languageName: node
              linkType: hard

            "globals-BABEL_8_BREAKING-false@npm:globals@^11.1.0":
              version: 11.12.0
              resolution: "globals@npm:11.12.0"
              languageName: node
              linkType: hard

            "globals-BABEL_8_BREAKING-true@npm:globals@^13.5.0":
              version: 13.24.0
              resolution: "globals@npm:13.24.0"
              languageName: node
              linkType: hard
            """)
        assert model.versions_of("globals") == {"11.12.0", "13.24.0"}
        assert model.declared["globals"] == {"globals"}, "both variants resolve to the real name"
        assert model.unread == [], "a condition entry is read, not refused"

    def test_an_entry_without_a_version_is_unread(self):
        model = parse(HEAD + """\
            "chalk@npm:^5.0.0":
              resolution: "chalk@npm:5.6.1"
              languageName: node
              linkType: hard
            """)
        assert model.packages == []
        assert model.unread == ['chalk@npm:^5.0.0: entry records no version']

    def test_an_entry_without_a_resolution_is_unread(self):
        model = parse(HEAD + """\
            "chalk@npm:^5.0.0":
              version: 5.6.1
              languageName: node
              linkType: hard
            """)
        assert model.packages == []
        assert len(model.unread) == 1 and "no resolution" in model.unread[0]

    def test_a_bare_resolution_is_unread(self):
        model = parse(HEAD + """\
            "weird@npm:^1.0.0":
              version: 1.0.0
              resolution: "weird"
              languageName: node
              linkType: hard
            """)
        assert model.packages == []
        assert len(model.unread) == 1 and "is not a locator" in model.unread[0]

    def test_an_ssh_locator_is_source(self):
        model = parse(HEAD + """\
            "pkg@ssh://git@github.com/acme/pkg.git#commit=abc123":
              version: 2.0.0
              resolution: "pkg@ssh://git@github.com/acme/pkg.git#commit=abc123"
              languageName: node
              linkType: hard
            """)
        assert rows(model) == [("pkg", "2.0.0", SOURCE)]

    def test_a_dependencies_block_cut_to_nothing_is_unread(self):
        """A cut right after ``dependencies:`` parses the block to None; the edges
        that stood there are evidence this snapshot no longer holds."""
        model = parse(HEAD + """\
            "app@workspace:.":
              version: 0.0.0-use.local
              resolution: "app@workspace:."
              dependencies:
            """)
        assert len(model.unread) == 1
        assert "dependencies block did not parse" in model.unread[0]

    def test_a_dependency_cut_after_its_name_is_unread(self):
        model = parse(HEAD + """\
            "app@workspace:.":
              version: 0.0.0-use.local
              resolution: "app@workspace:."
              dependencies:
                chalk:
              languageName: unknown
              linkType: soft
            """)
        assert len(model.unread) == 1
        assert model.unread[0] == "app@workspace:.: the dependency 'chalk' carries no range"

    def test_a_protocol_less_resolution_without_a_path_is_not_a_shorthand(self):
        model = parse(HEAD + """\
            "weird@npm:^1.0.0":
              version: 1.0.0
              resolution: "weird@1.0.0"
              languageName: node
              linkType: hard
            """)
        assert model.packages == [], "a fabricated source row would read as evidence"
        assert len(model.unread) == 1 and "is not a locator" in model.unread[0]

    def test_a_blank_version_is_unread(self):
        model = parse(HEAD + """\
            "chalk@npm:^5.0.0":
              version: ""
              resolution: "chalk@npm:5.6.1"
              languageName: node
              linkType: hard
            """)
        assert model.packages == []
        assert model.unread == ["chalk@npm:^5.0.0: entry records no version"]

    def test_an_early_github_shorthand_is_source(self):
        """41 real resolutions carry no protocol: early Berry's GitHub shorthand."""
        for resolution in ("left-pad@left-pad/left-pad#commit:a1b2c3",
                           "babel-plugin-lazy-import@arcanis/babel-plugin-lazy-import"):
            model = parse(HEAD + f"""\
            "{resolution.split('@')[0]}@github-ish":
              version: 1.3.0
              resolution: "{resolution}"
              languageName: node
              linkType: hard
            """)
            assert [(p.name, p.origin) for p in model.packages] == [(resolution.split("@")[0], SOURCE)]

    def test_an_unknown_protocol_is_unread_not_guessed(self):
        model = parse(HEAD + """\
            "thing@exec:./build.js":
              version: 1.0.0
              resolution: "thing@exec:./build.js"
              languageName: node
              linkType: hard
            """)
        assert model.packages == []
        assert len(model.unread) == 1 and "protocol 'exec'" in model.unread[0]


class TestEdgesResolveThroughTheDescriptorIndex:
    def test_an_aliased_edge_lands_on_the_real_name(self):
        model = parse(HEAD + """\
            "app@workspace:.":
              version: 0.0.0-use.local
              resolution: "app@workspace:."
              dependencies:
                execa: "npm:safe-execa@^0.1.2"
              languageName: unknown
              linkType: soft

            "execa@npm:safe-execa@^0.1.2":
              version: 0.1.2
              resolution: "safe-execa@npm:0.1.2"
              languageName: node
              linkType: hard
            """)
        assert model.root_deps == {"safe-execa"}
        assert model.chain_to("safe-execa") == ["safe-execa"]
        assert model.unread == [], "a complete file with an alias is not truncated"

    def test_older_metadata_writes_ranges_bare(self):
        """Before metadata 8 the range has no ``npm:``; the descriptor does."""
        model = parse("""\
            __metadata:
              version: 4
              cacheKey: 7

            "app@workspace:.":
              version: 0.0.0-use.local
              resolution: "app@workspace:."
              dependencies:
                chalk: ^5.0.0
              languageName: unknown
              linkType: soft

            "chalk@npm:^5.0.0":
              version: 5.6.1
              resolution: "chalk@npm:5.6.1"
              dependencies:
                ansi-styles: ^4.1.0
              languageName: node
              linkType: hard

            "ansi-styles@npm:^4.1.0":
              version: 4.3.0
              resolution: "ansi-styles@npm:4.3.0"
              languageName: node
              linkType: hard
            """)
        assert model.root_deps == {"chalk"}
        assert model.declared["chalk"] == {"ansi-styles"}
        assert model.chain_to("ansi-styles") == ["chalk", "ansi-styles"]
        assert model.lockfile_version == "4"
        assert model.unread == []

    def test_a_pre_eight_aliased_bare_edge_lands_on_the_real_name(self):
        """The range is bare but the descriptor carries ``npm:``; only the second
        spelling finds it, and only the resolution names the row."""
        model = parse("""\
            __metadata:
              version: 4
              cacheKey: 7

            "app@workspace:.":
              version: 0.0.0-use.local
              resolution: "app@workspace:."
              dependencies:
                execa: safe-execa@^0.1.2
              languageName: unknown
              linkType: soft

            "execa@npm:safe-execa@^0.1.2":
              version: 0.1.2
              resolution: "safe-execa@npm:0.1.2"
              languageName: node
              linkType: hard
            """)
        assert model.root_deps == {"safe-execa"}
        assert model.unread == []

    def test_an_edge_answered_by_the_second_descriptor_of_a_comma_joined_key(self):
        model = parse(HEAD + """\
            "app@workspace:.":
              version: 0.0.0-use.local
              resolution: "app@workspace:."
              dependencies:
                execa: "npm:safe-execa@^0.2.0"
              languageName: unknown
              linkType: soft

            "safe-execa@npm:^0.1.2, execa@npm:safe-execa@^0.2.0":
              version: 0.2.0
              resolution: "safe-execa@npm:0.2.0"
              languageName: node
              linkType: hard
            """)
        assert model.root_deps == {"safe-execa"}
        assert model.unread == []


class TestATruncatedDocumentIsNotACleanOne:
    """The same YAML prefix-validity that bit pnpm: entries are alphabetical, so a cut
    file keeps early entries whose edges point at nothing."""

    def test_an_edge_no_entry_answers_is_unread(self):
        model = parse(HEAD + """\
            "app@workspace:.":
              version: 0.0.0-use.local
              resolution: "app@workspace:."
              dependencies:
                chalk: "npm:^5.0.0"
              languageName: unknown
              linkType: soft
            """)
        assert model.packages == []
        assert model.unread == ["chalk: the document resolves it to 'npm:^5.0.0' and "
                                "holds no entry for it"]

    def test_an_overridden_range_backed_by_the_name_is_no_finding(self):
        """`resolutions:` overrides leave the requested range unanswered while the
        package is present under another descriptor -- 57,527 real edges do this."""
        model = parse(HEAD + """\
            "app@workspace:.":
              version: 0.0.0-use.local
              resolution: "app@workspace:."
              dependencies:
                browserslist: "npm:^4.22.2"
              languageName: unknown
              linkType: soft

            "browserslist@npm:4.24.0":
              version: 4.24.0
              resolution: "browserslist@npm:4.24.0"
              languageName: node
              linkType: hard
            """)
        assert model.unread == []
        assert model.versions_of("browserslist") == {"4.24.0"}

    def test_a_document_that_already_has_unread_rows_does_not_double_report(self):
        model = parse(HEAD + """\
            "app@workspace:.":
              version: 0.0.0-use.local
              resolution: "app@workspace:."
              dependencies:
                chalk: "npm:^5.0.0"
              languageName: unknown
              linkType: soft

            "weird@npm:^1.0.0":
              version: 1.0.0
              resolution: "weird"
              languageName: node
              linkType: hard
            """)
        assert len(model.unread) == 1 and model.unread[0].startswith("weird@npm:")


class TestWhatIsRefused:
    @pytest.mark.parametrize("text, fragment", [
        ("", "expected one document"),
        ("- a\n- b\n", "is a mapping"),
        ("chalk@npm:5.6.1:\n  version: 5.6.1\n", "no __metadata"),
        ("__metadata:\n  version:\n", "carries no version"),
        ("# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n"
         "# yarn lockfile v1\n", "one document"),
    ])
    def test_the_text_is_not_a_berry_lockfile(self, text, fragment):
        with pytest.raises(LockfileParseError) as error:
            parse_yarn_berry_lockfile(text)
        assert fragment in str(error.value)


class TestAgainstTheFixtureLockfiles:
    def test_the_babel_slice_reads_every_shape_at_once(self):
        model = parse_yarn_berry_lockfile(
            FIXTURES.joinpath("yarn-berry-babel-slice.lock").read_text(encoding="utf-8"))
        assert model.lockfile_version == "10"
        assert model.unread == []
        assert rows(model) == [
            ("@babel/cli", "7.27.1", NPM),          # via the @babel-baseline alias
            ("@rollup/plugin-commonjs", "29.0.2", NPM),  # via patch:
            ("ansi-styles", "4.3.0", NPM),
            ("chalk", "2.4.2", NPM),
            ("picocolors", "1.1.1", NPM),
        ]
        assert model.root_deps == {"$repo-utils", "@babel/cli", "@rollup/plugin-commonjs"}
        assert model.declared["chalk"] == {"ansi-styles"}

    @pytest.mark.parametrize("name, version, count", [
        ("yarn-berry.lock", "10", 10), ("yarn-berry-v4.lock", "4", 9),
    ])
    def test_the_reader_fixtures_parse_every_row_they_hold(self, name, version, count):
        """These two are the YAML reader's slices, cut without regard for edge targets
        or the workspace entry, so the truncation guards rightly report both."""
        model = parse_yarn_berry_lockfile(FIXTURES.joinpath(name).read_text(encoding="utf-8"))
        assert model.lockfile_version == version
        assert len(model.packages) == count
        assert all(p.origin == NPM for p in model.packages)
        assert any("holds no workspace entry" in message for message in model.unread)
        assert all("holds no entry for it" in message or "no resolution" in message
                   or "holds no workspace entry" in message
                   for message in model.unread), model.unread

    def test_a_closed_prefix_without_the_project_is_not_a_clean_tree(self):
        """A cut can leave an alphabetical run that references only itself -- 2,007 of
        jest's 2,025 rows vanished behind a clean model until the workspace check."""
        model = parse("""\
            __metadata:
              version: 8
              cacheKey: 10

            "@algolia/cache-common@npm:4.13.1":
              version: 4.13.1
              resolution: "@algolia/cache-common@npm:4.13.1"
              languageName: node
              linkType: hard

            "@algolia/cache-in-memory@npm:4.13.1":
              version: 4.13.1
              resolution: "@algolia/cache-in-memory@npm:4.13.1"
              dependencies:
                "@algolia/cache-common": "npm:4.13.1"
              languageName: node
              linkType: hard
            """)
        assert len(model.packages) == 2, "the surviving rows are still read"
        assert model.unread == ["the document holds no workspace entry; every Berry "
                               "lockfile records its own project, so the rest of this "
                               "one is missing"]

    def test_every_fixture_entry_is_accounted_for(self):
        """Entries == rows + unread + project entries + condition entries, counted
        from the raw document."""
        from deptrail.yamlsubset import load
        for name in ("yarn-berry-babel-slice.lock", "yarn-berry.lock", "yarn-berry-v4.lock"):
            text = FIXTURES.joinpath(name).read_text(encoding="utf-8")
            model = parse_yarn_berry_lockfile(text)
            document = load(text)
            entries = [k for k in document if k != "__metadata"]
            resolutions = [document[k].get("resolution", "") if isinstance(document[k], dict)
                           else "" for k in entries]
            project = sum(1 for r in resolutions
                          if any(p in r for p in ("@workspace:", "@link:", "@portal:")))
            condition = sum(1 for r in resolutions if "@condition:" in r)
            guard = sum(1 for m in model.unread if "holds no entry for it" in m
                        or "holds no workspace entry" in m)
            assert len(model.packages) + (len(model.unread) - guard) + project + condition \
                == len(entries), name


class TestTheScanPathStillReachesNothing:
    def test_a_scan_does_not_import_the_berry_reader(self):
        """history.py does not read yarn.lock yet; the wiring (and the Yarn 1
        sniffing it needs) is its own change and must import this deliberately."""
        script = (
            "import sys, tempfile\n"
            f"sys.path[:0] = {sys.path!r}\n"
            "from deptrail.cli import main\n"
            "with tempfile.TemporaryDirectory() as d: main(['demo', '--workdir', d])\n"
            "sys.exit('imported' if 'deptrail.yarnberry' in sys.modules else 0)\n"
        )
        result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
        assert result.returncode == 0, result.stdout.strip() or result.stderr.strip()
