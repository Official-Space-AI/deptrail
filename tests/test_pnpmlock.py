"""The pnpm document reader: a whole ``pnpm-lock.yaml`` into a ``LockfileModel``.

The key splitter is tested in ``test_pnpmkeys``; what is tested here is everything the
document adds around the keys -- which rows become packages, where edges come from, what
the project depends on, what happens to a row that will not read -- each on the shape
pnpm really writes. Two fixtures are real files: ``pnpm-v9-header-lies.yaml`` is
``smartcontractkit/payment-abstraction`` trimmed to seven rows, a 9.0 header over 6.x
keys; ``pnpm-v9-mixed-keys.yaml`` is a published test fixture with eleven 9.0 keys and
two legacy ones, the case that forbids re-reading per key.
"""
from __future__ import annotations

import pathlib
import subprocess
import sys
import textwrap

import pytest

from deptrail.lockfile import (NOT_NPM, NPM, OTHER_REGISTRY, ROOT, SOURCE, LockfileParseError)
from deptrail.pnpmkeys import split_key, suffix_groups
from deptrail.pnpmlock import parse_pnpm_lockfile
from deptrail.yamlsubset import load_documents

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "yaml"


def parse(text: str):
    return parse_pnpm_lockfile(textwrap.dedent(text))


def rows(model):
    return sorted((p.name, p.version, p.origin, p.path) for p in model.packages)


V6_HEAD = """\
    lockfileVersion: '6.0'

    dependencies:
      chalk:
        specifier: ^5.0.0
        version: 5.6.1

    packages:
    """


class TestWhatARowBecomes:
    def test_a_registry_row_is_a_package_whose_path_is_the_key(self):
        model = parse(V6_HEAD + """
              /chalk@5.6.1:
                resolution: {integrity: sha512-x}
                dev: false
            """)
        assert rows(model) == [("chalk", "5.6.1", NPM, "/chalk@5.6.1")]
        assert model.versions_of("chalk") == {"5.6.1"}
        assert model.unread == []

    def test_a_git_row_is_source_and_named_by_its_body(self):
        model = parse(V6_HEAD + """
              github.com/watson/ci-info/f43f6a1cefff47fb361c88cf4b943fdbcaafe540:
                resolution: {tarball: https://codeload.github.com/watson/ci-info/tar.gz/f43f6a1cefff47fb361c88cf4b943fdbcaafe540}
                name: ci-info
                version: 2.0.0
                dev: false
            """)
        assert rows(model) == [("ci-info", "2.0.0", SOURCE,
                                "github.com/watson/ci-info/f43f6a1cefff47fb361c88cf4b943fdbcaafe540")]
        assert model.versions_of("ci-info") == set(), "a tarball is not the registry's 2.0.0"

    def test_a_jsr_row_is_another_registry_and_still_answers(self):
        model = parse("""\
            lockfileVersion: '9.0'

            packages:

              '@jsr/std__assert@1.0.19':
                resolution: {integrity: sha512-x, tarball: https://npm.jsr.io/~/11/@jsr/std__assert/1.0.19.tgz}

            snapshots:

              '@jsr/std__assert@1.0.19': {}
            """)
        assert rows(model) == [("@jsr/std__assert", "1.0.19", OTHER_REGISTRY, "@jsr/std__assert@1.0.19")]
        assert model.versions_of("@jsr/std__assert") == {"1.0.19"}

    def test_a_runtime_row_is_not_npm_and_keeps_its_version(self):
        model = parse("""\
            lockfileVersion: '9.0'

            packages:

              node@runtime:26.7.0:
                resolution: {type: variations, variants: []}
                version: 26.7.0

            snapshots:

              node@runtime:26.7.0: {}
            """)
        assert rows(model) == [("node", "26.7.0", NOT_NPM, "node@runtime:26.7.0")]
        assert model.versions_of("node") == set(), "node the runtime is not node the npm package"

    def test_a_local_directory_has_no_row_and_keeps_its_edges(self):
        model = parse(V6_HEAD + """
              file:playground/alias/dir/module:
                resolution: {directory: playground/alias/dir/module, type: directory}
                name: '@vitejs/test-aliased-module'
                dependencies:
                  chalk: 5.6.1
                dev: false

              /chalk@5.6.1:
                resolution: {integrity: sha512-x}
            """)
        assert rows(model) == [("chalk", "5.6.1", NPM, "/chalk@5.6.1")]
        assert model.declared["@vitejs/test-aliased-module"] == {"chalk"}
        assert model.unread == [], "a local directory was read; it just is not a package"

    def test_a_nameless_local_directory_contributes_nothing(self):
        model = parse(V6_HEAD + """
              file:../nameless-package:
                resolution: {directory: ../nameless-package, type: directory}
                version: 1.0.0
                dependencies:
                  chalk: 5.6.1

              /chalk@5.6.1:
                resolution: {integrity: sha512-x}
            """)
        assert rows(model) == [("chalk", "5.6.1", NPM, "/chalk@5.6.1")]
        assert set(model.declared) == {ROOT, "chalk"}
        assert model.unread == []

    def test_an_unreadable_row_is_reported_with_its_reason_and_nothing_else_is_lost(self):
        model = parse(V6_HEAD + """
              /chalk@5.6.1:
                resolution: {integrity: sha512-x}

              /what@is@this:
                resolution: {integrity: sha512-y}
            """)
        assert rows(model) == [("chalk", "5.6.1", NPM, "/chalk@5.6.1")]
        assert len(model.unread) == 1
        assert model.unread[0].startswith("/what@is@this: ")

    def test_a_blank_body_version_is_unread_not_an_empty_version(self):
        model = parse(V6_HEAD + """
              /chalk@5.6.1:
                resolution: {integrity: sha512-x}
                name: chalk
                version: ''
            """)
        assert model.packages == []
        assert model.unread == ["/chalk@5.6.1: body version is blank"]

    def test_a_body_version_that_is_not_text_is_unread_not_a_version(self):
        model = parse(V6_HEAD + """
              /chalk@5.6.1:
                resolution: {integrity: sha512-x}
                version: {x: 1}
            """)
        assert model.packages == []
        assert model.unread == ["/chalk@5.6.1: body version is a dict, not a string"]


class TestTheThreeBands:
    @pytest.mark.parametrize("version, key", [
        ("5.4", "/chalk/5.6.1"), ("5", "/chalk/5.6.1"), ("5.3-inlineSpecifiers", "/chalk/5.6.1"),
        ("'6.0'", "/chalk@5.6.1"), ("'6.1'", "/chalk@5.6.1"), ("'9.0'", "chalk@5.6.1"),
    ])
    def test_each_band_reads_chalk(self, version, key):
        model = parse(f"""\
            lockfileVersion: {version}

            packages:

              {key}:
                resolution: {{integrity: sha512-x}}
            """)
        assert model.versions_of("chalk") == {"5.6.1"}
        assert model.lockfile_version == version.strip("'")

    def test_the_old_layout_with_lockfile_version_at_the_end(self):
        """pnpm 3 wrote the header last; the reader does not care where it is."""
        model = parse("""\
            dependencies:
              chalk: 5.6.1
            specifiers:
              chalk: ^5.0.0
            packages:
              /chalk/5.6.1:
                resolution: {integrity: sha512-x}
            lockfileVersion: 5.1
            """)
        assert model.lockfile_version == "5.1"
        assert model.root_deps == {"chalk"}
        assert model.versions_of("chalk") == {"5.6.1"}


class TestNineRowsComeFromPackagesAndEdgesFromSnapshots:
    DOC = """\
        lockfileVersion: '9.0'

        importers:

          .:
            dependencies:
              trpc:
                specifier: ^1.0.0
                version: 1.0.0(react@18.3.1)
              react:
                specifier: ^18.0.0
                version: 18.3.1

        packages:

          trpc@1.0.0:
            resolution: {integrity: sha512-a}
            peerDependencies:
              react: '*'

          react@18.3.1:
            resolution: {integrity: sha512-b}

          react@17.0.2:
            resolution: {integrity: sha512-c}

          loose-envify@1.4.0:
            resolution: {integrity: sha512-d}

          scheduler@0.23.0:
            resolution: {integrity: sha512-e}

        snapshots:

          trpc@1.0.0(react@18.3.1):
            dependencies:
              react: 18.3.1

          trpc@1.0.0(react@17.0.2):
            dependencies:
              react: 17.0.2
              scheduler: 0.23.0

          react@18.3.1:
            dependencies:
              loose-envify: 1.4.0

          react@17.0.2:
            dependencies:
              loose-envify: 1.4.0

          loose-envify@1.4.0: {}
          scheduler@0.23.0: {}
        """

    def test_one_row_per_packages_entry_however_many_peer_variants(self):
        model = parse(self.DOC)
        assert [(p.name, p.version) for p in model.packages] == [
            ("trpc", "1.0.0"), ("react", "18.3.1"), ("react", "17.0.2"), ("loose-envify", "1.4.0"),
            ("scheduler", "0.23.0")]
        assert model.versions_of("react") == {"18.3.1", "17.0.2"}

    def test_edges_are_the_union_over_the_variants(self):
        """Only the react@17 variant of trpc depends on scheduler; the edge is trpc's
        whichever variant was installed, so it is kept."""
        model = parse(self.DOC)
        assert model.declared["trpc"] == {"react", "scheduler"}
        assert model.declared["react"] == {"loose-envify"}
        assert model.chain_to("loose-envify") == ["react", "loose-envify"]
        assert model.chain_to("scheduler") == ["trpc", "scheduler"]

    def test_a_snapshot_whose_base_has_no_packages_entry_is_still_a_row(self):
        model = parse("""\
            lockfileVersion: '9.0'

            packages:

              react@18.3.1:
                resolution: {integrity: sha512-b}

            snapshots:

              react@18.3.1: {}

              orphan@2.0.0(react@18.3.1):
                dependencies:
                  react: 18.3.1
            """)
        assert rows(model) == [("orphan", "2.0.0", NPM, "orphan@2.0.0(react@18.3.1)"),
                               ("react", "18.3.1", NPM, "react@18.3.1")]
        assert model.declared["orphan"] == {"react"}

    def test_a_key_present_in_both_sections_is_one_row(self):
        model = parse("""\
            lockfileVersion: '9.0'

            packages:

              foo@1.0.0(bar@2.0.0):
                resolution: {integrity: sha512-a}

            snapshots:

              foo@1.0.0(bar@2.0.0): {}
            """)
        assert rows(model) == [("foo", "1.0.0", NPM, "foo@1.0.0(bar@2.0.0)")]

    def test_a_packages_entry_that_carries_edges_is_read_too(self):
        """64 of 467,116 real 9.0 ``packages:`` entries have a dependencies block."""
        model = parse("""\
            lockfileVersion: '9.0'

            packages:

              a@1.0.0:
                resolution: {integrity: sha512-a}
                dependencies:
                  b: 1.0.0

              b@1.0.0:
                resolution: {integrity: sha512-b}

            snapshots:

              a@1.0.0: {}
              b@1.0.0: {}
            """)
        assert model.declared["a"] == {"b"}


class TestTheHeaderCanLie:
    def test_a_nine_header_over_six_keys_is_read_under_the_six_grammar(self):
        model = parse_pnpm_lockfile(FIXTURES.joinpath("pnpm-v9-header-lies.yaml").read_text())
        assert model.lockfile_version == "9.0", "the model reports what the file declares"
        assert model.unread == []
        assert model.versions_of("solhint") == {"5.0.5"}
        assert model.versions_of("@babel/code-frame") == {"7.26.2"}
        assert rows(model)[2] == ("@chainlink/solhint-plugin-chainlink-solidity", "1.2.0", SOURCE,
                                  "github.com/smartcontractkit/chainlink-solhint-rules/"
                                  "1b4c0c2663fcd983589d4f33a2e73908624ed43c")

    def test_the_key_that_is_not_a_slash_key_is_what_the_literal_rule_missed(self):
        """The git key refuses under 9.0 for a different reason than the other 157, so a
        rule on the reason string never re-read this file (#79)."""
        document = load_documents(FIXTURES.joinpath("pnpm-v9-header-lies.yaml").read_text())[0]
        reasons = {split_key("9.0", key, entry, document["packages"]).reason
                   for key, entry in document["packages"].items()}
        assert len(reasons) == 2

    def test_the_importer_edge_to_the_git_dependency_resolves_to_the_name_it_installs(self):
        model = parse_pnpm_lockfile(FIXTURES.joinpath("pnpm-v9-header-lies.yaml").read_text())
        assert model.root_deps == {"solhint", "@chainlink/solhint-plugin-chainlink-solidity",
                                   "lcov-parse"}
        assert model.chain_to("@chainlink/solhint-plugin-chainlink-solidity") is None, \
            "a source row is not an advisory target"
        assert model.chain_to("solhint") == ["solhint"]
        assert model.chain_to("picocolors") == ["picocolors"], \
            "the trimmed fixture keeps no declarer of @babel/code-frame, so the orphan fallback"

    def test_a_genuinely_mixed_document_keeps_its_nine_rows_and_reports_the_legacy_keys(self):
        model = parse_pnpm_lockfile(FIXTURES.joinpath("pnpm-v9-mixed-keys.yaml").read_text())
        assert len(model.packages) == 11
        assert model.versions_of("kleur") == {"4.1.5", "3.0.3"}
        assert model.unread == [
            "/legacy-package/1.2.3_peer@2.0.0: v5/v6-style key in a document declaring "
            "lockfileVersion 9.0",
            "/@legacy/scope/4.5.6_peer@2.0.0: v5/v6-style key in a document declaring "
            "lockfileVersion 9.0",
        ]

    def test_a_document_no_grammar_reads_is_all_unread_not_re_read(self):
        model = parse("""\
            lockfileVersion: '9.0'

            packages:

              '@@@':
                resolution: {integrity: sha512-a}

              what is this:
                resolution: {integrity: sha512-b}
            """)
        assert model.packages == []
        assert len(model.unread) == 2
        assert all("separator" in m or "implausible" in m for m in model.unread), \
            "the reasons are the declared grammar's, not the legacy grammar's"

    def test_re_reading_happens_only_when_nothing_read_under_nine(self):
        model = parse("""\
            lockfileVersion: '9.0'

            packages:

              chalk@5.6.1:
                resolution: {integrity: sha512-a}

              /ansi-styles@6.2.1:
                resolution: {integrity: sha512-b}

            snapshots:

              chalk@5.6.1: {}
            """)
        assert rows(model) == [("chalk", "5.6.1", NPM, "chalk@5.6.1")]
        assert len(model.unread) == 1 and model.unread[0].startswith("/ansi-styles@6.2.1: ")

    def test_re_reading_keeps_every_row_the_nine_pass_took_from_snapshots(self):
        """Re-reading under 6.0 used to look at ``packages:`` only, so three rows that
        the 9.0 pass had as unread were simply gone -- no row, no unread, a clean tree."""
        model = parse("""\
            lockfileVersion: '9.0'

            packages:

              /chalk@5.6.1:
                resolution: {integrity: sha512-a}

            snapshots:

              /lodash@4.17.21:
                dependencies:
                  ms: 2.1.3

              '@@@': {}

              /ms@2.1.3: {}
            """)
        assert rows(model) == [("chalk", "5.6.1", NPM, "/chalk@5.6.1"),
                               ("lodash", "4.17.21", NPM, "/lodash@4.17.21"),
                               ("ms", "2.1.3", NPM, "/ms@2.1.3")]
        assert model.declared["lodash"] == {"ms"}
        assert len(model.unread) == 1 and model.unread[0].startswith("@@@: ")

    def test_re_reading_needs_one_legacy_key_to_read_not_all_of_them(self):
        """Requiring every key to read under the legacy grammar would leave a document
        with one garbage key wholly unread, when 157 of its rows were there to be had."""
        model = parse("""\
            lockfileVersion: '9.0'

            packages:

              /chalk@5.6.1:
                resolution: {integrity: sha512-a}

              /ansi-styles@6.2.1:
                resolution: {integrity: sha512-b}

              what is this:
                resolution: {integrity: sha512-c}
            """)
        assert model.versions_of("chalk") == {"5.6.1"}
        assert model.versions_of("ansi-styles") == {"6.2.1"}
        assert len(model.unread) == 1 and model.unread[0].startswith("what is this: ")


class TestWhatTheProjectDependsOn:
    def test_without_importers_the_document_is_the_importer(self):
        model = parse("""\
            lockfileVersion: 5.4

            specifiers:
              chalk: ^5.0.0
              vitest: ^0.20.0
              '@types/node': ^18.0.0

            dependencies:
              chalk: 5.6.1

            devDependencies:
              vitest: 0.20.3
              '@types/node': 18.15.0

            packages:

              /chalk/5.6.1:
                resolution: {integrity: sha512-a}

              /vitest/0.20.3:
                resolution: {integrity: sha512-b}

              /@types/node/18.15.0:
                resolution: {integrity: sha512-c}
            """)
        assert model.root_deps == {"chalk", "vitest", "@types/node"}
        assert model.declared[ROOT] == model.root_deps

    def test_every_importer_of_a_workspace_is_the_root(self):
        """Each workspace package was installed by the same ``pnpm install``; a
        compromised dev dependency of any of them ran."""
        model = parse("""\
            lockfileVersion: '6.0'

            importers:

              .:
                devDependencies:
                  prettier:
                    specifier: ^3.0.0
                    version: 3.0.3

              packages/web:
                dependencies:
                  chalk:
                    specifier: ^5.0.0
                    version: 5.6.1
                  '@acme/ui':
                    specifier: workspace:*
                    version: link:../ui

              packages/ui:
                dependencies:
                  react:
                    specifier: ^18.0.0
                    version: 18.3.1

            packages:

              /prettier@3.0.3:
                resolution: {integrity: sha512-a}

              /chalk@5.6.1:
                resolution: {integrity: sha512-b}

              /react@18.3.1:
                resolution: {integrity: sha512-c}
            """)
        assert model.root_deps == {"prettier", "chalk", "@acme/ui", "react"}
        assert model.chain_to("react") == ["react"]

    def test_an_aliased_dependency_is_the_package_it_installs(self):
        model = parse("""\
            lockfileVersion: '6.0'

            importers:

              .:
                dependencies:
                  react-17:
                    specifier: npm:react@17.0.2
                    version: /react@17.0.2
                  execa:
                    specifier: npm:safe-execa@0.1.2
                    version: /safe-execa@0.1.2(typescript@5.2.2)

            packages:

              /react@17.0.2:
                resolution: {integrity: sha512-a}

              /safe-execa@0.1.2(typescript@5.2.2):
                resolution: {integrity: sha512-b}

              /typescript@5.2.2:
                resolution: {integrity: sha512-c}
            """)
        assert model.root_deps == {"react", "safe-execa"}
        assert model.versions_of("execa") == set()
        assert model.chain_to("safe-execa") == ["safe-execa"]

    def test_pnpm_twelve_pins_its_own_install_as_an_importer_block(self):
        model = parse_pnpm_lockfile(FIXTURES.joinpath("pnpm-v9-two-documents.yaml").read_text())
        assert "pnpm" in model.root_deps
        assert model.versions_of("pnpm") == {"12.0.0-rc.7"}

    def test_a_five_importer_lists_versions_and_its_specifiers_are_not_read(self):
        """``specifiers`` names an aliased dependency by its alias; ``dependencies``
        resolves it. Reading both put ``@popperjs/core`` next to ``@sxzz/popperjs-es``
        in the roots of ``element-plus``, and a chain to the real ``@popperjs/core``,
        had it been installed transitively, would have stopped there."""
        five = parse("""\
            lockfileVersion: 5.4

            importers:

              .:
                dependencies:
                  chalk: 5.6.1
                  tslint: 6.1.2_typescript@3.9.3
                  '@popperjs/core': /@sxzz/popperjs-es/2.11.6
                specifiers:
                  chalk: ^5.0.0
                  tslint: ^6.0.0
                  '@popperjs/core': npm:@sxzz/popperjs-es@^2.11.6
                  unresolved: ^1.0.0

            packages:

              /chalk/5.6.1:
                resolution: {integrity: sha512-a}

              /@sxzz/popperjs-es/2.11.6:
                resolution: {integrity: sha512-b}
            """)
        assert five.root_deps == {"chalk", "tslint", "@sxzz/popperjs-es"}


class TestEdgesResolveToWhatTheyInstall:
    def test_an_alias_edge_inside_a_package(self):
        model = parse(V6_HEAD + """
              /chalk@5.6.1:
                resolution: {integrity: sha512-a}
                dependencies:
                  execa: /safe-execa@0.1.2
                  ansi-styles: 6.2.1

              /safe-execa@0.1.2:
                resolution: {integrity: sha512-b}

              /ansi-styles@6.2.1:
                resolution: {integrity: sha512-c}
            """)
        assert model.declared["chalk"] == {"safe-execa", "ansi-styles"}
        assert model.chain_to("safe-execa") == ["chalk", "safe-execa"]

    def test_a_git_edge_resolves_through_the_body_of_the_row_it_points_at(self):
        model = parse(V6_HEAD + """
              /chalk@5.6.1:
                resolution: {integrity: sha512-a}
                dependencies:
                  '@rari-capital/solmate': github.com/transmissions11/solmate/8f9b23f8838670afda0fd8983f2c41e8037ae6bc

              github.com/transmissions11/solmate/8f9b23f8838670afda0fd8983f2c41e8037ae6bc:
                resolution: {tarball: https://codeload.github.com/transmissions11/solmate/tar.gz/8f9b23f8838670afda0fd8983f2c41e8037ae6bc}
                name: solmate
                version: 6.2.0
            """)
        assert model.declared["chalk"] == {"solmate"}

    def test_a_version_that_happens_to_look_like_a_key_is_not_one(self):
        """A 5.x edge value with a peer suffix contains ``@``; only a value that is a key
        of the document is a dep-path."""
        model = parse("""\
            lockfileVersion: 5.4

            packages:

              /ts-node/8.10.1_typescript@3.9.3:
                resolution: {integrity: sha512-a}
                dependencies:
                  typescript: 3.9.3
                  tslib: 1.14.1_typescript@3.9.3

              /typescript/3.9.3:
                resolution: {integrity: sha512-b}
            """)
        assert model.declared["ts-node"] == {"typescript", "tslib"}

    def test_an_edge_to_a_dep_path_that_is_not_in_the_document_keeps_its_name(self):
        model = parse(V6_HEAD + """
              /chalk@5.6.1:
                resolution: {integrity: sha512-a}
                dependencies:
                  execa: /safe-execa@0.1.2
            """)
        assert model.declared["chalk"] == {"execa"}

    def test_a_nine_snapshot_alias_edge(self):
        model = parse("""\
            lockfileVersion: '9.0'

            packages:

              chalk@5.6.1:
                resolution: {integrity: sha512-a}

              safe-execa@0.1.2:
                resolution: {integrity: sha512-b}

            snapshots:

              chalk@5.6.1:
                dependencies:
                  execa: safe-execa@0.1.2

              safe-execa@0.1.2: {}
            """)
        assert model.declared["chalk"] == {"safe-execa"}

    def test_link_and_workspace_values_keep_the_declared_name(self):
        model = parse("""\
            lockfileVersion: '9.0'

            importers:

              .:
                dependencies:
                  '@acme/ui':
                    specifier: workspace:*
                    version: link:packages/ui

            packages: {}

            snapshots: {}
            """)
        assert model.root_deps == {"@acme/ui"}
        assert model.packages == []


class TestShapesTheCorpusDoesNotHave:
    """Each of these is a mutation of the reader that every real lockfile survived."""

    def test_an_unreadable_snapshot_with_edges_does_not_declare_under_no_name(self):
        model = parse("""\
            lockfileVersion: '9.0'

            packages:

              chalk@5.6.1:
                resolution: {integrity: sha512-a}

            snapshots:

              chalk@5.6.1: {}

              '@@@':
                dependencies:
                  chalk: 5.6.1
            """)
        assert None not in model.declared
        assert set(model.declared) == {ROOT, "chalk"}
        assert len(model.unread) == 1

    def test_an_edge_value_that_is_not_text_keeps_the_declared_name(self):
        model = parse(V6_HEAD + """
              /chalk@5.6.1:
                resolution: {integrity: sha512-a}
                dependencies:
                  a: [1, 2]
                  b: {x: 1}
                  c: ~
            """)
        assert model.declared["chalk"] == {"a", "b", "c"}

    def test_a_nine_alias_whose_value_is_a_snapshot_key_with_a_peer_suffix(self):
        """The alias value carries the peer suffix, so it is a key of ``snapshots:`` and
        not of ``packages:``; 20 of 176 sampled files have one."""
        model = parse("""\
            lockfileVersion: '9.0'

            importers:

              .:
                dependencies:
                  chalk:
                    specifier: ^5.0.0
                    version: 5.6.1

            packages:

              chalk@5.6.1:
                resolution: {integrity: sha512-a}

              safe-execa@0.1.2:
                resolution: {integrity: sha512-b}

              typescript@5.2.2:
                resolution: {integrity: sha512-c}

            snapshots:

              chalk@5.6.1:
                dependencies:
                  execa: safe-execa@0.1.2(typescript@5.2.2)

              safe-execa@0.1.2(typescript@5.2.2):
                dependencies:
                  typescript: 5.2.2

              typescript@5.2.2: {}
            """)
        assert model.declared["chalk"] == {"safe-execa"}
        assert model.chain_to("typescript") == ["chalk", "safe-execa", "typescript"]

    def test_peer_dependencies_are_not_edges(self):
        """A peer dependency is a constraint on whoever installs the package, not an
        edge to an instance; reading it blamed a plugin that never installed react."""
        model = parse("""\
            lockfileVersion: '6.0'

            importers:

              .:
                dependencies:
                  aaa-plugin:
                    specifier: ^1.0.0
                    version: 1.0.0
                  zzz-lib:
                    specifier: ^1.0.0
                    version: 1.0.0

            packages:

              /aaa-plugin@1.0.0:
                resolution: {integrity: sha512-a}
                peerDependencies:
                  react: '*'

              /zzz-lib@1.0.0:
                resolution: {integrity: sha512-b}
                dependencies:
                  react: 18.3.1

              /react@18.3.1:
                resolution: {integrity: sha512-c}
            """)
        assert model.declared["aaa-plugin"] == set()
        assert model.chain_to("react") == ["zzz-lib", "react"]

    def test_config_dependencies_are_roots(self):
        model = parse("""\
            lockfileVersion: '9.0'

            importers:

              .:
                configDependencies:
                  '@acme/pnpm-config':
                    specifier: 1.2.0
                    version: 1.2.0

            packages:

              '@acme/pnpm-config@1.2.0':
                resolution: {integrity: sha512-a}

            snapshots:

              '@acme/pnpm-config@1.2.0': {}
            """)
        assert model.root_deps == {"@acme/pnpm-config"}

    def test_an_unbalanced_snapshot_key_is_unread(self):
        model = parse("""\
            lockfileVersion: '9.0'

            packages:

              chalk@5.6.1:
                resolution: {integrity: sha512-a}

            snapshots:

              chalk@5.6.1: {}

              'foo@1.0.0)':
                dependencies:
                  chalk: 5.6.1
            """)
        assert rows(model) == [("chalk", "5.6.1", NPM, "chalk@5.6.1")]
        assert len(model.unread) == 1 and model.unread[0].startswith("foo@1.0.0): ")

    def test_a_re_read_document_resolves_its_package_edges_under_the_grammar_it_was_read_with(self):
        model = parse("""\
            lockfileVersion: '9.0'

            packages:

              /chalk@5.6.1:
                resolution: {integrity: sha512-a}
                dependencies:
                  execa: /safe-execa@0.1.2

              /safe-execa@0.1.2:
                resolution: {integrity: sha512-b}
            """)
        assert model.unread == []
        assert model.declared["chalk"] == {"safe-execa"}

    def test_optional_dependencies_are_edges_in_packages_and_in_importers(self):
        model = parse("""\
            lockfileVersion: '6.0'

            importers:

              .:
                optionalDependencies:
                  fsevents:
                    specifier: ^2.3.0
                    version: 2.3.3

            packages:

              /fsevents@2.3.3:
                resolution: {integrity: sha512-a}
                optionalDependencies:
                  node-gyp-build: 4.8.0

              /node-gyp-build@4.8.0:
                resolution: {integrity: sha512-b}
            """)
        assert model.root_deps == {"fsevents"}
        assert model.declared["fsevents"] == {"node-gyp-build"}
        assert model.chain_to("node-gyp-build") == ["fsevents", "node-gyp-build"]


class TestTwoDocuments:
    def test_both_documents_are_in_the_model(self):
        model = parse_pnpm_lockfile(FIXTURES.joinpath("pnpm-v9-two-documents.yaml").read_text())
        documents = load_documents(FIXTURES.joinpath("pnpm-v9-two-documents.yaml").read_text())
        assert len(documents) == 2
        per_document = [len(d["packages"]) for d in documents]
        assert len(model.packages) == sum(per_document)
        assert model.versions_of("pnpm") == {"12.0.0-rc.7"}

    def test_root_deps_edges_and_unread_are_merged(self):
        model = parse("""\
            ---
            lockfileVersion: '9.0'

            importers:

              .:
                packageManagerDependencies:
                  pnpm:
                    specifier: 12.0.0
                    version: 12.0.0

            packages:

              pnpm@12.0.0:
                resolution: {integrity: sha512-a}

              /stray@1.0.0:
                resolution: {integrity: sha512-s}

            snapshots:

              pnpm@12.0.0: {}
            ---
            lockfileVersion: '9.0'

            importers:

              .:
                dependencies:
                  chalk:
                    specifier: ^5.0.0
                    version: 5.6.1

            packages:

              chalk@5.6.1:
                resolution: {integrity: sha512-b}

            snapshots:

              chalk@5.6.1:
                dependencies:
                  ansi-styles: 6.2.1
            """)
        assert model.root_deps == {"pnpm", "chalk"}
        assert model.declared[ROOT] == {"pnpm", "chalk"}
        assert model.declared["chalk"] == {"ansi-styles"}
        assert [p.name for p in model.packages] == ["pnpm", "chalk"]
        assert model.unread == ["/stray@1.0.0: v5/v6-style key in a document declaring "
                               "lockfileVersion 9.0"]


class TestWhatIsRefused:
    @pytest.mark.parametrize("text, fragment", [
        ("", "no YAML document"),
        ("# only a comment\n", "no YAML document"),
        ("- a\n- b\n", "not a mapping"),
        ("packages: {}\n", "no lockfileVersion"),
        ("lockfileVersion: 7\npackages: {}\n", "unsupported lockfileVersion"),
        ("lockfileVersion: '9.0'\npackages:\n  - a\n", "packages is a list"),
        ("lockfileVersion: '9.0'\npackages: {}\nsnapshots: text\n", "snapshots is a str"),
        ("lockfileVersion: '9.0'\npackages:\n  a@1.0.0:\n    resolution: {integrity: [\n",
         ""),
        ("lockfileVersion: '6.0'\n---\n- not a mapping\n", "document 1 is not a mapping"),
    ])
    def test_the_text_is_not_a_lockfile_this_reads(self, text, fragment):
        with pytest.raises(LockfileParseError) as error:
            parse_pnpm_lockfile(text)
        assert fragment in str(error.value)

    def test_a_trailing_document_marker_is_not_a_document(self):
        model = parse("""\
            lockfileVersion: '9.0'

            packages:

              chalk@5.6.1:
                resolution: {integrity: sha512-a}

            snapshots:

              chalk@5.6.1: {}
            ---
            """)
        assert model.versions_of("chalk") == {"5.6.1"}

    def test_an_empty_packages_section_is_a_model_with_no_packages(self):
        model = parse("""\
            lockfileVersion: 5.4

            specifiers: {}
            """)
        assert model.packages == [] and model.unread == [] and model.root_deps == set()


class TestAgainstTheFixtureLockfiles:
    """Every pnpm fixture in the tree, with the accounting the model has to satisfy:
    each key of the row sections is either a package, an unread message, or a row that
    reads to a name without a version. Counts come from the raw document."""

    @staticmethod
    def expected_rows(document) -> tuple[list[str], int]:
        """The row keys of one document and how many of them read to a name without a
        version, computed from the raw document under the grammar the reader would use
        (re-read under 6.0 when nothing reads under a declared 9.0)."""
        version = document["lockfileVersion"]
        packages = document.get("packages") or {}
        snapshots = document.get("snapshots") or {}
        keys = list(packages)
        if str(version).startswith("9"):
            keys += [k for k in snapshots if suffix_groups(k)[0] not in packages]

        def records(grammar):
            return [split_key(grammar, k, packages.get(k, snapshots.get(k)), packages) for k in keys]
        found = records(version)
        if str(version).startswith("9") and found and all(r.status == "unknown" for r in found):
            legacy = records("6.0")
            if any(r.status != "unknown" for r in legacy):
                found = legacy
        name_only = sum(1 for r in found
                        if r.status != "unknown" and r.name is not None and r.version is None)
        return keys, name_only

    @pytest.mark.parametrize("path", sorted(FIXTURES.glob("pnpm-*.yaml")), ids=lambda p: p.name)
    def test_every_key_is_accounted_for_exactly_once(self, path):
        text = path.read_text(encoding="utf-8")
        model = parse_pnpm_lockfile(text)
        keys: list[str] = []
        name_only = 0
        for document in load_documents(text):
            document_keys, document_name_only = self.expected_rows(document)
            assert len(set(document_keys)) == len(document_keys)
            keys += document_keys
            name_only += document_name_only
        paths = [p.path for p in model.packages]
        assert len(paths) + len(model.unread) + name_only == len(keys), path.name
        assert set(paths) <= set(keys)
        assert all(message.split(": ", 1)[0] in keys for message in model.unread)

    def test_the_accounting_can_fail(self):
        """A two-document file where the first document holds a name-only row, and a
        lying header over a directory row: the two shapes that made an earlier version
        of the count wrong while the model was right."""
        text = textwrap.dedent("""\
            ---
            lockfileVersion: '9.0'

            packages:

              local-tool@file:../local-tool:
                resolution: {directory: ../local-tool, type: directory}

              pnpm@12.0.0:
                resolution: {integrity: sha512-a}

            snapshots:

              local-tool@file:../local-tool: {}
              pnpm@12.0.0: {}
            ---
            lockfileVersion: '9.0'

            packages:

              /chalk@5.6.1:
                resolution: {integrity: sha512-b}

              file:../local-rules:
                resolution: {directory: ../local-rules, type: directory}
                name: local-rules
            """)
        model = parse_pnpm_lockfile(text)
        assert rows(model) == [("chalk", "5.6.1", NPM, "/chalk@5.6.1"), ("pnpm", "12.0.0", NPM, "pnpm@12.0.0")]
        assert model.unread == []
        assert {"local-tool", "local-rules"} <= set(model.declared)
        keys, name_only = [], 0
        for document in load_documents(text):
            document_keys, document_name_only = self.expected_rows(document)
            keys += document_keys
            name_only += document_name_only
        assert (len(keys), name_only) == (4, 2)
        assert len(model.packages) + len(model.unread) + name_only == len(keys)

    @pytest.mark.parametrize("name, package, versions", [
        ("pnpm-v5.4.yaml", "@algolia/autocomplete-core", {"1.6.3"}),
        ("pnpm-v5.3-prettier.yaml", "@types/node", {"18.15.0"}),
        ("pnpm-v6.0.yaml", "@aashutoshrathi/word-wrap", {"1.2.6"}),
        ("pnpm-v9.yaml", "@aashutoshrathi/word-wrap", {"1.2.6"}),
        ("pnpm-v9-header-lies.yaml", "solhint", {"5.0.5"}),
        ("pnpm-v9-mixed-keys.yaml", "kleur", {"4.1.5", "3.0.3"}),
        ("pnpm-v9-two-documents.yaml", "pnpm", {"12.0.0-rc.7"}),
    ])
    def test_a_known_package_of_each_fixture(self, name, package, versions):
        model = parse_pnpm_lockfile(FIXTURES.joinpath(name).read_text(encoding="utf-8"))
        assert model.versions_of(package) == versions

    def test_every_fixture_row_is_a_known_origin(self):
        for path in sorted(FIXTURES.glob("pnpm-*.yaml")):
            model = parse_pnpm_lockfile(path.read_text(encoding="utf-8"))
            assert {p.origin for p in model.packages} <= {NPM, OTHER_REGISTRY, SOURCE, NOT_NPM}
            assert all(p.version for p in model.packages), path.name


class TestTheScanPathStillReachesNothing:
    def test_a_scan_does_not_import_the_document_reader(self):
        """history.py does not read pnpm lockfiles yet; when it does, the import must
        come from there and be tested there."""
        script = (
            "import sys, tempfile\n"
            f"sys.path[:0] = {sys.path!r}\n"
            "from deptrail.cli import main\n"
            "with tempfile.TemporaryDirectory() as d: main(['demo', '--workdir', d])\n"
            "sys.exit('imported' if 'deptrail.pnpmlock' in sys.modules else 0)\n"
        )
        result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
        assert result.returncode == 0, result.stdout.strip() or result.stderr.strip()
