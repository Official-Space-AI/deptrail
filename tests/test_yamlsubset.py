"""The vendored YAML reader, measured against PyYAML rather than trusted.

A hand-rolled parser earns nothing by being asserted correct, so most of what is here
compares it to a reference implementation over real lockfiles and generated ones. The
contract it has to keep is not "always right" — that would be a claim about YAML at
large, which this reader deliberately does not implement. It is:

    for any input, either return what PyYAML returns, or raise.

Silence is the failure. A refusal costs a repository its verdict and says so; a quiet
disagreement hands back a tree that was never in the file.

PyYAML is a test dependency (the `dev` extra) and never a runtime one — the last class
here proves that, because the whole argument for vendoring is that a supply-chain
forensics tool should not carry a supply-chain dependency.
"""
from __future__ import annotations

import os
import pathlib
import random
import subprocess
import sys

import pytest

from deptrail.yamlsubset import YamlSubsetError, load, load_documents

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "yaml"

try:
    import yaml as pyyaml
except ImportError:  # pragma: no cover - exercised by the CI guard below
    pyyaml = None


def reference_loader():
    """PyYAML, configured to leave every scalar a string, as this reader does.

    YAML's plain-scalar typing is the thing being deliberately not implemented: it reads
    `lockfileVersion: 6.0` as a float and turns the version `1.10` into `1.1`. Switching
    the reference to strings compares the two parsers on structure and text, which is
    what a lockfile is made of, instead of on a typing rule neither of them should apply
    here.
    """
    if pyyaml is None:
        # CI installs the dev extra, so a skip there means the extra changed and this
        # entire file quietly stopped testing anything.
        if os.environ.get("CI"):
            pytest.fail("PyYAML is missing in CI: the dev extra changed and the "
                        "differential tests stopped running")
        pytest.skip("PyYAML is not installed here")

    class StringScalars(pyyaml.SafeLoader):
        pass

    for tag in ("bool", "int", "float", "timestamp", "value"):
        StringScalars.add_constructor(f"tag:yaml.org,2002:{tag}",
                                      lambda loader, node: loader.construct_scalar(node))
    StringScalars.add_constructor("tag:yaml.org,2002:null", lambda loader, node: None)
    return StringScalars


def reference(text: str) -> list:
    return list(pyyaml.load_all(text, Loader=reference_loader()))


REAL_LOCKFILES = sorted(p.name for p in FIXTURES.iterdir() if p.is_file())


class TestRealLockfiles:
    """Slices of lockfiles that npm projects actually ship, kept verbatim.

    Trimmed rather than re-serialised: a fixture written back out by PyYAML would be in
    PyYAML's style, and the question here is whether pnpm's and Yarn's style can be
    read.
    """

    def test_the_corpus_did_not_quietly_shrink(self):
        # Every construct below is covered by exactly one file, so deleting one deletes
        # its coverage without failing anything else.
        assert set(REAL_LOCKFILES) == {
            "pnpm-v9.yaml",
            "pnpm-v9-two-documents.yaml",
            "pnpm-v9-sequence-of-mappings.yaml",
            "pnpm-v9-block-scalar.yaml",
            "yarn-berry.lock",
        }

    @pytest.mark.parametrize("name", REAL_LOCKFILES)
    def test_it_reads_what_pyyaml_reads(self, name):
        text = FIXTURES.joinpath(name).read_text(encoding="utf-8")
        assert load_documents(text) == reference(text)

    def test_a_pnpm_lockfile_can_hold_more_than_one_document(self):
        """pnpm 12 writes the package manager's own install as a separate document.

        Measured on `pnpm/pnpm`, where the first document is 98 lines and the second is
        25,430. A reader that stops at the first one reports the 98 and calls the rest
        absent, which is a clean verdict for a tree it never opened.
        """
        text = FIXTURES.joinpath("pnpm-v9-two-documents.yaml").read_text(encoding="utf-8")
        documents = load_documents(text)
        assert len(documents) == 2
        assert "pnpm" in documents[0]["importers"]["."]["packageManagerDependencies"]
        # The second document is the project's own, and it is the larger one.
        assert len(documents[1]["packages"]) >= 1
        assert documents[0] != documents[1]

        with pytest.raises(YamlSubsetError):
            load(text)

    def test_a_sequence_item_keeps_every_key_of_its_mapping(self):
        """`- cpu: ppc64` followed by `os: aix` is one mapping with two keys.

        Read as "a mapping starts here and ends at the line break" it becomes one key,
        and the platform an artefact was built for disappears without an error. pnpm
        writes this shape for pinned Node runtimes.
        """
        text = FIXTURES.joinpath("pnpm-v9-sequence-of-mappings.yaml").read_text(
            encoding="utf-8")
        entry = load(text)["packages"]["node@runtime:26.7.0"]
        variants = entry["resolution"]["variants"]
        targets = [target for variant in variants for target in variant["targets"]]
        assert targets, "the fixture stopped covering sequences of mappings"
        assert all(set(target) == {"cpu", "os"} or "libc" in target
                   for target in targets), targets

    def test_a_block_scalar_is_not_parsed_as_yaml(self):
        """`deprecated: |-` carries free text, and free text can look like YAML."""
        text = FIXTURES.joinpath("pnpm-v9-block-scalar.yaml").read_text(encoding="utf-8")
        entry = load(text)["packages"]["q@1.5.1"]
        assert entry["deprecated"].startswith("You or someone you depend on")
        assert "\n" in entry["deprecated"]
        assert not entry["deprecated"].endswith("\n"), "`|-` strips the final break"


# Constructs the real corpus happens not to contain. Each is compared to PyYAML rather
# than to a hand-written expectation, so a wrong expectation cannot make a wrong parser
# look right.
UNCOVERED = {
    "folded scalar": "k: >\n  one\n  two\n\n  three\n",
    "folded, stripped": "k: >-\n  one\n  two\n",
    "literal, kept": "k: |+\n  one\n\n",
    "literal, clipped": "k: |\n  one\n  two\n",
    "block scalar holding yaml": "k: |\n  a: 1\n  - b\n  # not a comment\n",
    "empty value": "a:\nb: 1\n",
    "explicit null": "a: null\nb: ~\n",
    "nested flow": "k: {a: [1, {b: [2, 3]}], c: {}}\n",
    "empty collections": "a: {}\nb: []\n",
    "flow at the document root": "{a: 1, b: [2, 3]}\n",
    "sequence at the document root": "- a\n- b\n",
    "quotes inside quotes": """a: 'it''s'\nb: "say \\"hi\\""\n""",
    "escapes": 'a: "\\u65E5\\t\\\\\\n"\n',
    "colon inside a plain scalar": "url: https://example.test/a:b\n",
    "hash inside a plain scalar": "k: a#b\n",
    "indicator-led plain scalar": "a: '}'\nb: ']'\n",
    "unicode whitespace in a scalar": "k: value\u00a0\n",
    "keys that look typed": "'true': 1\n'6.0': 2\n'1.10': 3\n",
    "deep indentation": "a:\n  b:\n    c:\n      d:\n        e: 1\n",
    "comments and blank lines": "# lead\n\na: 1\n\n# middle\nb: 2\n",
    "document end marker": "a: 1\n...\n",
    "three documents": "---\na: 1\n---\nb: 2\n---\nc: 3\n",
    "leading document marker": "---\na: 1\n",
    "nothing at all": "",
    "blank lines only": "\n\n",
    "comments only": "# nothing here\n",
    "an empty document between markers": "---\n---\na: 1\n",
    "a lone document marker": "---\n",
    "a document restarted after an end marker": "a: 1\n...\n---\nb: 2\n",
    "a sequence at its key's own column": "a:\n- x\n- y\n",
    "a sequence at a nested key's column": "a:\n  b:\n  - x\nc: 1\n",
}


class TestConstructsTheCorpusDoesNotCover:
    @pytest.mark.parametrize("name", sorted(UNCOVERED))
    def test_it_reads_what_pyyaml_reads(self, name):
        text = UNCOVERED[name]
        assert load_documents(text) == reference(text), text

    def test_a_carriage_return_does_not_become_part_of_a_scalar(self):
        """CI runs on Windows, where a checkout can rewrite every line ending."""
        assert load("a: 1\r\nb: 2\r\n") == {"a": "1", "b": "2"}

    def test_a_byte_order_mark_does_not_become_part_of_the_first_key(self):
        assert load("\ufeffa: 1\n") == {"a": "1"}


class TestMatchOrRefuse:
    """The contract, checked over generated YAML: equal to PyYAML, or an error.

    Seeded, so a failure is reproducible rather than a story about a run that happened
    once. The generator deliberately emits characters that lockfiles do not contain —
    control characters, quotes, colons, no-break spaces — because the interesting
    failures are the ones a lockfile-shaped corpus never provokes.
    """

    ALPHABET = list("abcXYZ019-_./@+=") + [
        " ", ":", "#", "'", '"', "\\", "\n", "\t", "%", "*", "&", "!", "|", ">",
        "[", "]", "{", "}", ",", "?", "~", "`", "é", "\u65e5", "\u00a0", "\x1b",
    ]
    LITERALS = ["", "true", "false", "null", "~", "0", "6.0", "1.10", "9.0", "yes",
                "no", "on", "off", "-", "---", "...", "@scope/pkg@1.0.0",
                "sha512-a/b+c==", "https://example.test/x"]

    def _scalar(self, rng):
        if rng.random() < 0.15:
            return rng.choice(self.LITERALS)
        return "".join(rng.choice(self.ALPHABET) for _ in range(rng.randint(0, 12)))

    def _build(self, rng, depth=0):
        roll = rng.random()
        if depth >= 3 or roll < 0.45:
            return self._scalar(rng)
        if roll < 0.75:
            return {self._scalar(rng) or f"k{rng.randint(0, 99)}": self._build(rng, depth + 1)
                    for _ in range(rng.randint(1, 4))}
        return [self._build(rng, depth + 1) for _ in range(rng.randint(1, 4))]

    def test_it_never_disagrees_without_saying_so(self):
        loader = reference_loader()
        rng = random.Random(20260820)
        agreed = refused = 0
        for _ in range(1500):
            value = self._build(rng)
            for flow in (False, True):
                try:
                    text = pyyaml.dump(value, default_flow_style=flow,
                                       allow_unicode=rng.random() < 0.5)
                    expected = list(pyyaml.load_all(text, Loader=loader))
                except Exception:
                    continue
                try:
                    actual = load_documents(text)
                except YamlSubsetError:
                    refused += 1
                    continue
                assert actual == expected, f"silent disagreement on {text!r}"
                agreed += 1
        # Without this the test would pass just as well if the reader refused its whole
        # input, which is the failure mode that looks most like success.
        assert agreed > 350, f"only {agreed} inputs were read; the reader may be refusing everything"
        assert refused > 0, "the generator stopped producing anything out of subset"


REFUSED = {
    "anchor": "a: &x 1\nb: *x\n",
    "alias": "a: 1\nb: *x\n",
    "merge key": "b:\n  <<: {p: 1}\n",
    "explicit tag": "a: !!str 1\n",
    "tab indentation": "a:\n\tb: 1\n",
    "explicit key": "? a: 1\n",
    "explicit key in flow": "{? a : 1}\n",
    "flow spanning lines": "a: {b: 1,\n    c: 2}\n",
    "unterminated single quote": "a: 'x\n",
    "unterminated double quote": 'a: "x\n',
    "duplicate key": "a: 1\na: 2\n",
    "duplicate key in flow": "k: {a: 1, a: 2}\n",
    "flow collection as a key": "a: 1\n{b: 2}: 3\n",
    "sequence on a sequence item": "- - a\n",
    "unknown escape": 'a: "\\q"\n',
    "truncated unicode escape": 'a: "\\u12"\n',
    "trailing content after a flow collection": "a: {b: 1} c\n",
    "trailing content after a quoted scalar": "a: 'b' c\n",
    "comment after a plain scalar": "a: b # note\n",
    "scalar document": "just a string\n",
    "unindented continuation": "a: 1\n  b: 2\n",
    "mapping key with no value": "{a}\n",
    "content after a document end": "a: 1\n...\nb: 2\n",
    "a node on a document marker line": "--- a: 1\n",
    "a document end that ends nothing": "...\n",
}


class TestWhatItRefuses:
    """Everything outside the subset has to raise, and raise this one error.

    A refusal is not a defeat here: `YamlSubsetError` reaches the caller as an
    unreadable snapshot, and an unreadable snapshot leaves the repository
    INDETERMINATE. What must never happen is a plausible answer.
    """

    @pytest.mark.parametrize("name", sorted(REFUSED))
    def test_it_says_so_rather_than_guessing(self, name):
        with pytest.raises(YamlSubsetError):
            load_documents(REFUSED[name])

    @pytest.mark.parametrize("name", sorted(REFUSED))
    def test_pyyaml_agrees_it_is_either_invalid_or_out_of_subset(self, name):
        """Half of these are valid YAML that this reader declines on purpose.

        Asserting which half is which keeps the refusal list honest: a line that PyYAML
        also rejects proves nothing about the subset, and a line PyYAML reads is a
        deliberate limit that should be recorded as one.
        """
        text = REFUSED[name]
        try:
            reference(text)
        except Exception:
            return  # malformed for everyone
        assert name in {
            "anchor", "merge key", "explicit tag", "explicit key",
            "explicit key in flow", "flow spanning lines", "duplicate key",
            "duplicate key in flow", "flow collection as a key",
            "sequence on a sequence item", "comment after a plain scalar",
            "scalar document", "mapping key with no value",
        }, f"{name!r} is valid YAML this reader declines; record it here"

    # Refusing is not enough: `? a: 1` is also unparseable if the guard for explicit keys
    # is deleted, so a test that only asserts "it raised" stays green while the guard it
    # was written for is gone. Measured — that mutation survived until this table existed.
    REASONS = {
        "anchor": "anchors are outside the subset",
        "explicit tag": "tags are outside the subset",
        "merge key": "merge keys are outside the subset",
        "tab indentation": "tab used for indentation",
        "explicit key": "explicit keys",
        "explicit key in flow": "explicit keys",
        "flow spanning lines": "close on the line it opened",
        "unterminated single quote": "close on the line it opened",
        "unterminated double quote": "close on the line it opened",
        "duplicate key": "duplicate key",
        "duplicate key in flow": "duplicate key",
        "flow collection as a key": "flow collection used as a mapping key",
        "sequence on a sequence item": "sequence opened directly on a sequence item",
        "unknown escape": "unknown escape",
        "truncated unicode escape": "truncated",
        "comment after a plain scalar": "comment cannot follow a plain scalar",
        "unindented continuation": "content after the end of the document",
        "content after a document end": "content after a document was ended",
        "a node on a document marker line": "node on a document marker line",
        "a document end that ends nothing": "ends a document that never began",
    }

    @pytest.mark.parametrize("name", sorted(REASONS))
    def test_it_refuses_for_the_reason_it_was_written_for(self, name):
        with pytest.raises(YamlSubsetError) as caught:
            load_documents(REFUSED[name])
        assert self.REASONS[name] in str(caught.value), str(caught.value)

    def test_the_error_names_the_line(self):
        with pytest.raises(YamlSubsetError) as caught:
            load("a: 1\nb: 2\nc: &anchor 3\n")
        assert caught.value.line == 3
        assert "line 3" in str(caught.value)


class TestFindingsFromTheDifferentialRun:
    """Each of these was a silent disagreement the comparison above caught first."""

    def test_a_no_break_space_is_not_whitespace(self):
        """`str.strip()` removes U+00A0; YAML does not.

        A trailing no-break space in a package name vanished, and the name compared
        equal to a different one — the sort of near-match an incident report exists to
        distinguish.
        """
        assert load("k: value\u00a0\n") == {"k": "value\u00a0"}
        assert load("\u00a0k: 1\n") == {"\u00a0k": "1"}

    def test_a_document_written_in_flow_style_is_not_split_on_its_first_colon(self):
        """`{"a": b, "c": d}` at the document root went to the mapping parser, which
        invented a key named `{"a"` and handed back a tree that was not in the file."""
        assert load('{"a": b, "c": d}\n') == {"a": "b", "c": "d"}

    def test_an_explicit_key_is_refused_rather_than_read_as_a_key_named_question_mark(self):
        with pytest.raises(YamlSubsetError):
            load("{? long : 1}\n")

    def test_content_after_a_document_end_is_not_dropped(self):
        """`...` closed the document and everything after it was thrown away in silence.

        In a lockfile that is the whole failure this project exists to prevent: the
        packages that were installed sit in the part that went missing, and what comes
        back is a shorter file that looks clean.
        """
        with pytest.raises(YamlSubsetError):
            load_documents("a: 1\n...\nb: 2\n")

    def test_a_file_with_nothing_in_it_holds_no_documents(self):
        """`[None]` reads as one document whose content is null, which is a different
        claim from "there is nothing here" -- and the wrong one for a truncated file."""
        assert load_documents("") == []
        assert load_documents("# only a comment\n") == []

    def test_an_empty_document_still_counts(self):
        """The count is what a caller iterates, so a dropped document is a dropped tree."""
        assert load_documents("---\n---\na: 1\n") == [None, {"a": "1"}]

    def test_a_sequence_may_sit_at_its_key_own_column(self):
        """Ordinary YAML that pnpm happens not to write; refusing it cost a verdict."""
        assert load("a:\n- x\n- y\n") == {"a": ["x", "y"]}

    def test_every_escape_means_what_yaml_says_it_means(self):
        # `\L` and `\P` were written as spaces here once, which is a wrong character
        # rather than a missing one, so nothing failed until this comparison ran.
        for code, expected in [("L", "\u2028"), ("P", "\u2029"), ("N", "\x85"),
                               ("_", "\u00a0"), ("e", "\x1b"), ("0", "\0")]:
            assert load(f'k: "\\{code}"\n') == {"k": expected}, code


class TestZeroRuntimeDependencies:
    """The reason this module exists instead of a line in pyproject.toml."""

    def test_importing_deptrail_does_not_import_pyyaml(self):
        script = (
            "import importlib, pkgutil, sys\n"
            # Without this the child imports whatever deptrail happens to be installed,
            # so a worktree that adds a module the installed copy lacks is never tested.
            f"sys.path[:0] = {sys.path!r}\n"
            "import deptrail\n"
            "for module in pkgutil.iter_modules(deptrail.__path__):\n"
            "    importlib.import_module('deptrail.' + module.name)\n"
            "leaked = sorted(m for m in sys.modules if m == 'yaml' or m.startswith('yaml.'))\n"
            "sys.exit('imported: ' + ', '.join(leaked) if leaked else 0)\n"
        )
        result = subprocess.run([sys.executable, "-c", script],
                                capture_output=True, text=True)
        assert result.returncode == 0, result.stdout.strip() or result.stderr.strip()

    def test_the_package_declares_no_runtime_dependencies(self):
        from importlib import metadata
        try:
            requires = metadata.requires("deptrail")
        except metadata.PackageNotFoundError:
            if os.environ.get("CI"):
                pytest.fail("no deptrail distribution in CI: the install step changed")
            pytest.skip("deptrail is not installed as a distribution here")
        runtime = [r for r in (requires or []) if "extra ==" not in r]
        assert runtime == [], runtime
