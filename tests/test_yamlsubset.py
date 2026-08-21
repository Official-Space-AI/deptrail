"""The vendored YAML reader, measured against PyYAML rather than trusted.

A hand-rolled parser earns nothing by being asserted correct, so most of what is here
compares it to a reference implementation over real lockfiles and generated ones. The
contract it has to keep is not "always right" — that would be a claim about YAML at
large, which this reader deliberately does not implement. It is:

    for any input, either return what PyYAML returns, or raise YamlSubsetError.

Silence is the failure. A refusal costs a repository its verdict and says so; a quiet
disagreement hands back a tree that was never in the file.

PyYAML is a test dependency (the `dev` extra) and never a runtime one — the last class
here proves that, because the whole argument for vendoring is that a supply-chain
forensics tool should not carry a supply-chain dependency.

Two lessons from an independent review are built into the shape of this file, because
both were live here and neither failed a test:

* **A comparison that skips is a comparison that passed.** ``reference_loader()`` used
  to be evaluated as an argument to ``pyyaml.load_all``, so Python resolved
  ``pyyaml.load_all`` first, raised ``AttributeError`` when PyYAML was absent, and a
  bare ``except Exception`` swallowed it. Twenty-five parameters went green with PyYAML
  uninstalled. Every test that claims to compare now calls ``reference_loader()`` into a
  local first, so the skip-or-fail decision happens before anything else can.
* **A differential fixture asserts nothing on its own.** Two of these fixtures could be
  replaced wholesale with ``a: 1`` and the suite stayed green, because "both parsers
  agree" is satisfied by any content at all. Each one now also has to *be* what it
  claims to be.
"""
from __future__ import annotations

import inspect
import os
import pathlib
import random
import subprocess
import sys

import pytest

from deptrail.lockfile import LockfileParseError
from deptrail.yamlsubset import (_ESCAPES, _MAX_DEPTH, YamlSubsetError, load,
                                 load_documents)

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
    what a lockfile is made of, instead of on a typing rule neither should apply here.
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
    loader = reference_loader()
    return list(pyyaml.load_all(text, Loader=loader))


REAL_LOCKFILES = sorted(p.name for p in FIXTURES.iterdir() if p.is_file())


class TestRealLockfiles:
    """Slices of lockfiles that npm projects actually ship, kept verbatim.

    Trimmed rather than re-serialised: a fixture written back out by PyYAML would be in
    PyYAML's style, and the question here is whether pnpm's and Yarn's style can be read.
    """

    def test_the_corpus_did_not_quietly_shrink(self):
        assert set(REAL_LOCKFILES) == {
            "pnpm-v5.4.yaml",
            "pnpm-v6.0.yaml",
            "pnpm-v9.yaml",
            "pnpm-v9-two-documents.yaml",
            "pnpm-v9-sequence-of-mappings.yaml",
            "pnpm-v9-block-scalar.yaml",
            "yarn-berry.lock",
            "yarn-berry-v4.lock",
        }

    @pytest.mark.parametrize("name", REAL_LOCKFILES)
    def test_it_reads_what_pyyaml_reads(self, name):
        text = FIXTURES.joinpath(name).read_text(encoding="utf-8")
        assert load_documents(text) == reference(text)

    def test_each_fixture_is_still_the_lockfile_it_claims_to_be(self):
        """Emptying a differential fixture does not fail a differential test.

        Both parsers agree about `a: 1` as readily as about 5 KB of pnpm, so the two
        largest fixtures here could be replaced outright and nothing went red. These
        assertions are what makes the corpus a corpus rather than eight files.

        The three package-key grammars are the point of keeping all three pnpm versions:
        v5 separates name from version with `/`, v6 with `@` behind a leading `/`, and v9
        drops the slash. A parser written against v9 alone silently reads nothing from
        the other two.
        """
        def document(name):
            return load(FIXTURES.joinpath(name).read_text(encoding="utf-8"))

        five = document("pnpm-v5.4.yaml")
        assert five["lockfileVersion"] == "5.4"
        assert "/@algolia/autocomplete-core/1.6.3" in five["packages"]

        six = document("pnpm-v6.0.yaml")
        assert six["lockfileVersion"] == "6.0"
        assert "/@aashutoshrathi/word-wrap@1.2.6" in six["packages"]

        nine = document("pnpm-v9.yaml")
        assert nine["lockfileVersion"] == "9.0"
        assert "@aashutoshrathi/word-wrap@1.2.6" in nine["packages"]
        assert nine["importers"]["."], "the importers block carries the root's own deps"
        assert len(nine["packages"]) >= 5 and len(nine["snapshots"]) >= 5

        berry_ten = document("yarn-berry.lock")
        assert berry_ten["__metadata"] == {"version": "10", "cacheKey": "10"}
        berry_four = document("yarn-berry-v4.lock")
        assert berry_four["__metadata"]["version"] == "4"
        # Berry writes several descriptors into one quoted key, comma-separated. Keeping
        # that whole is the reader's job; splitting it is the Yarn parser's.
        assert any("," in key for key in berry_ten), berry_ten

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
        assert documents[0] != documents[1]
        # Both carry `lockfileVersion: '9.0'` and both have `packages` and `snapshots`,
        # so nothing in the content tells them apart. That is why `load()` refuses rather
        # than picking, and why the pnpm parser must not reach for `documents[0]`.
        assert all(d["lockfileVersion"] == "9.0" for d in documents)
        assert all("packages" in d for d in documents)
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
        assert len(targets) > 1, "the fixture stopped covering sequences of mappings"
        assert all(set(target) == {"cpu", "os"} or "libc" in target
                   for target in targets), targets

    def test_a_block_scalar_stops_at_the_next_key(self):
        """`deprecated: |-` carries free text, and free text can look like YAML.

        The sibling entry after it is the whole point: without something at a lower
        indent to stop on, deleting the block scalar's dedent check changed nothing, and
        a mutation that swallowed the entire rest of the lockfile into one string passed
        every test in this file.
        """
        text = FIXTURES.joinpath("pnpm-v9-block-scalar.yaml").read_text(encoding="utf-8")
        packages = load(text)["packages"]
        assert list(packages) == ["q@1.5.1", "qs@6.11.0"]
        deprecated = packages["q@1.5.1"]["deprecated"]
        assert deprecated.startswith("You or someone you depend on")
        assert "\n" in deprecated
        assert not deprecated.endswith("\n"), "`|-` strips the final break"
        assert "resolution" not in deprecated, "the block scalar ran past its own key"
        assert packages["qs@6.11.0"]["engines"] == {"node": ">=0.6"}


# Constructs the real corpus happens not to contain. Each is compared to PyYAML rather
# than to a hand-written expectation, so a wrong expectation cannot make a wrong parser
# look right.
UNCOVERED = {
    "folded scalar": "k: >\n  one\n  two\n\n  three\n",
    "folded, stripped": "k: >-\n  one\n  two\n",
    "folded, more-indented line": "k: >\n  one\n   two\n  three\n",
    "folded, kept": "k: >+\n  one\n\n",
    "literal, kept": "k: |+\n  one\n\n",
    "literal, clipped": "k: |\n  one\n  two\n",
    "literal, several trailing breaks": "k: |\n  one\n\n\n",
    "block scalar holding yaml": "k: |\n  a: 1\n  - b\n  # not a comment\n",
    "empty value": "a:\nb: 1\n",
    "explicit null": "a: null\nb: ~\n",
    "comment as the whole value": "a: # note\nb: 1\n",
    "comment as a sequence item": "- # note\n- b\n",
    "comment holding a colon as a sequence item": "- #h: yes\n",
    "a file that does not end in a newline": "a: 1",
    "a sequence in a file that does not end in a newline": "- a\n- b",
    "block scalar with a sibling at its own column": "a:\n  b: |\n    x\n  c: 1\n",
    "nested flow": "k: {a: [1, {b: [2, 3]}], c: {}}\n",
    "empty collections": "a: {}\nb: []\n",
    "empty value in a flow mapping": "engines: {node: }\n",
    "flow mapping key holding a colon": "k: {node@runtime:26.7.0: 2}\n",
    "flow mapping key holding a url": "k: {https://example.test/a:b: 1}\n",
    "flow at the document root": "{a: 1, b: [2, 3]}\n",
    "flow sequence at the document root": "[a, {b: 1}]\n",
    "sequence at the document root": "- a\n- b\n",
    "empty sequence items": "-\n- b\n",
    "empty sequence item between two others": "- a\n-\n- c\n",
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

    def test_every_escape_in_the_table_matches_pyyaml(self):
        """Driven off `_ESCAPES` itself, so a new entry cannot arrive untested.

        Seven of them had never been executed: `\\L` and `\\P` were written as spaces —
        a wrong character rather than a missing one, which nothing was comparing.
        """
        for code in _ESCAPES:
            text = 'k: "\\' + code + '"\n'
            assert load(text) == reference(text)[0], code
        for code in ("x41", "u65E5", "U0001F600"):
            text = 'k: "\\' + code + '"\n'
            assert load(text) == reference(text)[0], code

    def test_a_carriage_return_does_not_become_part_of_a_scalar(self):
        """CI runs on Windows, and a caller reading bytes off disk sees what git stored.

        The one caller in this project pipes `git show` through `subprocess` with
        `text=True`, which already applies universal newlines — so this is belt and
        braces for that path rather than the thing that saves it. It is not dead code:
        nothing stops a caller from reading the file itself.
        """
        assert load("a: 1\r\nb: 2\r\n") == {"a": "1", "b": "2"}
        assert load("a: 1\rb: 2\r") == {"a": "1", "b": "2"}

    def test_a_byte_order_mark_does_not_become_part_of_the_first_key(self):
        assert load("\ufeffa: 1\n") == {"a": "1"}


class TestMatchOrRefuse:
    """The contract, checked over generated YAML: equal to PyYAML, or an error.

    Seeded, so a failure is reproducible rather than a story about a run that happened
    once. The generator deliberately emits characters lockfiles do not contain — control
    characters, quotes, colons, no-break spaces — because the interesting failures are
    the ones a lockfile-shaped corpus never provokes.

    Round-tripping a Python value through `pyyaml.dump` can only ever produce YAML that
    PyYAML is willing to *write*, which left three of the subset's own constructs at zero
    coverage and explained twenty surviving mutants in the block-scalar code. The raw
    inputs below fill that in, and the per-construct assertions stop it silently emptying
    again.
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

    def _raw(self, rng):
        """YAML written directly, for the constructs `pyyaml.dump` never emits."""
        body = [self._scalar(rng).replace("\n", " ") for _ in range(rng.randint(1, 4))]
        indented = "".join(f"  {line}\n" for line in body)
        header = rng.choice(["|", "|-", "|+", ">", ">-", ">+"])
        blanks = "\n" * rng.randint(0, 2)
        yield f"k: {header}\n{indented}{blanks}"
        yield f"# a comment\nk: {header}\n{indented}"
        yield f"---\na: 1\n---\nk: {header}\n{indented}"
        yield f"a: 1\n\n# between\nb:\n{indented}"
        yield f"---\na: 1\n...\n---\nb: 2\n"

    def test_it_never_disagrees_without_saying_so(self):
        loader = reference_loader()
        rng = random.Random(20260820)
        agreed = refused = 0
        seen = {"block scalar": 0, "more than one document": 0, "a comment": 0}
        inputs = []
        for _ in range(1500):
            value = self._build(rng)
            for flow in (False, True):
                try:
                    inputs.append(pyyaml.dump(value, default_flow_style=flow,
                                              allow_unicode=rng.random() < 0.5))
                except Exception:
                    continue
            inputs.extend(self._raw(rng))

        for text in inputs:
            try:
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
            if any(f"{c}\n" in text for c in ("|", "|-", "|+", ">", ">-", ">+")):
                seen["block scalar"] += 1
            if text.count("---") >= 1:
                seen["more than one document"] += 1
            if "#" in text:
                seen["a comment"] += 1

        # Without this the test would pass just as well if the reader refused its whole
        # input, which is the failure mode that looks most like success.
        assert agreed > 400, f"only {agreed} inputs were read; the reader may be refusing everything"
        assert refused > 0, "the generator stopped producing anything out of subset"
        # One global count hid three empty constructs: dropping no-break-space handling
        # entirely still left the old threshold satisfied.
        for construct, count in seen.items():
            assert count > 20, f"only {count} compared inputs contained {construct}: {seen}"


REFUSED = {
    "anchor": "a: &x 1\nb: *x\n",
    "alias": "a: 1\nb: *x\n",
    "merge key": "b:\n  <<: {p: 1}\n",
    "explicit tag": "a: !!str 1\n",
    "tab indentation": "a:\n\tb: 1\n",
    "tab indentation under a key": "a:\n  \tb: 1\n",
    "tab indentation behind a dash": "- \ta: 1\n  b: 2\n",
    "explicit key": "? a: 1\n",
    "explicit key in flow": "{? a : 1}\n",
    "explicit key in flow without a space": "k: {?a: 1}\n",
    "explicit key in a flow sequence": "k: [?a]\n",
    "flow spanning lines": "a: {b: 1,\n    c: 2}\n",
    "unterminated single quote": "a: 'x\n",
    "unterminated double quote": 'a: "x\n',
    "duplicate key": "a: 1\na: 2\n",
    "duplicate key in flow": "k: {a: 1, a: 2}\n",
    "flow collection as a key": "a: 1\n{b: 2}: 3\n",
    "sequence on a sequence item": "- - a\n",
    "empty sequence nested on a sequence item": "- -\n",
    "unknown escape": 'a: "\\q"\n',
    "truncated unicode escape": 'a: "\\u12"\n',
    "non-hexadecimal unicode escape": 'a: "\\u 123"\n',
    "non-hexadecimal unicode escape with a sign": 'a: "\\u+123"\n',
    "non-hexadecimal unicode escape with a separator": 'a: "\\u1_23"\n',
    "trailing content after a flow collection": "a: {b: 1} c\n",
    "trailing content after a quoted scalar": "a: 'b' c\n",
    "comment after a plain scalar": "a: b # note\n",
    "plain scalar holding a colon and a space": "a: note: this is gone\n",
    "not a block scalar header": "k: |pipe\n",
    "block scalar with an indentation indicator": "k: |2\n   one\n",
    "two values in one flow entry": "k: {a: 1 b: 2}\n",
    "single-pair mapping in a flow sequence": 'k: ["a": b]\n',
    "null key": "null: 1\n",
    "empty key": ": 1\n",
    "null key in flow": "k: {null: 1}\n",
    "flow key with no value": "k: {a, b}\n",
    "scalar document": "just a string\n",
    "unindented continuation": "a: 1\n  b: 2\n",
    "mapping key with no value": "{a}\n",
    "content after a document end": "a: 1\n...\nb: 2\n",
    "a node on a document marker line": "--- a: 1\n",
    "a document end that ends nothing": "...\n",
    "tab after a plain scalar": "a: b\t\n",
    "tab inside a plain scalar": "a: b\tc\n",
    "tab after a key": "a\t: b\n",
    "tab inside a flow value": "k: {a: b\tc}\n",
    "tab inside a sequence item": "- a\tb\n",
    "unterminated flow mapping key": "k: {abc\n",
    "unterminated flow mapping value": "k: {a: b\n",
    "unterminated flow sequence": "k: [a, b\n",
    "flow key holding a bracket": "k: {a[b]: 1}\n",
    "sequence item inside a mapping": "a: 1\n- x\n",
}

# Refusals that PyYAML would read. Recording which half is which keeps the list honest:
# a line PyYAML also rejects proves nothing about the subset, and a line it reads is a
# deliberate limit that should be written down as one.
DECLINED_ON_PURPOSE = {
    "anchor", "merge key", "explicit tag", "explicit key in flow",
    "explicit key in flow without a space", "explicit key in a flow sequence",
    "flow spanning lines", "duplicate key", "duplicate key in flow",
    "sequence on a sequence item", "empty sequence nested on a sequence item",
    "comment after a plain scalar", "scalar document", "mapping key with no value",
    "null key", "null key in flow", "flow key with no value",
    "single-pair mapping in a flow sequence",
    "block scalar with an indentation indicator",
}


class TestWhatItRefuses:
    """Everything outside the subset has to raise, and raise this one error.

    A refusal is not a defeat here: `YamlSubsetError` reaches the caller as an unreadable
    snapshot, and an unreadable snapshot leaves the repository INDETERMINATE. What must
    never happen is a plausible answer.
    """

    @pytest.mark.parametrize("name", sorted(REFUSED))
    def test_it_says_so_rather_than_guessing(self, name):
        with pytest.raises(YamlSubsetError):
            load_documents(REFUSED[name])

    @pytest.mark.parametrize("name", sorted(REFUSED))
    def test_pyyaml_agrees_it_is_either_invalid_or_out_of_subset(self, name):
        loader = reference_loader()
        text = REFUSED[name]
        try:
            list(pyyaml.load_all(text, Loader=loader))
        except pyyaml.YAMLError:
            assert name not in DECLINED_ON_PURPOSE, (
                f"{name!r} is malformed for PyYAML too; it is not a subset limit")
            return
        assert name in DECLINED_ON_PURPOSE, (
            f"{name!r} is valid YAML this reader declines; record it in "
            "DECLINED_ON_PURPOSE")

    # Refusing is not enough. `? a: 1` is also unparseable with its guard deleted, so a
    # test that only asserts "it raised" stays green while the guard it was written for
    # is gone — measured: that mutation survived until this table existed.
    REASONS = {
        "anchor": "anchors are outside the subset",
        "alias": "aliases are outside the subset",
        "explicit tag": "tags are outside the subset",
        "merge key": "merge keys are outside the subset",
        "tab indentation": "tab used for indentation",
        "tab indentation under a key": "tab used for indentation",
        "tab indentation behind a dash": "tab cannot appear in a plain scalar",
        "explicit key": "explicit keys",
        "explicit key in flow": "explicit keys",
        "explicit key in flow without a space": "explicit keys",
        "explicit key in a flow sequence": "explicit keys",
        "flow spanning lines": "close on the line it opened",
        "unterminated single quote": "close on the line it opened",
        "unterminated double quote": "close on the line it opened",
        "duplicate key": "duplicate key",
        "duplicate key in flow": "duplicate key",
        "flow collection as a key": "flow collection used as a mapping key",
        "sequence on a sequence item": "sequence opened directly on a sequence item",
        "empty sequence nested on a sequence item":
            "sequence opened directly on a sequence item",
        "unknown escape": "unknown escape",
        "truncated unicode escape": "truncated or non-hexadecimal",
        "non-hexadecimal unicode escape": "truncated or non-hexadecimal",
        "non-hexadecimal unicode escape with a sign": "truncated or non-hexadecimal",
        "non-hexadecimal unicode escape with a separator": "truncated or non-hexadecimal",
        "comment after a plain scalar": "comment cannot follow a plain scalar",
        "plain scalar holding a colon and a space": "cannot contain ': '",
        "two values in one flow entry": "cannot contain ': '",
        "not a block scalar header": "not a block scalar header",
        "block scalar with an indentation indicator": "not a block scalar header",
        "single-pair mapping in a flow sequence": "single-pair mapping",
        "null key": "null mapping key",
        "empty key": "mapping key is empty",
        "null key in flow": "null mapping key",
        "flow key with no value": "has no value",
        "trailing content after a flow collection": "trailing content after a flow",
        "trailing content after a quoted scalar": "trailing content after a quoted",
        "scalar document": "not a mapping entry",
        "unindented continuation": "content after the end of the document",
        "mapping key with no value": "has no value",
        "content after a document end": "content after a document was ended",
        "a node on a document marker line": "node on a document marker line",
        "a document end that ends nothing": "ends a document that never began",
        "tab after a plain scalar": "tab cannot appear in a plain scalar",
        "tab inside a plain scalar": "tab cannot appear in a plain scalar",
        "tab after a key": "tab cannot appear in a plain scalar",
        "tab inside a flow value": "tab cannot appear in a plain scalar",
        "tab inside a sequence item": "tab cannot appear in a plain scalar",
        "unterminated flow mapping key": "has no value",
        "unterminated flow mapping value": "expected ',' or '}'",
        "unterminated flow sequence": "expected ',' or ']'",
        "flow key holding a bracket": "has no value",
        "sequence item inside a mapping": "sequence item inside a mapping",
    }

    def test_every_refusal_has_a_recorded_reason(self):
        """Five entries had none, so only the weak "it raised" assertion applied to them
        — and one of those guards was deletable with a wrong tree left behind."""
        assert set(self.REASONS) == set(REFUSED), (
            set(REFUSED) ^ set(self.REASONS))

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

    def test_a_refusal_is_the_kind_of_error_a_lockfile_caller_already_catches(self):
        """`history.py` catches `LockfileParseError` and turns it into an unreadable
        snapshot, which is what leaves a repository INDETERMINATE rather than clean.

        The module docstring claimed that outcome while `YamlSubsetError` was a plain
        `ValueError`, so the claim was aspiration, not behaviour: the exception would
        have travelled past the handler and cost the repository its verdict entirely.
        """
        assert issubclass(YamlSubsetError, LockfileParseError)
        with pytest.raises(LockfileParseError):
            load("a: &x 1\n")


class TestItRefusesRatherThanCrashing:
    """A rejection has to arrive as `YamlSubsetError` and nothing else.

    The caller catches that one class. `RecursionError` is not a `ValueError`, so it went
    straight through: 996 bytes of nothing but `-` lines killed a scan on a file PyYAML
    reads without complaint.
    """

    # Parametrised on the name alone, and the input built inside. pytest turns a
    # parameter into part of the test id, GitHub Actions puts the id in an environment
    # variable, and Windows caps those at 32,767 characters -- so passing the 8 KB of
    # brackets directly fails on one platform only, at setup, with a ValueError that
    # names neither the test nor the parser. That has now cost this project two CI runs.
    DEEP = {
        "nested flow sequences": lambda n: "a: " + "[" * n + "]" * n + "\n",
        "nested flow mappings": lambda n: "a: " + "{a: " * n + "1" + "}" * n + "\n",
        "nested block mappings": lambda n: "".join(" " * i + "k:\n" for i in range(n)),
    }

    @pytest.mark.parametrize("name", sorted(DEEP))
    def test_nesting_past_the_bound_is_refused(self, name):
        with pytest.raises(YamlSubsetError) as caught:
            load_documents(self.DEEP[name](2000))
        assert "deeper than" in str(caught.value), str(caught.value)

    def test_a_long_run_of_empty_sequence_items_stays_flat(self):
        """The bound is a backstop, not the fix: these items must not nest at all.

        A thousand empty items became a thousand levels deep because a sequence *item*
        took the branch meant for a mapping *key* -- for a key, a `-` at the same column
        is its sequence; for an item, it is the next item.
        """
        assert load_documents("-\n" * 1000) == [[None] * 1000]

    def test_the_bound_is_exactly_where_it_says_it_is(self):
        """Seven levels is the deepest measured across the corpus; this is 64.

        Pinned at the boundary rather than somewhere comfortably inside it, because an
        off-by-one here refuses a file for no reason and nothing else would notice.
        """
        assert _MAX_DEPTH >= 32
        # Flow nesting counts one level per bracket, so the boundary is exact here.
        def flow(levels):
            return "a: " + "[" * levels + "]" * levels + "\n"
        load_documents(flow(_MAX_DEPTH))
        with pytest.raises(YamlSubsetError) as caught:
            load_documents(flow(_MAX_DEPTH + 1))
        assert "deeper than" in str(caught.value)
        # Block nesting has to clear the deepest real lockfile, measured at seven.
        load_documents("".join(" " * (2 * i) + "k:\n" for i in range(_MAX_DEPTH // 2)))


class TestFindingsFromTheDifferentialRuns:
    """Each of these was a silent disagreement that a comparison caught and no
    hand-written assertion would have."""

    def test_a_no_break_space_is_not_whitespace(self):
        """`str.strip()` removes U+00A0; YAML does not.

        A trailing no-break space in a package name vanished, and the name compared equal
        to a different one -- the sort of near-match an incident report exists to tell
        apart.
        """
        assert load("k: value\u00a0\n") == {"k": "value\u00a0"}
        assert load("\u00a0k: 1\n") == {"\u00a0k": "1"}

    def test_a_document_written_in_flow_style_is_not_split_on_its_first_colon(self):
        assert load('{"a": b, "c": d}\n') == {"a": "b", "c": "d"}

    def test_a_flow_key_may_hold_a_colon(self):
        """`{node@runtime:26.7.0: 2}` was split into the key `node@runtime` and the
        value `26.7.0: 2` -- a package renamed without a word, on a key shape pnpm
        already writes elsewhere in the same file."""
        assert load("k: {node@runtime:26.7.0: 2}\n") == {"k": {"node@runtime:26.7.0": "2"}}
        assert load("k: {https://e.test/a:b: 1}\n") == {"k": {"https://e.test/a:b": "1"}}

    def test_a_comment_in_the_value_position_is_not_the_value(self):
        """`overrides: # see incident 4412` returned the comment text where a version
        belonged. The guard for `a: b # note` existed; it simply never saw the case
        where the comment is the whole of it."""
        assert load("overrides: # see incident 4412\n") == {"overrides": None}
        assert load_documents("- # note\n- b\n") == [[None, "b"]]

    def test_an_empty_flow_value_is_absent_rather_than_empty(self):
        assert load("engines: {node: }\n") == {"engines": {"node": None}}

    def test_content_after_a_document_end_is_not_dropped(self):
        """`...` closed the document and everything after it was thrown away in silence.

        In a lockfile that is the whole failure this project exists to prevent: the
        packages that were installed sit in the part that went missing, and what comes
        back is a shorter file that looks clean.
        """
        with pytest.raises(YamlSubsetError):
            load_documents("a: 1\n...\nb: 2\n")

    def test_a_file_with_nothing_in_it_holds_no_documents(self):
        assert load_documents("") == []
        assert load_documents("# only a comment\n") == []

    def test_an_empty_document_still_counts(self):
        assert load_documents("---\n---\na: 1\n") == [None, {"a": "1"}]

    def test_a_sequence_may_sit_at_its_key_own_column(self):
        assert load("a:\n- x\n- y\n") == {"a": ["x", "y"]}

    def test_a_plain_scalar_that_pyyaml_rejects_is_refused_too(self):
        """The contract runs both ways. Accepting `deprecated: note: this is gone` meant
        reading a broken file as a tree, which is the direction that invents data."""
        with pytest.raises(YamlSubsetError):
            load("deprecated: note: this is gone\n")

    def test_a_malformed_escape_is_an_error_rather_than_a_different_character(self):
        """`int(digits, 16)` accepts " 123", "+123" and "1_23", so `\\u 123` silently
        produced U+0123."""
        for bad in ('a: "\\u 123"\n', 'a: "\\u+123"\n', 'a: "\\u1_23"\n'):
            with pytest.raises(YamlSubsetError):
                load(bad)


class TestTheSuiteItself:
    """One guard, for a trap this project has now fallen into twice."""

    def test_no_parametrised_value_could_overflow_a_windows_test_id(self):
        """pytest folds a parameter into the test id, GitHub Actions puts the id in an
        environment variable, and Windows caps those at 32,767 characters.

        A parameter carrying its own input therefore fails on one platform only, during
        setup, with a `ValueError` naming neither the test nor the parser. Both times it
        happened the fix was the same -- parametrise on a short name and build the input
        inside the test -- so this checks the shape rather than trusting the memory of
        it. It covers any parametrize added to this module later, not just today's.
        """
        module = sys.modules[__name__]
        oversized = []
        for _, cls in inspect.getmembers(module, inspect.isclass):
            for _, function in inspect.getmembers(cls, inspect.isfunction):
                for mark in getattr(function, "pytestmark", ()):
                    if mark.name != "parametrize":
                        continue
                    for value in mark.args[1]:
                        if len(repr(value)) > 400:
                            oversized.append((function.__qualname__, len(repr(value))))
        assert not oversized, oversized


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
