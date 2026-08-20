"""Read the YAML subset that lockfiles are written in, and refuse the rest.

``pnpm-lock.yaml`` and Yarn Berry's ``yarn.lock`` are YAML, so reading them means either
taking a YAML dependency or writing a reader. This project ships no runtime dependencies
on purpose — a supply-chain forensics tool that carries a supply-chain dependency argues
against itself — so it writes one.

A hand-rolled YAML reader is usually a bad trade, because YAML is large and a parser
that is quietly wrong about a lockfile would report a tree as clean that was not. Three
things make the trade defensible here.

**The subset is measured, not guessed.** Checked against 1,505 real lockfiles: every
pnpm ``lockfileVersion`` in the wild (5.1, 5.3, 5.4, 6.0, 6.1, 9.0) and every Yarn Berry
``__metadata.version`` (4, 5, 6, 8, 10), including 1,193 historical ``pnpm-lock.yaml``
blobs from one repository's full history — the case that matters most, because this tool
walks history rather than HEAD and meets five lockfile versions in one repository's past.
Anchors, aliases, merge keys, explicit tags, tab indentation, flow collections spanning
lines, and trailing comments do not occur once. What does occur is block mappings, block
sequences, single-line flow collections, all three scalar styles, block scalars,
full-line comments, and more than one document in a file.

**Everything outside the subset raises, and raises something the caller already
catches.** ``YamlSubsetError`` is a ``LockfileParseError``, which is what ``history.py``
turns into an unreadable snapshot — and an unreadable snapshot leaves the repository
INDETERMINATE rather than clean. It was a bare ``ValueError`` until a review pointed out
that the sentence above was therefore false: the error would have travelled straight
past the handler it names. This reader is allowed to answer "I cannot read this"; it is
not allowed to guess, and it is not allowed to fail in a way its caller does not expect.

**The claim is checked rather than asserted.** PyYAML is a test-only dependency, and the
suite parses the corpus both ways on every run. The contract is not "this parser is
correct" — that would be a claim about YAML at large, which this deliberately does not
implement. It is: return what PyYAML returns, or raise. A silent disagreement fails the
build.

Scalars come back as strings, always, and mappings as plain dicts. YAML's plain-scalar
typing would read ``lockfileVersion: 6.0`` as a float and turn the version ``1.10`` into
``1.1``, which is the wrong answer for a file whose content is version identifiers.
Callers that want a number convert one deliberately. Null is the exception, because
absence is structure rather than text: ``key:``, ``key: null`` and ``key: ~`` all read as
``None``.

**A note for whoever writes the pnpm parser.** ``load_documents`` returns a list because
``pnpm-lock.yaml`` really can hold more than one document, and nothing in the content
tells them apart: measured on ``pnpm/pnpm``, both documents carry ``lockfileVersion:
'9.0'`` and both have ``packages`` and ``snapshots``, while the first holds 9 packages
and the second 1,678. Reaching for ``documents[0]`` there reports the 9 and calls the
rest absent, which is a clean verdict for a tree that was never opened. Refuse a lockfile
whose documents disagree about what they are, rather than picking one — refusing costs a
verdict and says so, picking wrong invents one. ``load`` already refuses anything that is
not exactly one document.
"""
from __future__ import annotations

import string

from .lockfile import LockfileParseError

# Folded scalars (`>`) appear in no lockfile in the corpus, and are implemented rather
# than refused because refusing would cost a whole repository its verdict over a
# `deprecated:` message nothing reads. "Slightly wrong is free" was the original excuse
# and it was wrong: what a careless fold drops is a line break, not whitespace, so this
# is measured against PyYAML like everything else.
_CHOMP = {"-": "strip", "+": "keep", "": "clip"}

# `str.strip()` is wrong here: it also removes U+00A0 and the rest of Unicode's spaces,
# which are ordinary characters in a package name -- measured against PyYAML, where a
# trailing no-break space vanished from a scalar PyYAML kept whole. Tab is left out for
# the opposite reason: PyYAML rejects a tab in every plain-scalar position, so stripping
# one would turn a file it calls broken into a value, and `_plain` refuses it instead.
_WS = " "

# YAML's null is absence rather than a value, which is why an empty `key:` already
# reads as None here. Spelling that absence out loud should mean the same thing.
# Numbers and booleans stay text: `1.10` is a version, not 1.1.
_NULL = frozenset({"null", "Null", "NULL", "~"})

# Recursion, not taste. Every nesting level costs two Python frames, so a 996-byte file
# of nothing but `-` lines used to raise RecursionError -- which is not a
# YamlSubsetError, so it walked straight through the caller's handler and killed the
# scan on a file PyYAML reads without complaint. The deepest real lockfile measured is
# seven levels, so this is an order of magnitude of headroom.
_MAX_DEPTH = 64

_ESCAPES = {
    '"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n",
    "r": "\r", "t": "\t", "0": "\0", "a": "\a", "v": "\v", "e": "\x1b",
    " ": " ", "N": "\x85", "_": "\xa0", "L": "\u2028", "P": "\u2029",
}


class YamlSubsetError(LockfileParseError):
    """The input is not in the subset of YAML this reader is measured against.

    Raised both for genuinely malformed YAML and for valid YAML using a construct
    outside the subset. The distinction does not matter to the caller: either way the
    file was not read, and a file that was not read cannot clear anybody.
    """

    def __init__(self, message: str, line: int | None = None):
        self.line = line
        super().__init__(f"line {line}: {message}" if line else message)


def load_documents(text: str) -> list[object]:
    """Every YAML document in ``text``, in order.

    A list rather than a single value because ``pnpm-lock.yaml`` really can hold more
    than one document: pnpm 12 writes the package manager's own pinned install as a
    separate document ahead of the project's. Reading only the first one silently
    dropped 25,430 lines of a 25,528-line lockfile when this was measured against
    ``pnpm/pnpm``, so the caller is handed all of them and has to say what it wants.
    """
    lines = _prepare(text)
    documents: list[object] = []
    for start, end in _document_ranges(lines):
        value, index = _parse_block(lines, start, end, indent=0)
        index = _skip_blank(lines, index, end)
        if index < end:
            raise YamlSubsetError(
                f"content after the end of the document: {lines[index].strip(_WS)!r}",
                index + 1)
        documents.append(value)
    return documents


def load(text: str) -> object:
    """The single document in ``text``, or an error if there is not exactly one."""
    documents = load_documents(text)
    if len(documents) != 1:
        raise YamlSubsetError(f"expected one document, found {len(documents)}")
    return documents[0]


def _prepare(text: str) -> list[str]:
    """Split into lines, drop a BOM, normalise line endings, and reject tab indents.

    The one caller in this project pipes ``git show`` through ``subprocess`` with
    ``text=True``, which already applies universal newlines, so CRLF never reaches here
    by that route — the earlier comment claiming Windows checkouts made this load-bearing
    described a path that does not exist. It is kept for the caller that reads a file
    itself, where a trailing carriage return would otherwise end every scalar.
    """
    if text.startswith("﻿"):
        text = text[1:]
    # `.replace().replace().split()` made three full copies of the text, which cost 1.5 GB
    # peak on a 100 MB input; a MemoryError there is not a YamlSubsetError either. Almost
    # every real file is LF or CRLF, and both are handled by dropping one trailing
    # carriage return per line. Only a lone CR mid-line needs the expensive path.
    lines = [line[:-1] if line[-1:] == "\r" else line for line in text.split("\n")]
    if any("\r" in line for line in lines):
        lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if lines and lines[-1] == "":
        # The newline that ends a file is a terminator, not an empty last line, and a
        # block scalar written `|+` would otherwise keep it as content.
        lines.pop()
    for number, line in enumerate(lines, 1):
        stripped = line.lstrip(" ")
        if stripped.startswith("\t") or (line and line[0] == "\t"):
            raise YamlSubsetError("tab used for indentation", number)
    return lines


def _document_ranges(lines: list[str]) -> list[tuple[int, int]]:
    """Half-open index ranges, one per document, empty documents included.

    Splitting before parsing is safe only because an unterminated quote is an error
    here: no scalar can span lines, so a `---` in the first column is always a real
    marker and never content.

    An empty document is kept rather than dropped, because the count is load-bearing --
    a caller reading a multi-document lockfile decides what to do per document, and
    silently renumbering them hides one.
    """
    ranges: list[tuple[int, int, bool]] = []
    start, opened, ended = 0, False, False
    for index, line in enumerate(lines):
        stripped = line.rstrip(_WS)
        if line[:1] in ("-", ".") and stripped[:4] in ("--- ", "... "):
            # `--- a: 1` is a document marker with a node on the same line. Left
            # unrecognised the whole line goes to the mapping parser, which reads a key
            # named `--- a` -- a package name that was never in the file.
            raise YamlSubsetError(
                "a node on a document marker line is outside the subset", index + 1)
        if stripped not in ("---", "..."):
            if ended and _significant(line):
                # Dropping this quietly is how 25,430 lines would go missing.
                raise YamlSubsetError(
                    "content after a document was ended by `...`", index + 1)
            continue
        held = _holds_content(lines, start, index)
        if stripped == "..." and not (opened or held):
            raise YamlSubsetError("`...` ends a document that never began", index + 1)
        if opened or held:
            ranges.append((start, index, opened))
        start = index + 1
        opened, ended = stripped == "---", stripped == "..."
    if opened or _holds_content(lines, start, len(lines)):
        ranges.append((start, len(lines), opened))
    return [(begin, finish) for begin, finish, _ in ranges]


def _holds_content(lines: list[str], start: int, end: int) -> bool:
    return any(_significant(line) for line in lines[start:end])


def _deeper(depth: int, index: int) -> int:
    depth += 1
    if depth > _MAX_DEPTH:
        raise YamlSubsetError(f"nested deeper than {_MAX_DEPTH} levels", index + 1)
    return depth


def _significant(line: str) -> bool:
    stripped = line.strip(_WS)
    return bool(stripped) and not stripped.startswith("#")


def _skip_blank(lines: list[str], index: int, end: int) -> int:
    while index < end and not _significant(lines[index]):
        index += 1
    return index


def _indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _parse_block(lines: list[str], index: int, end: int, indent: int,
                 depth: int = 0) -> tuple[object, int]:
    """One block node at column ``indent``, and the index just past it.

    ``depth`` is counted by whoever descends, not here: a mapping and the sequence it
    dispatches to are the same level, and counting in both places halved the bound.
    """
    index = _skip_blank(lines, index, end)
    if index >= end:
        return None, index
    # No indentation check here. Both callers already fix `indent` to this line's own
    # column -- `load_documents` at zero, `_parse_value` from the line it just measured --
    # so a mismatch is unreachable, and a guard nothing can reach is a guard nothing can
    # test. A line at the wrong column is caught where it is actually read, by the loop
    # in `_parse_mapping` or `_parse_sequence` and then by the trailing-content check.
    stripped = lines[index].strip(_WS)
    if stripped == "-" or stripped.startswith("- "):
        return _parse_sequence(lines, index, end, indent, depth)
    if stripped[:1] in ("{", "["):
        # A whole node written in flow style. Without this the line goes to the mapping
        # parser, which splits `{"a": b, "c": d}` at its first `": "` and invents a key
        # named `{"a"` -- a different tree, returned without complaint.
        return _parse_flow_scalar(stripped, index + 1), index + 1
    return _parse_mapping(lines, index, end, indent, depth)


def _parse_mapping(lines: list[str], index: int, end: int, indent: int,
                   depth: int = 0) -> tuple[dict, int]:
    mapping: dict[str, object] = {}
    while True:
        index = _skip_blank(lines, index, end)
        if index >= end or _indent_of(lines[index]) != indent:
            break
        line = lines[index]
        if line.lstrip(" ").startswith("- "):
            raise YamlSubsetError("sequence item inside a mapping", index + 1)
        key, rest = _split_key(line.strip(_WS), index + 1)
        if key in mapping:
            # Last-one-wins is what YAML implementations do, but a duplicate key in a
            # lockfile means two answers to "what was installed" and no way to tell
            # which the package manager used.
            raise YamlSubsetError(f"duplicate key {key!r}", index + 1)
        # Only a mapping key may own a sequence written at its own column; see
        # `_parse_value`.
        mapping[key], index = _parse_value(lines, index, end, indent, rest, depth,
                                           owns_sibling_sequence=True)
    return mapping, index


def _parse_sequence(lines: list[str], index: int, end: int, indent: int,
                    depth: int = 0) -> tuple[list, int]:
    items: list[object] = []
    while True:
        index = _skip_blank(lines, index, end)
        if index >= end or _indent_of(lines[index]) != indent:
            break
        line = lines[index]
        stripped = line.strip(_WS)
        if stripped != "-" and not stripped.startswith("- "):
            break
        rest = stripped[2:].strip(_WS) if stripped != "-" else ""
        if rest[:1] == "#":
            # The whole value is a comment, so there is no value. Reading the comment
            # text as the value is what happened before, which put `# see incident 4412`
            # in a lockfile where a version belonged.
            rest = ""
        if rest == "-" or rest.startswith("- "):
            # `- -` is a nested sequence exactly as `- - x` is; testing only for the
            # trailing space let the bare form through as the string "-".
            raise YamlSubsetError(
                "a sequence opened directly on a sequence item", index + 1)
        if rest and _looks_like_key(rest):
            # `- key: value` opens a mapping at the column the item's content starts in,
            # and that mapping's later keys line up under it rather than under a second
            # dash. Rewriting the dash as the spaces it stands for lets the ordinary
            # mapping parser read the whole item, rather than a special case that reads
            # the first key and loses the rest -- which is how `- cpu: ppc64` followed by
            # `os: aix` would quietly become a mapping with one key instead of two.
            # A tab here cannot survive to be rewritten: `_looks_like_key` runs `_plain`
            # over the key, and `_plain` refuses a tab, so such a line has already been
            # sent down the ordinary value path and refused there.
            column = len(line) - len(line.lstrip(" ")) + 1
            while line[column] == " ":
                column += 1
            lines[index] = " " * column + line[column:]
            value, index = _parse_mapping(lines, index, end, column, _deeper(depth, index))
        else:
            value, index = _parse_value(lines, index, end, indent, rest, depth)
        items.append(value)
    return items, index


def _parse_value(lines: list[str], index: int, end: int, indent: int, rest: str,
                 depth: int = 0, *,
                 owns_sibling_sequence: bool = False) -> tuple[object, int]:
    """The value written after ``key:`` or ``-`` on line ``index``, and the next index.

    ``rest`` is what followed on the same line: empty means the value is either a block
    underneath or nothing at all.

    ``owns_sibling_sequence`` is what separates a mapping key from a sequence item. YAML
    lets a sequence sit at its own *key's* column, and a key has no other reading for
    one. A sequence *item* does: the next `-` at the same column is the item after it,
    not a child of it. Letting both take the same branch made `-` followed by `-` nest
    instead of appending -- ten empty items became ten levels deep, and about a thousand
    of them exhausted the interpreter's stack on a file PyYAML reads without complaint.
    """
    number = index + 1
    if rest[:1] == "#":
        rest = ""
    if rest[:1] in ("|", ">"):
        if not _is_block_scalar_header(rest):
            # `|` and `>` cannot open a plain scalar in YAML, so `k: |pipe` is not the
            # string "|pipe"; it is a file this reader has no reading for.
            raise YamlSubsetError(
                f"not a block scalar header: {rest!r}", number)
        return _parse_block_scalar(lines, index, end, indent, rest)
    if rest:
        return _parse_flow_scalar(rest, number), index + 1
    following = _skip_blank(lines, index + 1, end)
    if following < end:
        found = _indent_of(lines[following])
        if found > indent:
            return _parse_block(lines, following, end, found, _deeper(depth, index))
        after = lines[following].strip(_WS)
        if (owns_sibling_sequence and found == indent
                and (after == "-" or after.startswith("- "))):
            return _parse_sequence(lines, following, end, indent, _deeper(depth, index))
    return None, index + 1


def _is_block_scalar_header(rest: str) -> bool:
    """``|``, ``>-``, ``|+`` and friends — but not a plain scalar that starts with them."""
    return rest[1:] in ("", "-", "+")


def _parse_block_scalar(lines: list[str], index: int, end: int, indent: int,
                        header: str) -> tuple[str, int]:
    style, chomp = header[0], header[1:]
    index += 1
    block: list[str] = []
    inner: int | None = None
    while index < end:
        line = lines[index]
        if line.strip(_WS) and _indent_of(line) <= indent:
            break
        if line.strip(_WS) and inner is None:
            inner = _indent_of(line)
        block.append(line)
        index += 1
    mode = _CHOMP[chomp]
    if inner is None:
        return ("\n" * len(block)) if mode == "keep" else "", index
    body = [line[inner:] if len(line) > inner else "" for line in block]
    text = "".join(f"{line}\n" for line in body) if style == "|" else _fold(body)
    if mode == "strip":
        return text.rstrip("\n"), index
    if mode == "clip":
        # One break kept, however many the block ended with.
        return text.rstrip("\n") + "\n" if text.strip("\n") else "", index
    return text, index


def _fold(body: list[str]) -> str:
    """Folded (``>``) scalars: one break between ordinary lines becomes a space.

    A line indented further than the block is "more indented" in YAML's sense: its break
    is kept, and so is the break before it. Blank lines contribute a newline each.

    Lines are emitted as they stand. Two earlier versions stripped trailing whitespace
    -- first on every line, then only where the break folded -- and PyYAML disagreed with
    both: it keeps those spaces, so a folded value came back shorter than the file said.
    """
    out: list[str] = []
    started = False
    previous_more = False
    blanks = 0
    for line in body:
        if not line:
            # Emptiness is measured after the block's own indentation is removed, so a
            # line of nothing but spaces is a *more indented* line whose content is
            # those spaces -- not a break. Treating it as one dropped a line PyYAML kept.
            blanks += 1
            continue
        more = line[:1] in (" ", "\t")
        if started:
            if blanks:
                out.append("\n" * blanks)
            elif more or previous_more:
                out.append("\n")
            else:
                out.append(" ")
        elif blanks:
            # Blank lines ahead of the first content line are breaks too; dropping them
            # shortened the value by exactly the newlines a reader would see.
            out.append("\n" * blanks)
        out.append(line)
        started, previous_more, blanks = True, more, 0
    # `started` is always true by here: the caller only folds once it has found a line
    # with content, and that line is non-empty after its indentation comes off.
    out.append("\n" * (blanks + 1))
    return "".join(out)


def _is_explicit_key(text: str) -> bool:
    """``? `` opening a key in block context, not a scalar that merely starts with one.

    Flow context does not go through here: there any ``?`` opens an explicit key, and
    ``_scan_flow`` refuses it without asking about the space.
    """
    return text[:1] == "?" and (len(text) == 1 or text[1] in _WS)


def _looks_like_key(text: str) -> bool:
    try:
        _split_key(text, 0)
    except YamlSubsetError:
        return False
    return True


def _split_key(text: str, number: int) -> tuple[str, str]:
    """``key: value`` into its two halves, respecting quotes around the key."""
    if text[:1] in ("{", "["):
        raise YamlSubsetError(
            "a flow collection used as a mapping key is outside the subset", number)
    if _is_explicit_key(text):
        # `? key : value` writes the key out of line. Left unrecognised it parses as a
        # plain key named `?` -- or as one enormous key swallowing the value -- so it is
        # refused rather than guessed at. Quoted `'?'` is an ordinary key and stays one.
        raise YamlSubsetError("explicit keys (`? `) are outside the subset", number)
    if text[:1] in ("'", '"'):
        key, position = _scan_quoted(text, 0, number)
        if text[position:position + 1] != ":":
            raise YamlSubsetError("quoted key is not followed by ':'", number)
        return key, text[position + 1:].strip(_WS)
    for position, character in enumerate(text):
        if character != ":":
            continue
        if position + 1 == len(text) or text[position + 1] == " ":
            key = text[:position].strip(_WS)
            if not key:
                raise YamlSubsetError("mapping key is empty", number)
            if key in _NULL:
                raise YamlSubsetError("a null mapping key is outside the subset", number)
            return _plain(key, number), text[position + 1:].strip(_WS)
    raise YamlSubsetError(f"not a mapping entry: {text!r}", number)


def _parse_flow_scalar(text: str, number: int) -> object:
    """A value written on one line: flow collection or scalar."""
    if text[:1] in ("{", "["):
        value, position = _scan_flow(text, 0, number)
        if text[position:].strip(_WS):
            raise YamlSubsetError(
                f"trailing content after a flow collection: {text[position:].strip(_WS)!r}",
                number)
        return value
    if text[:1] in ("'", '"'):
        value, position = _scan_quoted(text, 0, number)
        if text[position:].strip(_WS):
            raise YamlSubsetError(
                f"trailing content after a quoted scalar: {text[position:].strip(_WS)!r}",
                number)
        return value
    return _null_or(_plain(text, number))


def _null_or(text: str) -> str | None:
    # The empty scalar is null in YAML too, which is what `{a: }` writes. Returning ""
    # made a flow mapping disagree with the block parser about the same absence.
    return None if text == "" or text in _NULL else text


def _plain(text: str, number: int) -> str:
    """An unquoted scalar, refused where YAML would read it as something else."""
    if "\t" in text:
        # PyYAML rejects a tab in every plain-scalar position -- before, inside and after
        # -- and accepts one only inside a quoted scalar or a block scalar body, neither
        # of which comes through here. Stripping it instead turned `a: b<TAB>` into the
        # value "b", which is a file PyYAML calls broken read as one that is not.
        raise YamlSubsetError("a tab cannot appear in a plain scalar", number)
    if ": " in text or text.endswith(":"):
        # A plain scalar cannot carry `": "` in YAML -- `deprecated: note: this is gone`
        # is a broken file, not a value. Reading it as one meant accepting input PyYAML
        # rejects, which is the direction this reader is not allowed to fail in.
        raise YamlSubsetError(f"a plain scalar cannot contain ': ': {text!r}", number)
    if " #" in text:
        # Measured absent from every lockfile in the corpus, and ambiguous if it did
        # appear: YAML would cut a comment here and this reader would not.
        raise YamlSubsetError("a comment cannot follow a plain scalar here", number)
    if text[:1] in ("&", "*", "!"):
        kind = {"&": "anchors", "*": "aliases", "!": "tags"}[text[0]]
        raise YamlSubsetError(f"{kind} are outside the subset", number)
    if text.startswith("<<"):
        raise YamlSubsetError("merge keys are outside the subset", number)
    return text.strip(_WS)


def _scan_flow(text: str, position: int, number: int,
               depth: int = 0) -> tuple[object, int]:
    depth = _deeper(depth, number - 1)
    opener = text[position]
    closer = "}" if opener == "{" else "]"
    container: object = {} if opener == "{" else []
    position += 1
    while True:
        position = _skip_spaces(text, position)
        if position >= len(text):
            raise YamlSubsetError(
                "a flow collection has to close on the line it opened", number)
        if text[position] == closer:
            return container, position + 1
        if text[position] == "?":
            # In flow context any `?` opens an explicit key, with or without the space
            # that block context requires. Testing for the space missed `{?a: 1}`, which
            # then parsed as an ordinary key named `?a`.
            raise YamlSubsetError("explicit keys (`? `) are outside the subset", number)
        if opener == "{":
            quoted_key = text[position] in ("'", '"')
            if quoted_key:
                key, position = _scan_quoted(text, position, number)
            else:
                key, position = _scan_flow_key(text, position, number)
                if key in _NULL or key == "":
                    raise YamlSubsetError(
                        "a null mapping key is outside the subset", number)
            position = _skip_spaces(text, position)
            if text[position:position + 1] != ":":
                raise YamlSubsetError(f"flow mapping key {key!r} has no value", number)
            position = _skip_spaces(text, position + 1)
            value, position = _scan_flow_item(text, position, number, closer, depth)
            if key in container:
                raise YamlSubsetError(f"duplicate key {key!r} in a flow mapping", number)
            container[key] = value
        else:
            value, position = _scan_flow_item(text, position, number, closer, depth)
            if text[_skip_spaces(text, position):][:1] == ":":
                raise YamlSubsetError(
                    "a single-pair mapping inside a flow sequence is outside the subset",
                    number)
            container.append(value)
        position = _skip_spaces(text, position)
        if text[position:position + 1] == ",":
            position += 1
        elif text[position:position + 1] != closer:
            raise YamlSubsetError(
                f"expected ',' or {closer!r} in a flow collection", number)


def _scan_flow_key(text: str, position: int, number: int) -> tuple[str, int]:
    """An unquoted key inside a flow mapping.

    A colon ends the key only where YAML says it does: followed by a space, by a flow
    indicator, or by the end of the line. Stopping at *any* colon split
    ``{node@runtime:26.7.0: 2}`` into the key ``node@runtime`` and the value
    ``26.7.0: 2`` -- a package renamed without a word, on a key shape pnpm already
    writes elsewhere in the same file.
    """
    start = position
    while position < len(text):
        character = text[position]
        if character in ",{}[]":
            break
        if character == ":" and text[position + 1:position + 2] in ("", " ", ",", "}",
                                                                    "]", "{", "["):
            break
        position += 1
    return _plain(text[start:position], number), position


def _scan_flow_item(text: str, position: int, number: int, closer: str,
                    depth: int = 0) -> tuple[object, int]:
    if text[position:position + 1] in ("{", "["):
        return _scan_flow(text, position, number, depth)
    quoted = text[position:position + 1] in ("'", '"')
    value, position = _scan_flow_scalar(text, position, number, stop="," + closer)
    return (value if quoted else _null_or(value)), position


def _scan_flow_scalar(text: str, position: int, number: int,
                      stop: str) -> tuple[str, int]:
    if text[position:position + 1] in ("'", '"'):
        return _scan_quoted(text, position, number)
    start = position
    while position < len(text) and text[position] not in stop:
        position += 1
    return _plain(text[start:position], number), position


def _scan_quoted(text: str, position: int, number: int) -> tuple[str, int]:
    quote = text[position]
    position += 1
    out: list[str] = []
    while position < len(text):
        character = text[position]
        if character == quote:
            if quote == "'" and text[position + 1:position + 2] == "'":
                out.append("'")
                position += 2
                continue
            return "".join(out), position + 1
        if character == "\\" and quote == '"':
            position = _unescape(text, position, number, out)
            continue
        out.append(character)
        position += 1
    raise YamlSubsetError("a quoted scalar has to close on the line it opened", number)


def _unescape(text: str, position: int, number: int, out: list[str]) -> int:
    code = text[position + 1:position + 2]
    if code in ("x", "u", "U"):
        width = {"x": 2, "u": 4, "U": 8}[code]
        digits = text[position + 2:position + 2 + width]
        if len(digits) != width or not all(c in string.hexdigits for c in digits):
            # `int(digits, 16)` accepts " 123", "+123" and "1_23", so a malformed escape
            # produced a wrong character in silence rather than an error.
            raise YamlSubsetError(rf"truncated or non-hexadecimal \{code} escape", number)
        try:
            out.append(chr(int(digits, 16)))
        except ValueError as error:
            raise YamlSubsetError(rf"bad \{code} escape {digits!r}", number) from error
        return position + 2 + width
    if code in _ESCAPES:
        out.append(_ESCAPES[code])
        return position + 2
    raise YamlSubsetError(rf"unknown escape \{code}", number)


def _skip_spaces(text: str, position: int) -> int:
    while position < len(text) and text[position] == " ":
        position += 1
    return position
