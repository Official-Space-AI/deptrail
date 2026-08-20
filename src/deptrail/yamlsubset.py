"""Read the YAML subset that lockfiles are written in, and refuse the rest.

``pnpm-lock.yaml`` and Yarn Berry's ``yarn.lock`` are YAML, so reading them means
either taking a YAML dependency or writing a reader. This project ships no runtime
dependencies on purpose — a supply-chain forensics tool that carries a supply-chain
dependency argues against itself — so it writes one.

A hand-rolled YAML reader is usually a bad trade, because YAML is large and a parser
that is quietly wrong about a lockfile would report a tree as clean that was not.
Two things make the trade defensible here.

**The subset is measured, not guessed.** Across four real ``pnpm-lock.yaml`` v9 files
and two Yarn Berry lockfiles — 39,112 lines at the largest — anchors, aliases, merge
keys, explicit tags, tab indentation, flow collections spanning lines, and trailing
comments do not occur once. What does occur is block mappings, block sequences,
single-line flow collections, all three scalar styles, one block scalar, full-line
comments, and more than one document in a file.

**Everything outside the subset raises.** ``YamlSubsetError`` reaches the caller as an
unreadable snapshot, which leaves the repository INDETERMINATE rather than clean. This
reader is allowed to answer "I cannot read this"; it is not allowed to guess.

Scalars come back as strings, always, and mappings as plain dicts. YAML's plain-scalar
typing would read ``lockfileVersion: 6.0`` as a float and turn the version ``1.10``
into ``1.1``, which is the wrong answer for a file whose content is version
identifiers. Callers that want a number convert one deliberately.
"""
from __future__ import annotations

# The one construct here that no lockfile in the corpus uses, kept because refusing it
# would cost a verdict rather than a field: `deprecated: >-` folds, and the folded text
# is not something this tool reads. Getting it slightly wrong is free; declining to
# read the file it sits in is not.
_CHOMP = {"-": "strip", "+": "keep", "": "clip"}

# YAML calls space and tab whitespace and nothing else, so `str.strip()` is wrong
# here: it also removes U+00A0 and the rest of Unicode's spaces, which are ordinary
# characters in a package name. Measured against PyYAML on a generated corpus, where
# a trailing no-break space vanished from a scalar that PyYAML kept whole.
_WS = " \t"

# YAML's null is absence rather than a value, which is why an empty `key:` already
# reads as None here. Spelling that absence out loud should mean the same thing.
# Numbers and booleans stay text: `1.10` is a version, not 1.1.
_NULL = frozenset({"null", "Null", "NULL", "~"})

_ESCAPES = {
    '"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n",
    "r": "\r", "t": "\t", "0": "\0", "a": "\a", "v": "\v", "e": "\x1b",
    " ": " ", "N": "\x85", "_": "\xa0", "L": "\u2028", "P": "\u2029",
}


class YamlSubsetError(ValueError):
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

    CRLF matters because this tool runs on Windows, where a checkout can rewrite line
    endings; a trailing carriage return would otherwise become part of every scalar.
    """
    if text.startswith("﻿"):
        text = text[1:]
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
    """Half-open index ranges, one per document.

    Splitting before parsing is safe only because an unterminated quote is an error
    here: no scalar can span lines, so a ``---`` in the first column is always a real
    document marker and never content.
    """
    markers = [i for i, line in enumerate(lines)
               if line.rstrip(_WS) in ("---", "...")]
    if not markers:
        return [(0, len(lines))]

    ranges: list[tuple[int, int]] = []
    # Anything ahead of the first marker is a document in its own right, but only if it
    # holds something: a file opening with `---`, as pnpm's does, has no preamble.
    first = markers[0]
    if any(_significant(line) for line in lines[:first]):
        ranges.append((0, first))
    for position, marker in enumerate(markers):
        end = markers[position + 1] if position + 1 < len(markers) else len(lines)
        if lines[marker].rstrip(_WS) == "...":
            # `...` ends a document without opening one; a following `---` opens the next.
            continue
        ranges.append((marker + 1, end))
    return [(start, end) for start, end in ranges
            if any(_significant(line) for line in lines[start:end])]


def _significant(line: str) -> bool:
    stripped = line.strip(_WS)
    return bool(stripped) and not stripped.startswith("#")


def _skip_blank(lines: list[str], index: int, end: int) -> int:
    while index < end and not _significant(lines[index]):
        index += 1
    return index


def _indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _parse_block(lines: list[str], index: int, end: int, indent: int) -> tuple[object, int]:
    """One block node at column ``indent``, and the index just past it."""
    index = _skip_blank(lines, index, end)
    if index >= end:
        return None, index
    found = _indent_of(lines[index])
    if found < indent:
        return None, index
    if found > indent:
        raise YamlSubsetError(
            f"indented {found} where {indent} was expected", index + 1)
    stripped = lines[index].strip(_WS)
    if stripped == "-" or stripped.startswith("- "):
        return _parse_sequence(lines, index, end, indent)
    if stripped[:1] in ("{", "["):
        # A whole node written in flow style. Without this the line goes to the mapping
        # parser, which splits `{"a": b, "c": d}` at its first `": "` and invents a key
        # named `{"a"` -- a different tree, returned without complaint.
        return _parse_flow_scalar(stripped, index + 1), index + 1
    return _parse_mapping(lines, index, end, indent)


def _parse_mapping(lines: list[str], index: int, end: int,
                   indent: int) -> tuple[dict, int]:
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
        mapping[key], index = _parse_value(lines, index, end, indent, rest)
    return mapping, index


def _parse_sequence(lines: list[str], index: int, end: int,
                    indent: int) -> tuple[list, int]:
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
        if rest.startswith("- "):
            raise YamlSubsetError(
                "a sequence opened directly on a sequence item", index + 1)
        if rest and _looks_like_key(rest):
            # `- key: value` opens a mapping at the column the item's content starts in,
            # and that mapping's later keys line up under it rather than under a second
            # dash. Rewriting the dash as the spaces it stands for lets the ordinary
            # mapping parser read the whole item, rather than a special case that reads
            # the first key and loses the rest -- which is how `- cpu: ppc64` followed by
            # `os: aix` would quietly become a mapping with one key instead of two.
            column = len(line) - len(line.lstrip(" ")) + 1
            while line[column] == " ":
                column += 1
            lines[index] = " " * column + line[column:]
            value, index = _parse_mapping(lines, index, end, column)
        else:
            value, index = _parse_value(lines, index, end, indent, rest)
        items.append(value)
    return items, index


def _parse_value(lines: list[str], index: int, end: int, indent: int,
                 rest: str) -> tuple[object, int]:
    """The value written after ``key:`` or ``-`` on line ``index``, and the next index.

    ``rest`` is what followed on the same line: empty means the value is either a block
    underneath or nothing at all.
    """
    number = index + 1
    if rest.startswith(("|", ">")) and _is_block_scalar_header(rest):
        return _parse_block_scalar(lines, index, end, indent, rest)
    if rest:
        value = _parse_flow_scalar(rest, number)
        return value, index + 1
    following = _skip_blank(lines, index + 1, end)
    if following < end and _indent_of(lines[following]) > indent:
        return _parse_block(lines, following, end, _indent_of(lines[following]))
    return None, index + 1


def _is_block_scalar_header(rest: str) -> bool:
    """``|``, ``>-``, ``|+`` and friends — but not a plain scalar that starts with them."""
    body = rest[1:]
    return body in ("", "-", "+")


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
    """Folded (``>``) scalars: line breaks become spaces, blank lines become breaks.

    Lines that are themselves indented further are "more indented" in YAML's sense and
    keep their breaks.
    """
    out: list[str] = []
    for position, line in enumerate(body):
        if not line.strip(_WS):
            out.append("\n")
            continue
        more_indented = line[:1] == " "
        if out and not out[-1].endswith("\n") and not more_indented:
            out.append(" ")
        elif out and out[-1] == "\n" and position and body[position - 1].strip(_WS):
            pass
        out.append(line if more_indented else line.strip(_WS))
        if more_indented:
            out.append("\n")
    text = "".join(out)
    return text if text.endswith("\n") else text + "\n"


def _is_explicit_key(text: str) -> bool:
    """``? `` opening a key, as against a scalar or a key that merely starts with one."""
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
    return None if text in _NULL else text


def _plain(text: str, number: int) -> str:
    """An unquoted scalar, refused where YAML would read it as something else."""
    if " #" in text:
        # Measured absent from every lockfile in the corpus, and ambiguous if it did
        # appear: YAML would cut a comment here and this reader would not.
        raise YamlSubsetError("a comment cannot follow a plain scalar here", number)
    if text[:1] in ("&", "*", "!"):
        kind = {"&": "anchor", "*": "alias", "!": "tag"}[text[0]]
        raise YamlSubsetError(f"{kind}s are outside the subset", number)
    if text.startswith("<<"):
        raise YamlSubsetError("merge keys are outside the subset", number)
    return text.strip(_WS)


def _scan_flow(text: str, position: int, number: int) -> tuple[object, int]:
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
        if opener == "{":
            if _is_explicit_key(text[position:]):
                raise YamlSubsetError(
                    "explicit keys (`? `) are outside the subset", number)
            quoted_key = text[position:position + 1] in ("'", '"')
            key, position = _scan_flow_scalar(text, position, number, stop=":,}")
            if not quoted_key and key in _NULL:
                raise YamlSubsetError("a null mapping key is outside the subset", number)
            position = _skip_spaces(text, position)
            if text[position:position + 1] != ":":
                raise YamlSubsetError(f"flow mapping key {key!r} has no value", number)
            position = _skip_spaces(text, position + 1)
            value, position = _scan_flow_item(text, position, number, closer)
            if key in container:
                raise YamlSubsetError(f"duplicate key {key!r} in a flow mapping", number)
            container[key] = value
        else:
            value, position = _scan_flow_item(text, position, number, closer)
            container.append(value)
        position = _skip_spaces(text, position)
        if text[position:position + 1] == ",":
            position += 1
        elif text[position:position + 1] != closer:
            raise YamlSubsetError(
                f"expected ',' or {closer!r} in a flow collection", number)


def _scan_flow_item(text: str, position: int, number: int,
                    closer: str) -> tuple[object, int]:
    if text[position:position + 1] in ("{", "["):
        return _scan_flow(text, position, number)
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
        if len(digits) != width:
            raise YamlSubsetError(rf"truncated \{code} escape", number)
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
