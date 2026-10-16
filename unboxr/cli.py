"""The `unboxr` command line.

A DELIBERATE FLOOR, and one that has now been added to four times. It opens
an archive into a destination directory, says where the result is, and
summarises what could not be opened. On request -- and only on request -- it
also writes the extraction document: a CycloneDX inventory of the corpus, one
file per component with its digest, plus every container that was not opened
and why. On request again, that document says which other BOM it belongs to.
And on request once more it opens nothing at all: `--list-formats` prints
what THIS machine does with every extension the package recognises, in four
states, and exits.

WHAT IS STILL NOT THIS FLOOR. There is no self-check gate, no strict mode, and
no verdict of any kind. The command does not fetch, open or resolve the BOM it
is given the URN of, and it does not compose that URN: it is handed one, it
checks its shape, and it refuses what it cannot recognise. `--list-formats`
says what this installation CAN open, never what an archive contains, and it
neither installs nor suggests installing anything.

THE LISTING IS A RENDERING, NOT A SECOND TABLE. Everything it prints comes
from `unboxr.extraction.project_format_support()`, which is where the
extension tables live. What belongs to this module is the English a human
reads -- the headings and the notes under them -- and not one count: a total
computed here would be a figure to drift away from the tables the day an
extension is added.

WHAT CHANGED, AND WHY IT MATTERS MORE THAN IT LOOKS. This command used to learn
about amputations of the corpus by READING ITS OWN LOGGING RECORDS: a
`logging.Filter` sat on the handler and matched each record against the exact
format strings the library emits. It worked, and it was fragile -- a counter
matching on a format string is the very "discipline of print" a structured
report exists to replace, and it counted RECORDS, so one office container seen
at four call sites and at every nesting level counted several times over.

The count now comes from the report the library RETURNS, where the identity of
an entry is the pair (cause, path). One container, one entry.

The filter that survives is `_QuietFilter`, and it survives for a reason of its
own: `--quiet` must never drop below what declares an amputation, and the most
frequent amputation of all -- an office container being refused -- is emitted at
the INFORMATIONAL level. That filter reads the format strings from
`unboxr.report`, the table's one home, never from a copy.

THE PROGRESS LINE FOLLOWS THE SAME RULE. It is drawn from the `ProgressEvent`s
`prepare_source` hands a callable, never from the records the library logs,
and it is drawn only for a person watching a terminal: in a pipe, a file or
under `--quiet`, stderr carries exactly what it carried before the line
existed.

This module is the ONLY place in the package that configures logging, and the
only place that writes a file the caller asked for. The library never does
either (see `unboxr/__init__.py`): `unboxr.sbom` RETURNS a structure, and the
writing is a separate gesture, taken here.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import logging
import os
import shutil
import sys
import textwrap
import threading
import time
import unicodedata
from pathlib import Path

from . import __version__
from . import sbom
from .extraction import (
    FORMAT_SUPPORT_STATES,
    STATE_DELEGATED_TO_SEVEN_ZIP,
    STATE_OPENED_BY_THE_STANDARD_LIBRARY,
    STATE_RECOGNISED_AND_NOT_OPENED,
    STATE_RECOGNISED_AND_REFUSED,
    is_url,
    new_report,
    prepare_source,
    project_format_support,
    resolve_extraction_root,
)
from .report import AMPUTATION_MESSAGES, ORACLE_REMINDER_SENTENCE, text_for

# COMPOSED on the one constant, never retyped: the sentence itself lives in
# `unboxr.report`, where the document builder can also read it. What belongs to
# this module is the counting prefix, which is a logging concern and has no
# place in a document.
ORACLE_REMINDER = (
    "%s container(s) were not opened during this run. " + ORACLE_REMINDER_SENTENCE
)

# The two per-entry format strings `summarise` logs from the report -- its own
# deduplicated declaration, distinct from the raw per-event messages of
# `AMPUTATION_MESSAGES` emitted while extraction is still running. `--quiet`
# must keep both: the aggregate is what a caller who missed the live warnings
# (or who only ever reads the failure path, where `summarise` runs once, at
# the end) is left with. Named here, not inlined twice, so the filter and the
# emitter cannot drift apart. Verified in code review.
NOT_OPENED_LINE = "Not opened -- %s: %s"
STILL_IN_TREE_LINE = "In the tree, elsewhere -- %s: %s"


class _QuietFilter(logging.Filter):
    """Under `--quiet`, keeps warnings AND every named amputation.

    `--quiet` never drops below what declares an amputation. The most frequent
    amputation of all -- an office container being refused -- is emitted at the
    informational level, so a quiet mode that simply raised the threshold to
    warnings would silence it. Muting an amputation on request would contradict
    the positive-only oracle this package is built on.

    It matches on the format strings of `unboxr.report`, the table's one home,
    plus `summarise`'s own two aggregate lines -- its report-driven replacement
    for the per-event messages, which quiet mode must not hide either.
    A copy kept here would drift from it the first time a message was reworded,
    and nothing would say so.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        return (record.levelno >= logging.WARNING
                or record.msg in AMPUTATION_MESSAGES.values()
                or record.msg in (NOT_OPENED_LINE, STILL_IN_TREE_LINE))


# The English a human reads for each of the four states. The STATES are named
# in `unboxr.extraction`, beside the tables that produce them; the prose is
# here, because a library that carried the sentences a command prints would
# have to be reworded to reword a heading.
#
# LOOKED UP, NEVER DEFAULTED. A state added to the report and forgotten here
# raises `KeyError` on the first run, loudly, at the top of the listing. A
# `.get()` with a fallback heading would print that state under a made-up name,
# which is how a listing starts lying about what it is showing.
FORMAT_STATE_HEADINGS = {
    STATE_OPENED_BY_THE_STANDARD_LIBRARY: "Opened by the standard library",
    STATE_DELEGATED_TO_SEVEN_ZIP: "Delegated to an external 7-Zip binary",
    STATE_RECOGNISED_AND_REFUSED: "Recognised and refused",
    STATE_RECOGNISED_AND_NOT_OPENED: "Recognised and deliberately not opened",
}

# THREE ENTRIES AND NOT FOUR, deliberately: the delegated state is the one
# whose note depends on what this machine has, so it carries two of its own
# below and none here. A fourth entry written here would be the one never
# printed, and the first reader to reword it would reword nothing.
FORMAT_STATE_NOTES = {
    STATE_OPENED_BY_THE_STANDARD_LIBRARY:
        "Opened here and on every machine: no binary, no dependency, nothing "
        "to install.",
    STATE_RECOGNISED_AND_REFUSED:
        "Recognised so that the chain refuses them out loud rather than "
        "passing over them in silence. No machine opens these: the standard "
        "library has no reader for them here, and 7-Zip does not handle the "
        "format either. It is not a capability that installing something adds.",
    STATE_RECOGNISED_AND_NOT_OPENED:
        "Opened by nothing, on purpose. These are ZIP containers unboxr knows "
        "how to open and CHOOSES not to: an office document expands to "
        "presentation markup and packaging parts, which is not the material a "
        "caller asked for. The choice is made on the NAME a file carries, "
        "never on what is inside it.",
}

# The same four states, named for the one line that counts them all. NOT the
# headings above put through `.lower()`: that lower-cased `7-Zip` into a brand
# name nobody writes, and it would do the same to the next proper noun that
# entered a heading. Two registers, two strings, and the tie between them is
# the KEY -- which is why both tables are keyed on the state and iterated
# through `FORMAT_SUPPORT_STATES`, so a state can go missing from neither.
FORMAT_STATE_SUMMARY_LABELS = {
    STATE_OPENED_BY_THE_STANDARD_LIBRARY: "by the standard library",
    STATE_DELEGATED_TO_SEVEN_ZIP: "delegated to 7-Zip",
    STATE_RECOGNISED_AND_REFUSED: "recognised and refused",
    STATE_RECOGNISED_AND_NOT_OPENED: "recognised and not opened",
}

# The delegated state is the one whose note depends on the machine, so it has
# two -- and the absent case says what is NOT being claimed: these extensions
# are listed because they are recognised. A listing that dropped them on a
# machine without the binary would assert that unboxr does not know them,
# which is a different statement, and a false one.
SEVEN_ZIP_AVAILABLE_NOTE = (
    "AVAILABLE on this machine: opened by handing them to the binary named "
    "above. On a machine without it, these same extensions are recognised and "
    "not openable.")
SEVEN_ZIP_MISSING_NOTE = (
    "NOT AVAILABLE on this machine: recognised, and not openable here. They "
    "are listed because unboxr recognises them, not because it can open them "
    "-- removing them from this listing would say it does not know them at "
    "all. unboxr neither bundles, downloads nor installs 7-Zip.")

# What a state with nothing in it says. A heading, a note explaining what
# would be in it, and then four lines of prose about extensions followed by a
# blank line where the extensions should be -- that is what an emptied state
# printed until code review on 15 September 2026, and a reader has no way to
# tell it from a rendering that lost them. A state with nothing in it says so,
# in one line, and the note that describes extensions it does not have is left
# unprinted. The state itself STAYS: dropping the heading would be the same
# omission the four states exist to prevent.
EMPTY_STATE_LINE = "  (no extension is in this state)"

# WHAT THE MACHINE-READABLE LISTING IS, said in a value rather than left to be
# inferred from the presence of a key named `unboxr`. A consumer matches on
# this; the version beside it says which vocabulary it is reading, not which
# document.
FORMAT_SUPPORT_DOCUMENT_KIND = "unboxr.format-support"

# What the listing is NOT, printed under it every time rather than left to be
# inferred. Both sentences answer a question this listing invites and cannot
# answer: it is about the NAME a file declares, and it was measured here, now.
FORMAT_LISTING_CAVEAT = (
    "Every number above is counted from the tables at run time, on this "
    "machine -- count them here rather than trusting a figure typed into a "
    "README. And every line of it is about the NAME a file declares: an "
    "archive whose extension is absent or misleading may still be recognised "
    "by its header, and any of the names above may be carried by something "
    "else entirely.")


def _wrapped_extensions(extensions) -> str:
    """The extensions of one state, indented and wrapped for a terminal.

    ONE LINE PER STATE RUNS TO HUNDREDS OF CHARACTERS for the two largest,
    which a terminal then wraps at a width nobody chose, mid-extension. The
    width is
    fixed at 78 rather than read from the terminal, and that is the point: the
    listing has to be comparable with itself between two runs, and a width
    that followed the window would make two runs on one machine differ for a
    reason that has nothing to do with what that machine can open.
    """
    return textwrap.fill(" ".join(extensions), width=78,
                         initial_indent="  ", subsequent_indent="  ",
                         break_on_hyphens=False, break_long_words=False)


def codec_safe(text: str, encoding: str | None) -> str:
    """The same text, with whatever `encoding` cannot carry made VISIBLE.

    THE ONE COMMAND WHOSE JOB IS TO REPORT THE BINARY WAS THE ONE THAT COULD
    NOT PRINT IT. `find_7zip_binary` returns a path taken off this machine --
    the PATH sweep, or a default install location under a user profile -- and a
    path is not required to be encodable in whatever codec `stdout` happens to
    carry. Reproduced on Windows on 15 September 2026: `stdout` redirected to a
    file under `cp1252`, a 7-Zip path holding CJK characters, and
    `--list-formats` died with a raw `UnicodeEncodeError` traceback, return
    code 1, ZERO bytes printed. A listing that cannot say where the binary is,
    on precisely the machine whose binary is unusual, is the listing failing at
    its own subject.

    ESCAPED, NEVER DROPPED and never replaced by a question mark. `backslash
    replace` keeps every character recoverable in the output -- a reader can
    still tell two different paths apart, and paste the escape into a search --
    where `?` would silently turn several different paths into one. The
    degradation is VISIBLE, which is the whole difference between reporting a
    limit and hiding one.

    A MISSING `encoding` IS NOT A FAULT. `io.StringIO`, which is what every
    test in this suite redirects `stdout` to, has no encoding at all and
    carries any string; so does a stream a caller substituted. `None` means "no
    codec to be refused by", and the text goes through unchanged.
    """
    if encoding is None:
        return text
    try:
        text.encode(encoding, errors="strict")
    except (UnicodeEncodeError, LookupError):
        # `LookupError`: a stream declaring a codec Python does not know. Its
        # answer is the same as an unencodable character -- ASCII escapes -- so
        # it is handled here rather than crashing one line further down.
        return text.encode("ascii", errors="backslashreplace").decode("ascii")
    return text


def print_listing(text: str, stream=None) -> None:
    """The listing, out, whatever the stream's codec will accept.

    `print`, NOT `logging`, for the reason `main` gives at the call site. What
    is added here is the codec: `print` would raise on the first character the
    stream cannot carry, having already written the lines before it.
    """
    stream = sys.stdout if stream is None else stream
    print(codec_safe(text, getattr(stream, "encoding", None)), file=stream)


def render_format_support(projection) -> str:
    """The listing a human reads, built from the projection and nothing else.

    A PURE FUNCTION OF ITS ARGUMENT. It measures nothing itself -- the one
    measurement, the 7-Zip binary, was taken by `project_format_support` and
    travels inside the projection -- so this text and the JSON below say the
    same thing about the same instant, and a test can hand this function a
    projection taken on a machine it is not running on.
    """
    def counted(names):
        return ", ".join(
            f"{projection['states'][name]['count']} "
            f"{FORMAT_STATE_SUMMARY_LABELS[name]}"
            for name in names)

    lines = [f"unboxr {__version__} -- what this machine does with the "
             f"{projection['listed_extensions']} extensions it knows by "
             f"name.",
             ""]
    if projection["seven_zip_binary"] is not None:
        lines.append(f"7-Zip binary found: {projection['seven_zip_binary']}")
    else:
        lines.append("No 7-Zip binary found on this machine.")

    for name in FORMAT_SUPPORT_STATES:
        state = projection["states"][name]
        lines.append("")
        lines.append(f"{FORMAT_STATE_HEADINGS[name]} -- {state['count']} "
                     f"extension(s)")
        if not state["extensions"]:
            # SAID, not left to be inferred from a blank line. See
            # `EMPTY_STATE_LINE`: the note is skipped with the list, because
            # four lines explaining what this state does with its extensions,
            # above no extensions at all, reads as a rendering that dropped
            # them.
            lines.append(EMPTY_STATE_LINE)
            continue
        if name == STATE_DELEGATED_TO_SEVEN_ZIP:
            note = (SEVEN_ZIP_AVAILABLE_NOTE if state["openable_here"]
                    else SEVEN_ZIP_MISSING_NOTE)
        else:
            note = FORMAT_STATE_NOTES[name]
        lines.append(textwrap.fill(note, width=78, initial_indent="  ",
                                   subsequent_indent="  "))
        lines.append(_wrapped_extensions(state["extensions"]))

    # THE SPLIT IS THE TABLES' OWN, and the wording follows it rather than
    # flattening the four states into one addition. `recognised_extensions`
    # counts the extensions unboxr has a category for -- the number every
    # report already prints in "N of the M recognised extensions need
    # 7-Zip" -- and the office containers are counted apart because they
    # are in a table of their own. One flat total, called "recognised",
    # would contradict in this very output the figure `summarise` prints at
    # the end of every extraction, and a reader comparing the two would be
    # right to trust neither.
    #
    # AND THE BREAKDOWN IS DERIVED, NOT TYPED OUT. It was a hand-written
    # 3-tuple until code review on 15 September 2026, three lines under a
    # comment claiming every table here is iterated through
    # `FORMAT_SUPPORT_STATES` precisely so that a state can go missing from
    # none of them. Measured: a FIFTH state made this sentence print
    # "33 + 31 + 4" under a stated total of 69 -- an addition that does not
    # add up, in the one sentence of the listing a reader checks. The states
    # counted here are every state EXCEPT the one fed by the other table,
    # which is the distinction the sentence is built on and the only reason
    # the fourth is not in the sum.
    recognised_states = tuple(name for name in FORMAT_SUPPORT_STATES
                              if name != STATE_RECOGNISED_AND_NOT_OPENED)
    lines.append("")
    lines.append(textwrap.fill(
        f"{projection['recognised_extensions']} recognised extensions: "
        + counted(recognised_states)
        + f". {projection['not_extracted_extensions']} more are recognised "
          f"as containers and deliberately not opened. "
          f"{projection['listed_extensions']} listed here, "
          f"{projection['extensions_openable_here']} of them openable on this "
          f"machine.",
        width=78))
    lines.append("")
    lines.append(textwrap.fill(FORMAT_LISTING_CAVEAT, width=78))
    return "\n".join(lines)


def render_format_support_as_json(projection) -> str:
    """The same projection, for something other than a human.

    THE VERSION IS ADDED HERE AND NOT IN THE PROJECTION, and the reason is an
    import cycle: `unboxr/__init__.py` imports `unboxr.extraction`, so the
    module holding the tables cannot read the version back out of the package.
    The text rendering above puts it in its first line for the same purpose,
    so the two renderings carry the same fact rather than one of them being
    quietly poorer than the other.

    AND THE KIND IS ADDED HERE TOO. A version alone is not an identity: a
    consumer handed this document had nothing to match on but the PRESENCE of
    a key named `unboxr`, which every future machine-readable thing this
    command might print would carry just as well. `kind` says which document
    this is, in one value, so a reader can refuse one it does not understand
    instead of guessing from the shape.

    `sort_keys` is deliberately NOT set: the keys come out in the order the
    projection declares them -- which is the order the four states are meant
    to be read in, not the alphabet. That order is fixed by a tuple in
    `unboxr.extraction`, so the output is deterministic either way.

    WHY THIS RENDERING NEEDS NO CODEC GUARD, and it is a dependency rather than
    a property of the data: `json.dumps` defaults to `ensure_ascii=True`, so
    the 7-Zip path it carries -- the one value here taken off the machine, and
    the one that broke the TEXT rendering on a `cp1252` stdout -- comes out as
    `\\uXXXX` escapes whatever it holds. The day someone passes
    `ensure_ascii=False` for prettier output, this rendering acquires exactly
    the failure `codec_safe` exists to absorb. It goes out through
    `print_listing` all the same, which costs nothing and stops that day from
    being a crash.
    """
    return json.dumps({"unboxr": __version__,
                       "kind": FORMAT_SUPPORT_DOCUMENT_KIND,
                       **projection}, indent=2)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="unboxr",
        description="Open an archive, and the archives nested inside it, into a "
                    "destination directory.",
        epilog="unboxr renders no verdict on what it extracts. Containers it "
               "cannot or will not open are announced: what could not be opened "
               "cannot be reported on.",
    )
    # OPTIONAL, AND DECIDED IN `main` RATHER THAN BY argparse -- on the
    # exact pattern `destination` already follows. An
    # argparse action that prints and exits (the `--version` mechanism)
    # would also short-circuit a required positional, but it runs DURING
    # parsing, at the position the option occupies in `argv`: `--json
    # --list-formats` and `--list-formats --json` would then behave
    # differently. An optional positional keeps every refusal in one place,
    # in a written order.
    #
    # QUALIFIED, because as written this argues against something the parser
    # below already does TWICE. `--version` and `--help` ARE print-and-exit
    # actions, they DO run at the position they occupy in `argv`, and
    # `--list-formats --version` therefore prints the version and exits --
    # measured on 15 September 2026, and it is argparse's behaviour rather
    # than anything this file chose. The argument is not that no such action
    # may exist here; it is that `--list-formats` must not become the THIRD,
    # because it is the only one of the three whose result depends on other
    # options (`--json`) and whose refusals have to be ordered against the
    # refusals of an extraction. `--version` and `--help` answer questions
    # that nothing in `argv` can change the answer to, which is exactly why
    # position does not matter for them and does for this one.
    parser.add_argument(
        "archive",
        nargs="?",
        default=None,
        help="Path to a local archive, or a public http(s) URL. A URL is the "
             "only input that makes unboxr touch the network. Required, "
             "except with --list-formats, which opens nothing.",
    )
    parser.add_argument(
        "destination",
        type=Path,
        nargs="?",
        default=None,
        help="Directory to unpack under. Required, except with --replace. "
             "By default the extracted tree is created at "
             "DESTINATION/<archive name>, verbatim -- not DESTINATION "
             "itself: it may hold other things. See below for the other "
             "two modes.",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--replace", action="store_true",
        help="Extract the archive in place and replace it with its own "
             "content: no DESTINATION is accepted with this option. The "
             "archive is removed only after a successful extraction. "
             "Refused on a URL, and when the source is already a directory.",
    )
    mode.add_argument(
        "--no-archive-dir", action="store_true",
        help="Do not create the directory named after the archive; unpack "
             "straight into DESTINATION. DESTINATION must then be empty or "
             "absent, and no --sbom path under it is acceptable any more: "
             "the extracted tree IS DESTINATION. Refused when the source is "
             "already a directory.",
    )
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument(
        "-v", "--verbose", action="store_true",
        help="Show debug-level records as well.",
    )
    verbosity.add_argument(
        "-q", "--quiet", action="store_true",
        help="Show warnings only -- plus every announced amputation of the "
             "corpus, which quiet mode never hides.",
    )
    parser.add_argument(
        "--sbom",
        type=Path,
        metavar="FILE",
        help="Also write the extraction document to FILE: every extracted "
             "file with its SHA-256 digest, and every container that was not "
             "opened with its cause. Nothing is written without this option.",
    )
    parser.add_argument(
        "--linked-bom",
        metavar="URN",
        help="Record, in the extraction document, which other BOM this one "
             "belongs to. Takes a BOM-Link URN of the shape "
             "urn:cdx:<uuid>/<version>. Requires --sbom, and is refused "
             "without it.",
    )
    parser.add_argument(
        "--list-formats", action="store_true",
        help="Print what THIS machine does with every extension unboxr "
             "recognises -- opened by the standard library, delegated to a "
             "7-Zip binary, recognised and refused, or recognised and "
             "deliberately not opened -- then exit. Nothing is extracted, "
             "and no ARCHIVE is taken.",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Print that listing as JSON instead of text. Requires "
             "--list-formats, and is refused without it.",
    )
    parser.add_argument(
        "--version", action="version", version=f"unboxr {__version__}",
    )
    return parser


def check_linked_bom(parser, linked_bom, document_path) -> None:
    """Refuse a link that has no object, or no recognisable shape, NOW.

    DECIDED FROM THE ARGUMENTS ALONE, WHICH IS WHY IT COMES FIRST OF THE
    REFUSALS THAT CONCERN AN EXTRACTION. Nothing here touches the file
    system: the two faults are readable in `argv` and nothing about the
    state of the machine can change the answer. A refusal that cannot be
    pre-empted by an unrelated file-system state is a refusal that always
    names the reason that actually applies.

    WHAT NOW RUNS BEFORE IT, and the qualification above is there because of
    it: the two refusals that belong to `--list-formats`, plus the missing
    ARCHIVE. Those are argv-only too -- the claim "the only one decidable
    without touching the file system" stopped being true and is not left
    standing. They come before because a run that extracts nothing at all
    must not be refused for the shape of an option that describes a
    document it was never going to write.

    THE DEPENDENCY IS CHECKED BEFORE THE VALUE. An option with no object at
    all is not examined for the shape of its argument: a caller who forgot
    `--sbom` would otherwise be sent to fix a URN that was never the problem.

    AND NEITHER FAULT IS IGNORED IN SILENCE. An ignored option makes a caller
    believe work happened that did not -- here, that an attachment was
    recorded when no document was written at all.
    """
    if linked_bom is None:
        return
    if document_path is None:
        parser.error(
            "--linked-bom names the BOM the extraction document belongs to, "
            "and no document is being written: add --sbom FILE, or drop "
            "--linked-bom")
    if not sbom.is_bom_link_to_a_document(linked_bom):
        # Same wording as `InvalidBomLinkError`, read from the one place it is
        # spelled out (`sbom.INVALID_BOM_LINK_REASON`) rather than retyped
        # here: two independently worded copies of this explanation had
        # already drifted apart.
        parser.error("--linked-bom is "
                     + sbom.INVALID_BOM_LINK_REASON % (linked_bom,))


def _resolved(path: Path):
    """The absolute path, or `None` when the file system cannot resolve it.

    `Path.resolve()` does NOT require the target to exist, which matters here:
    the tree does not exist yet at the moment the check below runs. A failure
    is DECLARED by returning `None` and refused by the caller, never swallowed
    -- a containment check quietly switched off is worse than none at all.
    """
    try:
        return Path(path).resolve()
    except OSError:
        return None


def _inventoried_tree(archive: str, destination: Path | None, *,
                      replace: bool, no_archive_dir: bool):
    """The directory the document will claim to have inventoried in full, or
    `None` when even that cannot be decided.

    TWO BRANCHES. A source that is already a directory is walked WHERE IT IS --
    nothing is extracted -- so the tree is the user's own directory. Anything
    else is unpacked, and the tree is wherever `resolve_extraction_root`
    says `prepare_source` will create it, in ANY of the three modes -- the
    SAME function `prepare_source` itself calls: two
    independent computations of that path is exactly how `EXTRACTED_TREE_NAME`
    and this function's own former `destination / EXTRACTED_TREE_NAME` used
    to stay in step only because the value never varied. A URL is never a
    local directory, and is not probed as one.

    A FAILED PROBE IS DECLARED, never silently read as "not a directory" --
    the same discipline `_resolved` above applies to its own failure. Treating
    an unreadable `archive` as if it were an archive-style source would let
    the containment check below run against the WRONG tree, switching the
    refusal off without saying so. Reviewed in code review.
    """
    if not is_url(archive):
        candidate = Path(archive)
        try:
            is_directory = candidate.is_dir()
        except OSError:
            return None
        if is_directory:
            return candidate
    return resolve_extraction_root(archive, destination, replace=replace,
                                   no_archive_dir=no_archive_dir)


def check_extraction_target(parser, archive: str, destination: Path | None, *,
                            replace: bool, no_archive_dir: bool) -> None:
    """Refuse an already-occupied extraction target NOW, before anything runs


    ONLY THE DEFAULT MODE IS CHECKED HERE. `--no-archive-dir` keeps its own,
    older rule -- DESTINATION must be empty or absent -- checked in `main`
    where it always has been. `--replace` has nothing to check here
    at all: the archive occupying its own future path is not a collision to
    refuse, it is the whole point of the option, and
    `resolve_extraction_root` makes that path the archive's own by
    definition.

    THE REFUSAL IS ON EXISTENCE, NOT ON BEING NON-EMPTY -- the
    opposite rule from `--no-archive-dir`, and deliberately so: at the level
    of the archive's own name, `unboxr` claims a name that belongs to nobody
    yet, not a directory it is willing to add to. DESTINATION itself may
    hold other things.

    ONE SPECIAL CASE NAMES ITS OWN CAUSE: when what already
    holds that name IS the archive itself -- a local archive whose
    DESTINATION happens to be its own parent directory -- `--replace` is
    named as the way out, because it is the only one: nothing else changes
    what path the archive would occupy.
    """
    if replace or no_archive_dir or destination is None:
        return
    # `replace` and `no_archive_dir` are threaded through rather than
    # hard-coded `False`: the guard above already guarantees both are `False`
    # here, but stating that as a literal duplicates the guard's own
    # precondition -- exactly the kind of independent computation this
    # rule against computing that path twice warns drifts silently the day
    # the guard above changes.
    # Code review, 15 September 2026.
    target = resolve_extraction_root(archive, destination, replace=replace,
                                     no_archive_dir=no_archive_dir)
    resolved_target = _resolved(target)
    if resolved_target is None or not resolved_target.exists():
        return
    if not is_url(archive):
        resolved_archive = _resolved(Path(archive))
        if resolved_archive is not None and resolved_target == resolved_archive:
            parser.error(
                f"{target} is the archive itself: pass --replace to extract "
                f"it in place, or choose a DESTINATION that does not already "
                f"hold a path of that name")
            return
    parser.error(f"{target} already exists: unboxr will not write into a "
                f"path that is already taken")


def check_document_path(parser, archive: str, destination: Path | None,
                        document_path, *, replace: bool = False,
                        no_archive_dir: bool = False) -> None:
    """Refuse an unusable output path NOW, before anything is extracted.

    A long extraction thrown away at the final write would look like work that
    never happened. What is decidable here is decided here; what is not is
    handled where it happens, and named.

    NO WRITE PROBE. Creating and deleting a test file has a side effect in the
    user's own tree and establishes nothing about the instant the real write
    will happen. Stated rather than left implicit.

    AND THE ONE REFUSAL THAT IS NOT ABOUT CONVENIENCE. A document written INSIDE
    the tree it inventories makes its own central claim -- that it lists every
    file present when the extraction finished -- false at the very moment it is
    written, and a file whose content carries its own digest does not exist.
    The refused perimeter is the TREE, never the whole destination:
    `<destination>/sbom.json`, beside the tree, stays allowed in the default
    mode -- under `--no-archive-dir` the tree IS the whole destination, so
    nothing under it is left to stay allowed. Comparison is on
    RESOLVED paths, never on strings: two spellings of one path, or a link
    pointing into the tree, name the same target.

    TWO MORE TARGETS NAME SOMETHING THAT WOULD STOP EXISTING THE INSTANT THE
    DOCUMENT IS WRITTEN, for the same underlying reason as the tree itself,
    and are refused here for it (code review): the SOURCE ARCHIVE --
    a file whose content carries its own SHA-256 digest cannot also be the
    file holding a document that asserts that digest -- and the DESTINATION
    DIRECTORY itself, which the extraction is about to create and which would
    make `--sbom` write a file where a directory belongs.
    """
    if document_path is None:
        return
    document_path = Path(document_path)

    # CONTAINMENT IS CHECKED FIRST, and the order is not cosmetic. A path
    # inside the tree usually has a parent that does not exist YET -- the tree
    # has not been created -- so a usability check running first would refuse
    # it for "parent directory does not exist". Same code, same refusal, and a
    # cause that is not the real one: the caller would go and create the
    # directory, and be refused again. A refusal states the reason that
    # actually applies.
    tree = _inventoried_tree(archive, destination, replace=replace,
                             no_archive_dir=no_archive_dir)
    resolved_document = _resolved(document_path)
    resolved_tree = _resolved(tree) if tree is not None else None
    if resolved_document is None or resolved_tree is None:
        parser.error(
            f"--sbom cannot be checked against the extracted tree: one of "
            f"{document_path} and {tree} could not be resolved")
    if resolved_document == resolved_tree or resolved_tree in resolved_document.parents:
        parser.error(
            f"--sbom would be written inside the tree it inventories "
            f"({tree}): the document would list every file present when the "
            f"extraction finished, itself included, which it cannot do")

    if not is_url(archive):
        resolved_archive = _resolved(Path(archive))
        if resolved_archive is not None and resolved_document == resolved_archive:
            parser.error(
                f"--sbom would overwrite the source archive ({archive}): a "
                f"file whose content carries its own SHA-256 digest does not "
                f"exist")

    # DESTINATION HAS NO VALUE UNDER `--replace` (the option forbids it), so
    # this refusal has no object there: the tree-containment check above already
    # covers the equivalent case, since `tree` IS the archive's own path.
    if destination is not None:
        resolved_destination = _resolved(destination)
        if resolved_destination is not None and resolved_document == resolved_destination:
            parser.error(
                f"--sbom is the destination directory ({destination}), not a "
                f"file inside it: for example {destination / 'sbom.json'}")

    if document_path.is_dir():
        parser.error(f"--sbom is a directory, not a file: {document_path}")
    parent = document_path.parent
    if not parent.exists():
        parser.error(f"--sbom parent directory does not exist: {parent}")
    if not parent.is_dir():
        parser.error(f"--sbom parent is not a directory: {parent}")


# --- The progress line --------------------------------------------------------
#
# ONE LINE, REWRITTEN IN PLACE at the bottom of stderr while `prepare_source`
# runs, and gone before the first word of the summary. It is fed by the
# `progress` callable the library offers -- never by reading logging records,
# the pattern this module's docstring explains it has retired.
#
# SHOWN ONLY TO A PERSON. stderr must be a terminal, `--quiet` must be off, and
# `TERM` must not be "dumb". Anywhere else -- a pipe, a file, a CI log -- not one
# byte of it is written, and stderr is what it was before the line existed.
#
# NO ESCAPE SEQUENCE OF ANY KIND. The line is rewritten with a carriage return
# and padded with spaces, and it is cut one column short of the terminal width
# so that the terminal never wraps it: a wrapped line can no longer be reached
# by `\r` alone. That is what lets it work in a legacy Windows console without
# switching on virtual-terminal processing.
#
# NO PERCENTAGE. The total of a run is discovered level by level, so the bar
# only ever counts the archives found at the CURRENT level; a phase that is one
# opaque step (a download, a digest, a search, one extraction) gets a spinner.

# The source stays pure ASCII: every glyph is written as an escape.
_UNICODE_GLYPHS = {
    "spinner": "\u280b\u2819\u2839\u2838\u283c\u2834\u2826\u2827\u2807\u280f",
    "full": "\u2588",
    "empty": "\u2591",
    "ellipsis": "\u2026",
}
_ASCII_GLYPHS = {
    "spinner": "|/-\\",
    "full": "#",
    "empty": "-",
    "ellipsis": "...",
}
_BAR_CELLS = 12
_TICK_SECONDS = 0.1
_SEVEN_ZIP_MARKER = " (7-Zip)"


def _status_line_wanted(stream, quiet: bool, environ) -> bool:
    """Whether the progress line is drawn at all. No option turns it on."""
    if quiet or environ.get("TERM") == "dumb":
        return False
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError, OSError):
        # No `isatty`, or a closed stream: not a terminal anyone is watching.
        return False


def _glyphs_for(stream, environ, os_name: str) -> dict:
    """Unicode glyphs where they will be drawn, ASCII everywhere else.

    THE ENCODING ALONE IS NOT ENOUGH. On Windows, Python hands the console a
    UTF-8 stream whatever the console can draw, and the legacy console host
    draws a braille spinner as boxes. Windows Terminal announces itself with
    `WT_SESSION`; without it, ASCII. The Linux virtual console (`TERM=linux`)
    is in the same case: its font has neither braille nor block glyphs.
    """
    if os_name == "nt" and "WT_SESSION" not in environ:
        return _ASCII_GLYPHS
    if environ.get("TERM") == "linux":
        return _ASCII_GLYPHS
    encoding = getattr(stream, "encoding", None)
    if not encoding:
        return _ASCII_GLYPHS
    try:
        "".join(_UNICODE_GLYPHS.values()).encode(encoding, errors="strict")
    except (UnicodeEncodeError, LookupError):
        return _ASCII_GLYPHS
    return _UNICODE_GLYPHS


def _terminal_width(stream) -> int:
    """The width of the terminal `stream` writes to.

    The stream's own descriptor first: `shutil.get_terminal_size` asks STDOUT,
    which is redirected precisely when stdout carries the tree path to another
    program while stderr stays on the terminal.
    """
    try:
        columns = os.get_terminal_size(stream.fileno()).columns
    except (AttributeError, ValueError, OSError):
        columns = shutil.get_terminal_size().columns
    return columns if columns > 0 else 80


def _char_columns(char: str) -> int:
    if unicodedata.combining(char):
        return 0
    # AMBIGUOUS WIDTH ("A") COUNTS AS TWO, deliberately: a terminal set up for
    # East Asian text draws those characters on two columns, and nothing here
    # can ask which kind it is. A line one column too short costs nothing; a
    # line one column too long wraps, and cannot be rewritten any more.
    return 2 if unicodedata.east_asian_width(char) in ("W", "F", "A") else 1


def _columns(text: str) -> int:
    """Terminal columns, not characters: a CJK name takes two per character,
    and counting one would let the line wrap."""
    return sum(_char_columns(char) for char in text)


def _cut_left(text: str, budget: int, ellipsis: str) -> str:
    """Keep the END of `text` within `budget` columns: of a path, the end is
    the part that says which archive it is."""
    if _columns(text) <= budget:
        return text
    room = budget - _columns(ellipsis)
    if room <= 0:
        return ""
    kept, used = [], 0
    for char in reversed(text):
        width = _char_columns(char)
        if used + width > room:
            break
        kept.append(char)
        used += width
    return ellipsis + "".join(reversed(kept))


def _cut_right(text: str, budget: int) -> str:
    kept, used = [], 0
    for char in text:
        width = _char_columns(char)
        if used + width > budget:
            break
        kept.append(char)
        used += width
    return "".join(kept)


def _printable(text: str) -> str:
    """A name from an archive may hold a newline or a tab; either would break
    the one line this has to stay on. Escaped, visibly, never dropped."""
    return "".join(char if char.isprintable()
                   else char.encode("unicode_escape").decode("ascii")
                   for char in text)


def _elapsed_text(seconds: float) -> str:
    total = max(0, int(seconds))
    hours, rest = divmod(total, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def _render_status(event, elapsed: float, frame: int, width: int,
                   glyphs: dict, encoding: str | None = None) -> str:
    """The text of the line, at most `width - 1` columns, padding excluded."""
    spinner = glyphs["spinner"][frame % len(glyphs["spinner"])]
    path = _printable(codec_safe(event.path, encoding))
    marker = _SEVEN_ZIP_MARKER if event.seven_zip else ""
    if event.phase == "nested":
        total = max(event.total, 1)
        # Archives DONE, not the one in hand: the bar fills as each one ends.
        done = max(0, min(event.index - 1, total))
        # Half a bar on a narrow terminal, which leaves the path some room.
        cells = _BAR_CELLS if width >= 60 else _BAR_CELLS // 2
        filled = done * cells // total
        bar = glyphs["full"] * filled + glyphs["empty"] * (cells - filled)
        head = (f"{spinner} level {event.level} [{bar}] "
                f"{event.index}/{event.total}  ")
    elif event.phase == "input":
        head = f"{spinner} extracting "
    elif event.phase == "download":
        head = f"{spinner} downloading "
    elif event.phase == "digest":
        head, path = f"{spinner} hashing input", ""
    elif event.phase == "scan":
        head = f"{spinner} level {event.level}: looking for nested archives"
        path = ""
    else:
        # A phase this rendering does not know yet is NAMED, not hidden.
        head = f"{spinner} {_printable(event.phase)} "
    limit = width - 1
    # THE CLOCK IS KEPT LONGEST: it is what says the run is still alive. The
    # path gives way first, from its left; then the words, from their right;
    # then the 7-Zip marker. The clock itself is shown whole or not at all --
    # "00:0" would read as a time.
    clock = _elapsed_text(elapsed)
    tail = f"{marker}  {clock}"
    if _columns(tail) > limit:
        tail = f"  {clock}"
    if _columns(tail) > limit:
        tail = clock if _columns(clock) <= limit else ""
    room = limit - _columns(tail)
    ellipsis = glyphs["ellipsis"]
    if path:
        path = _cut_left(path, room - _columns(head), ellipsis)
    body = head + path
    if _columns(body) > room:
        body = (_cut_right(body, room - _columns(ellipsis)) + ellipsis
                if room > _columns(ellipsis) else "")
    # The last word, whatever the width: nothing may reach the last column.
    return _cut_right(body + tail, max(0, limit))


class _StatusLine:
    """The line itself: what it shows, and the one lock every write takes.

    The lock is SHARED with the logging handler below. A record and a redraw
    of the line both write to stderr, from two threads; without the lock, a
    record could land in the middle of the line.

    A FAILING STREAM SWITCHES THE LINE OFF, and nothing else. A display that
    could not be written is no reason to stop an extraction: the line goes
    quiet, and the run, its records and its summary carry on.
    """

    # How long `stop` waits for the ticker, then for the lock, in seconds.
    stop_timeout = 1.0

    def __init__(self, stream, *, glyphs: dict, width=None,
                 clock=time.monotonic) -> None:
        self._stream = stream
        self._glyphs = glyphs
        self._width = width if width is not None else (
            lambda: _terminal_width(stream))
        self._clock = clock
        self._encoding = getattr(stream, "encoding", None)
        self._started_at = clock()
        self._event = None
        self._frame = 0
        self._drawn = False
        self.broken = False
        self.lock = threading.RLock()
        self._stopping = threading.Event()
        self._ticker = None

    def start_ticker(self, interval: float = _TICK_SECONDS) -> None:
        """Turn the spinner and the clock while a phase gives no news."""
        self._ticker = threading.Thread(target=self._tick_until_stopped,
                                        args=(interval,),
                                        name="unboxr-progress", daemon=True)
        self._ticker.start()

    def _tick_until_stopped(self, interval: float) -> None:
        while not self._stopping.wait(interval):
            self.tick()

    def update(self, event) -> None:
        """The `progress` callable handed to `prepare_source`."""
        with self.lock:
            self._event = event
            self._draw()

    def tick(self) -> None:
        with self.lock:
            self._frame += 1
            self._draw()

    def clear(self) -> None:
        """Leave the cursor at the start of an empty line.

        On a line that has gone broken, whatever it last put on the screen
        cannot be erased any more; it is closed with a newline instead, so the
        next record does not land glued to it.
        """
        with self.lock:
            if not self._drawn:
                return
            if not self.broken:
                try:
                    blank = " " * max(0, self._width() - 1)
                except Exception:
                    self.broken = True
                else:
                    if self._write("\r" + blank + "\r"):
                        self._drawn = False
                        return
            self._abandon()

    def redraw(self) -> None:
        with self.lock:
            self._draw()

    def stop(self) -> None:
        """Stop the clock and leave the line blank, the cursor at its start.

        BOUNDED, BOTH WAYS. A ticker stuck in a write on a stalled terminal
        (Ctrl-S) is a daemon and holds the lock: waiting for either would hold
        the end of the run hostage, so after `stop_timeout` the line is given
        up and left as it is.
        """
        self._stopping.set()
        if self._ticker is not None:
            self._ticker.join(timeout=self.stop_timeout)
        if not self.lock.acquire(timeout=self.stop_timeout):
            self.broken = True
            return
        try:
            self.clear()
            self._event = None
        finally:
            self.lock.release()

    def _draw(self) -> None:
        if self.broken or self._event is None:
            return
        try:
            width = self._width()
            text = _render_status(self._event,
                                  self._clock() - self._started_at,
                                  self._frame, width, self._glyphs,
                                  self._encoding)
            # Padded to the full width: a shorter line must blank the longer
            # one it replaces, and `\r` alone moves the cursor without erasing.
            padding = " " * max(0, width - 1 - _columns(text))
        except Exception:
            # A fault in the DISPLAY is never a fault of the extraction. This
            # runs inside `prepare_source`, through the `progress` callable,
            # and an exception here would end the run for a progress line.
            self.broken = True
            return
        # Counted as drawn BEFORE the write: part of it may reach the screen
        # even when the write, or the flush after it, raises.
        self._drawn = True
        self._write("\r" + text + padding)

    def _abandon(self) -> None:
        """Close whatever a broken line left on the screen, best effort."""
        self._drawn = False
        try:
            self._stream.write("\n")
            self._stream.flush()
        except Exception:
            pass

    def _write(self, text: str) -> bool:
        try:
            self._stream.write(text)
            self._stream.flush()
        except (OSError, ValueError):
            # `ValueError` covers a closed stream and an encoding refusal
            # (`UnicodeEncodeError` is one).
            self.broken = True
            return False
        return True


class _ProgressAwareHandler(logging.StreamHandler):
    """A `StreamHandler` that steps around the progress line.

    With no line attached it IS a `StreamHandler`, byte for byte. With one, a
    record clears the line, is written on a line of its own, and the line is
    drawn again under it -- all under the line's lock.
    """

    status_line: _StatusLine | None = None

    def emit(self, record: logging.LogRecord) -> None:
        line = self.status_line
        if line is None:
            super().emit(record)
            return
        # A BROKEN line still goes through `clear`: it is what closes a
        # leftover with a newline, once, before this record is written.
        with line.lock:
            line.clear()
            super().emit(record)
            line.redraw()


@contextlib.contextmanager
def _progress_line(handler: _ProgressAwareHandler, quiet: bool, *,
                   environ=None, os_name: str | None = None, width=None,
                   clock=time.monotonic, ticker: bool = True):
    """Yield the `progress` callable for one run, or `None` when no line is due.

    The line is stopped and cleared on the way out, WHATEVER the way out --
    an exception and a Ctrl-C included -- so that the first record after it
    starts on a blank line.

    Everything after `quiet` exists for the tests: the environment, the
    platform, the width and the clock are what decide the line, and none of
    them is a command-line option.
    """
    environ = os.environ if environ is None else environ
    os_name = os.name if os_name is None else os_name
    stream = handler.stream
    if not _status_line_wanted(stream, quiet, environ):
        yield None
        return
    line = _StatusLine(stream, glyphs=_glyphs_for(stream, environ, os_name),
                       width=width, clock=clock)
    handler.status_line = line
    if ticker:
        line.start_ticker()
    try:
        yield line.update
    finally:
        line.stop()
        handler.status_line = None


def configure_logging(verbose: bool, quiet: bool) -> _ProgressAwareHandler:
    """Set up logging for the command line, and only for it.

    Returns the handler, which the progress line has to step around.
    """
    package_logger = logging.getLogger("unboxr")
    package_logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    handler = _ProgressAwareHandler(stream=sys.stderr)
    handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))

    if quiet:
        handler.addFilter(_QuietFilter())
    package_logger.addHandler(handler)
    return handler


def summarise(report, logger: logging.Logger) -> None:
    """Say what the report holds, in prose, at the informational level.

    NOTHING STRUCTURED REACHES `stdout`, which stays reserved for the path of
    the extracted tree -- the one output of this program that is not a logging
    record. A consumer piping `unboxr a.zip d` into something else must not
    find a summary in the middle of it. The extraction document, when one is
    asked for, goes to the FILE named by `--sbom` and never here.
    """
    logger.info("Containers opened: %s.", len(report.opened))
    if report.depth_limit is not None:
        logger.info("Flattening reached level %s of at most %s.",
                    report.depth_reached, report.depth_limit)
    profile = report.capability
    if profile.seven_zip_available:
        logger.info("7-Zip binary in use: %s (%s of the %s recognised "
                    "extensions need it).", profile.seven_zip_binary,
                    profile.extensions_needing_seven_zip,
                    profile.recognised_extensions)
    else:
        logger.info("No 7-Zip binary on this machine: %s of the %s recognised "
                    "extensions cannot be opened here.",
                    profile.extensions_needing_seven_zip,
                    profile.recognised_extensions)
    for entry in report.not_opened:
        logger.info(NOT_OPENED_LINE, entry.path, text_for(entry.code))
    for entry in report.still_in_tree:
        logger.info(STILL_IN_TREE_LINE, entry.path, text_for(entry.code))
    # `report.widened` is part of the published report surface (README, "Use
    # it as a library") but was missing here: the corpus GREW here, which is
    # not an amputation, so it stays outside `--quiet`'s guarantee -- but the
    # reference summary this function is meant to be a complete rendering of
    # must still say it. Verified in code review.
    for entry in report.widened:
        logger.info("Recognised by content -- %s: %s", entry.path,
                    text_for(entry.code))
    # `report.not_attested` is the fifth kind, and this function must list it
    # as it lists `widened`. A path whose content is
    # not attested would appear in the extraction document and nowhere at all on
    # the console, so a caller who reads the run rather than the document never
    # heard of it.
    for entry in report.not_attested:
        logger.info("Not attested -- %s: %s", entry.path,
                    text_for(entry.code))


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # THE LISTING MODE IS SETTLED BEFORE ANYTHING ELSE, in a written order,
    # and it is the whole reason `archive` is an optional positional rather
    # than an argparse action (see `build_parser`). No source is prepared,
    # no logging handler is installed, no archive is opened and no network
    # is reached: this mode reads the extension tables, looks once for a
    # 7-Zip binary, and exits.
    #
    # THAT LOOK IS NOT NOTHING, and saying "it touches no file system"
    # would be a shade too clean: `find_7zip_binary` sweeps the PATH and,
    # on Windows, stats a handful of default install locations. It reads no
    # file, writes nothing anywhere, and is the same call every extraction
    # makes -- but it is the one thing here that asks the machine a
    # question, which is precisely what this mode exists to report.
    #
    # THE NARROWER FAULT FIRST. `--json` with no listing to shape is a
    # smaller mistake than `--list-formats` handed an archive, and a caller
    # who made both should be told about the option that has no object at
    # all before being told what the listing does not do -- the same
    # ordering rule `check_linked_bom` applies to its own two faults.
    if args.json and not args.list_formats:
        parser.error(
            "--json has no object on its own: it names the shape of the "
            "--list-formats listing, and nothing else this command prints "
            "is machine-readable. Add --list-formats, or drop --json")

    if args.list_formats:
        # REFUSED, NEVER IGNORED. `unboxr a.zip dest --list-formats` would
        # print a listing and extract NOTHING, and the caller would read a
        # successful-looking run as an extraction that happened. An option
        # ignored in silence makes someone believe in work that was never
        # done -- the same motive `check_linked_bom` acts on a few lines
        # below, and one already applied twice elsewhere in this module.
        #
        # THE WHOLE SHAPE OF AN EXTRACTION IS CHECKED, not just the
        # positionals: `--sbom` names a document this mode does not write
        # and `--linked-bom` a link it does not record, so accepting them
        # here would be the same silence by another door. `--verbose` and
        # `--quiet` are deliberately NOT in this list: they govern the
        # logging stream, which this mode does not use, and neither of them
        # can make a caller believe an extraction took place.
        extraction_arguments = [name for name, given in (
            ("ARCHIVE", args.archive is not None),
            ("DESTINATION", args.destination is not None),
            ("--replace", args.replace),
            ("--no-archive-dir", args.no_archive_dir),
            ("--sbom", args.sbom is not None),
            ("--linked-bom", args.linked_bom is not None),
        ) if given]
        if extraction_arguments:
            parser.error(
                "--list-formats prints what this machine can open and "
                "exits, extracting nothing: "
                + ", ".join(extraction_arguments)
                + " would be ignored. Run --list-formats on its own, or "
                  "drop it to extract")

        # ONE PROJECTION, TWO RENDERINGS. Both read the same structure, so
        # the JSON cannot carry a total the text disagrees with, and the
        # single measurement inside it -- was a 7-Zip binary found? -- is
        # taken once.
        #
        # `print`, NOT `logging`. This package configures no logging of its
        # own, `--quiet` could hide a stream record, and a listing asked for
        # explicitly is the output of the program, not a note about it. The
        # one other machine-readable thing this command prints, the path of
        # the extracted tree, already goes out this way.
        #
        # AND THROUGH `print_listing`, WHICH IS STILL `print`. The one value
        # here that this package did not write -- the path of the 7-Zip binary
        # -- comes off the machine, and a machine is free to hold a path its
        # own stdout codec cannot carry. Printed raw, that killed the whole
        # listing with a traceback and nothing on stdout at all.
        projection = project_format_support()
        print_listing(render_format_support_as_json(projection) if args.json
                      else render_format_support(projection))
        return 0

    # ARGPARSE USED TO WRITE THIS SENTENCE ITSELF, and stopped the moment
    # `archive` became optional. It is written here, in argparse's own
    # words plus the condition that made the positional optional, and it is
    # checked HERE -- before every refusal that reads `args.archive` -- so
    # that omitting the archive is still answered with "archive", exactly
    # as it was. Same pattern, same place in the order, as `destination`.
    if args.archive is None:
        parser.error("the following arguments are required: archive "
                     "(omit it only together with --list-formats)")

    # FIRST OF THE REFUSALS THAT CONCERN AN EXTRACTION, because it is the
    # only one of those decidable without touching the file system at all.
    # See `check_linked_bom`.
    check_linked_bom(parser, args.linked_bom, args.sbom)

    # DECIDABLE FROM argv ALONE, next: the shape of the invocation itself,
    # before a single path on disk is looked at.
    # `--replace` and `--no-archive-dir` being mutually exclusive is already
    # enforced by `build_parser`'s own argument group.
    if args.replace and args.destination is not None:
        parser.error("DESTINATION is not accepted with --replace: the "
                     "archive is extracted in place, on its own path")
    if not args.replace and args.destination is None:
        parser.error("the following arguments are required: destination "
                     "(omit it only together with --replace)")

    is_source_url = is_url(args.archive)
    if args.replace and is_source_url:
        parser.error("--replace is refused on a URL: there is no local "
                     "file to replace")

    # A SOURCE THAT IS ALREADY A DIRECTORY has neither an archive to replace
    # nor a wrapper directory to omit: `prepare_source` extracts nothing on
    # this branch. Both options are refused here, with their cause,
    # rather than silently accepted and ignored.
    source_is_directory = False
    if not is_source_url:
        try:
            source_is_directory = Path(args.archive).is_dir()
        except OSError:
            source_is_directory = False
    if source_is_directory and (args.replace or args.no_archive_dir):
        used = "--replace" if args.replace else "--no-archive-dir"
        parser.error(f"{used} has no effect when the source is already a "
                     f"directory: it is inventoried where it is, and "
                     f"nothing is extracted")

    destination: Path | None = args.destination
    if destination is not None:
        if destination.exists() and not destination.is_dir():
            parser.error(f"destination is not a directory: {destination}")
        # NON-EMPTY IS REFUSED ONLY UNDER `--no-archive-dir`. The
        # default mode drops this rule: DESTINATION may hold other
        # things now that `unboxr` only claims a name inside it, not the
        # whole directory. `check_extraction_target`, below, checks THAT
        # name instead.
        if args.no_archive_dir and destination.is_dir() and any(destination.iterdir()):
            parser.error(f"destination exists and is not empty: {destination}")

    check_extraction_target(parser, args.archive, destination,
                            replace=args.replace,
                            no_archive_dir=args.no_archive_dir)

    # BEFORE ANY EXTRACTION, and before a single byte is written anywhere.
    check_document_path(parser, args.archive, destination, args.sbom,
                        replace=args.replace, no_archive_dir=args.no_archive_dir)

    handler = configure_logging(args.verbose, args.quiet)
    logger = logging.getLogger("unboxr.cli")

    # THE REPORT IS CREATED HERE, BEFORE THE RUN, AND HELD ACROSS IT. That is
    # what makes the failure path below able to declare: `prepare_source`
    # returns nothing when it raises, and the amputations that happened before
    # the failure would go with it.
    report = new_report()

    # THE LINE IS GONE BEFORE ANY OF WHAT FOLLOWS IS SAID. The `with` closes
    # before the `except` below runs, so an error, the summary and the tree
    # path all start on a blank line -- on a failure and a Ctrl-C as well.
    try:
        with _progress_line(handler, args.quiet) as progress:
            prepared = prepare_source(args.archive, workspace=destination,
                                      report=report, replace=args.replace,
                                      no_archive_dir=args.no_archive_dir,
                                      progress=progress)
    except Exception as exc:
        logger.error("%s: %s", exc.__class__.__name__, exc)
        # `summarise` too, on this path, not just the numeric reminder: this
        # is the exact moment the report exists to serve -- everything it
        # holds from before the failure (containers opened, amputations
        # already announced) would otherwise go unsaid, contradicting the
        # module docstring's own claim that the failure path can declare.
        # Verified in code review.
        summarise(report, logger)
        if report.amputation_count():
            logger.warning(ORACLE_REMINDER, report.amputation_count())
        # THE DOCUMENT IS WRITTEN HERE TOO, and this is the run where it says
        # the most: there is no tree to walk, but the report is alive and full,
        # and the corpus is as amputated as it ever gets. It carries the
        # containers, no file component at all, and an outcome that says so.
        # The return code stays 1: a failure that produced a document is still
        # a failure.
        # THE LINK IS CARRIED HERE TOO, and this is the branch that most needs
        # it: a run whose corpus is amputated to nothing is precisely the one
        # that has to be tied back to the conclusion it fed.
        _write_document(args.sbom, report, None, args.archive, None, logger,
                        linked_bom=args.linked_bom)
        return 1

    summarise(report, logger)
    if report.amputation_count():
        logger.warning(ORACLE_REMINDER, report.amputation_count())

    logger.info("Distribution nature: %s", prepared.nature)
    if prepared.digest is not None:
        logger.info("Input digest: sha256:%s", prepared.digest)
    written = _write_document(args.sbom, report, prepared.tree, args.archive,
                              prepared.digest, logger,
                              linked_bom=args.linked_bom)
    # `stdout` carries the tree whatever happened to the document: the
    # extraction is not lost because a write failed.
    print(prepared.tree)
    return 0 if written else 1


def _write_document(document_path, report, tree, source, source_digest,
                    logger: logging.Logger, linked_bom=None) -> bool:
    """Write the extraction document, or say why it could not be written.

    THE RESIDUE OF `check_document_path`, HANDLED RATHER THAN LEFT SILENT. That
    check refuses what is decidable before the extraction starts; a write can
    still fail afterwards -- a disk that filled, a permission that changed.
    When it does, the failure is NAMED with its file and its cause, and the run
    reports failure. It does not pretend a document exists.
    """
    if document_path is None:
        return True
    try:
        document = sbom.build_document(
            report, tree, source=source, source_digest=source_digest,
            linked_bom=linked_bom)
        sbom.write_document(document, document_path)
    except Exception as exc:
        logger.error("the extraction document could not be written to %s: "
                     "%s: %s", document_path, exc.__class__.__name__, exc)
        return False
    logger.info("Extraction document written: %s", document_path)
    return True


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
