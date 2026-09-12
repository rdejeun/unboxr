"""What was opened, and -- above all -- what was not.

`unboxr` is a library, and a library is silent: it emits on its own logger and
configures nothing. That silence has a cost this module pays back. Every
container the chain refuses, skips or fails to open AMPUTATES the corpus the
caller goes on to use, and an amputation announced only through the logging
system is an amputation a caller who configured no handler never hears about.

So it is not announced only there. It is RETURNED. `prepare_source` hands back
a report alongside the tree, which is what makes the "what could not be opened"
field impossible to omit: a caller cannot obtain the tree without also
receiving the report. The same report can be passed IN, which is what makes it
survive a `raise` -- the one moment where the declaration matters most and
where a return value does not exist.

POSITIVE-ONLY ORACLE, HERE TOO
------------------------------
An entry PROVES that a container was met and dealt with in the way its code
says. An ABSENT entry proves nothing whatsoever: this report says what the
chain saw, never what was there. No guarantee on the corpus when the 7-Zip
binary is absent -- the capability profile below DECLARES that divergence, it
does not close it.

ONE TABLE, AND ONE ONLY
-----------------------
Each cause carries a stable CODE -- an identifier, not a sentence -- and its
English text is DERIVED from that code by `CAUSE_TEXTS`, here and nowhere else.
A consumer on the other side of a language boundary translates the CODE and
ignores the text; a second table written elsewhere would diverge from this one
the first time a sentence was reworded, and nothing would say so. A code this
table does not know DEGRADES to a named "unknown" (see `text_for`), which is
distinct from "nothing to report" and must stay distinct.

THE IDENTITY OF AN ENTRY IS THE PAIR (code, path)
-------------------------------------------------
Never the call. `categorize_archive` is reached from four call sites, one of
them inside the sorted comprehension of `flatten_nested_archives`, which is
re-evaluated at every level: a report counting calls would announce dozens of
amputations for a single office document. That distinction is what separates
this report from a log.

This module holds DATA and the rules for filing it. It performs no extraction,
reads no file, and imports nothing but the standard library -- `unboxr.cli`
least of all: the command imports these tables, so the dependency runs that
way, and the reverse would be the cycle that stranded them in `cli.py` in the
first place.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

# --- The kinds an entry can have ---------------------------------------------
#
# FOUR, and they are not degrees of severity. They answer one question: is the
# content of this container in the tree the caller gets back?
#
#   NOT_OPENED    -- it is not. This is an amputation, and this is the field
#                    that cannot be omitted.
#   OPENED        -- it is, under the container's own name.
#   STILL_IN_TREE -- it is, but not where a caller would look for it, or mixed
#                    with something else. Declared, and NOT an amputation:
#                    counting it as one would assert a loss that did not happen.
#   WIDENED       -- the corpus GREW here: an archive was recognised by its
#                    content when its extension said nothing. Named for the
#                    same reason an amputation is -- a corpus that grows without
#                    a trace is no better than one that shrinks without a trace
#                    -- and kept out of the amputation count on purpose.
#
# A fifth value, LOG_ONLY, is not a kind of entry at all: it names a logging
# message that has no container of its own -- the closing recap, which restates
# entries already filed one by one. Recording one files nothing, which is why it
# is declared here rather than left to a caller to remember.
NOT_OPENED = "not_opened"
OPENED = "opened"
STILL_IN_TREE = "still_in_tree"
WIDENED = "widened"
LOG_ONLY = "log_only"

KINDS = (NOT_OPENED, OPENED, STILL_IN_TREE, WIDENED, LOG_ONLY)


# --- The cause codes ---------------------------------------------------------
#
# Identifiers, deliberately, and not the English prose the command used as keys
# until now ("office container refused", "several tars in a .7z envelope, only
# the first extracted"...). A reword changed those; a downstream program
# translates the CODE, so the key has to be stable under rewording, which prose
# is not. The prose is kept all the same, in ORIGINAL_AMPUTATION_NAMES below:
# it is the trail left by the code review that named those six, and renaming
# them must not lose it.

# Containers that were opened. Two codes rather than one plus a level, because
# the first-level container is the one the CALLER handed over: it is extracted
# outside the flattening loop, and a report that only knew about nested
# containers would miss it entirely.
INPUT_CONTAINER_OPENED = "input_container_opened"
NESTED_CONTAINER_OPENED = "nested_container_opened"

# Amputations. The first six were already named by the command; the last two
# are new here.
OFFICE_CONTAINER_EXCLUDED = "office_container_excluded"
SEVERAL_TARS_ONLY_FIRST_EXTRACTED = "several_tars_only_first_extracted"
EXTRACTION_FAILED = "extraction_failed"
MAXIMUM_DEPTH_REACHED = "maximum_depth_reached"
TAR_REFUSED_BY_SECURITY_FILTER = "tar_refused_by_security_filter"
TAR_CONTENT_PARTLY_MOVED = "tar_content_partly_moved"
# RECOGNISED, and refused. Distinct from EXTRACTION_FAILED on purpose: the
# first says "this tool does not open this format", the second "this archive
# could not be read". Collapsing them -- which is what happens when both travel
# as a bare RuntimeError through one generic handler -- loses the difference
# between a limit of the tool and a defect of the input.
ZSTD_NOT_SUPPORTED = "zstd_not_supported"
SEVEN_ZIP_BINARY_MISSING = "seven_zip_binary_missing"
# ONE code for BOTH 7-Zip call sites (the `.tar.7z` envelope and the delegated
# one-level formats). The cause is identical -- no binary on this machine -- and
# which format was refused is already carried by the entry's own path. Two codes
# would make a consumer translate the same cause twice.

# Declared NON-amputations: the content IS in the tree.
PROVISIONAL_DIRECTORY_ALREADY_OCCUPIED = "provisional_directory_already_occupied"
DESTINATION_ALREADY_OCCUPIED = "destination_already_occupied"
ARCHIVE_KEPT_AFTER_SUCCESSFUL_EXTRACTION = "archive_kept_after_successful_extraction"
EXTRACTION_KEPT_UNDER_PROVISIONAL_NAME = "extraction_kept_under_provisional_name"
DIRECTORY_OF_A_DIFFERENT_ORIGIN_DISCARDED = "directory_of_a_different_origin_discarded"
ARCHIVE_OUTSIDE_THE_ANALYSED_ROOT = "archive_outside_the_analysed_root"
FLATTENING_FINISHED_WITH_UNOPENED_ARCHIVES = "flattening_finished_with_unopened_archives"

# The corpus grows.
RECOGNISED_BY_CONTENT = "recognised_by_content"


# THE table. Code -> English text. Nothing else in this package may hold a
# second one; a test checks the sources of `cli.py` and `extraction.py` for the
# texts below.
CAUSE_TEXTS = {
    INPUT_CONTAINER_OPENED:
        "the container given as the source was opened",
    NESTED_CONTAINER_OPENED:
        "a container nested inside the tree was opened",

    OFFICE_CONTAINER_EXCLUDED:
        "an office container was set aside by policy and not opened",
    SEVERAL_TARS_ONLY_FIRST_EXTRACTED:
        "a 7z envelope held several tar archives and only the first was opened",
    EXTRACTION_FAILED:
        "a container was recognised but could not be read",
    MAXIMUM_DEPTH_REACHED:
        "a container was still unopened when flattening stopped at the "
        "maximum nesting depth",
    TAR_REFUSED_BY_SECURITY_FILTER:
        "a tar archive was refused whole by the security filter",
    TAR_CONTENT_PARTLY_MOVED:
        "the content of a tar archive reached its destination only in part",
    ZSTD_NOT_SUPPORTED:
        "a Zstandard container was recognised and refused: this tool does not "
        "open the format",
    SEVEN_ZIP_BINARY_MISSING:
        "a container needs an external 7-Zip binary, which is not on this "
        "machine",

    PROVISIONAL_DIRECTORY_ALREADY_OCCUPIED:
        "an earlier run over this workspace had already written under the same "
        "provisional name and the two are mixed",
    DESTINATION_ALREADY_OCCUPIED:
        "the destination already held content and this extraction merged into "
        "it",
    ARCHIVE_KEPT_AFTER_SUCCESSFUL_EXTRACTION:
        "a container was opened but could not be removed afterwards",
    EXTRACTION_KEPT_UNDER_PROVISIONAL_NAME:
        "an opened container kept its provisional directory name",
    DIRECTORY_OF_A_DIFFERENT_ORIGIN_DISCARDED:
        "a directory of a different origin was discarded to make room for this "
        "extraction",
    ARCHIVE_OUTSIDE_THE_ANALYSED_ROOT:
        "a container was met outside the analysed root and its provisional "
        "name depends on this machine",
    FLATTENING_FINISHED_WITH_UNOPENED_ARCHIVES:
        "flattening finished while containers remained unopened",

    RECOGNISED_BY_CONTENT:
        "a container was recognised by its first bytes, its extension being "
        "absent or misleading",
}

# Where each code is filed. Declared here rather than chosen at the call site:
# a code has ONE kind, and deciding it where the record is taken is how an
# amputation ends up in a list nothing counts.
CAUSE_KINDS = {
    INPUT_CONTAINER_OPENED: OPENED,
    NESTED_CONTAINER_OPENED: OPENED,

    OFFICE_CONTAINER_EXCLUDED: NOT_OPENED,
    SEVERAL_TARS_ONLY_FIRST_EXTRACTED: NOT_OPENED,
    EXTRACTION_FAILED: NOT_OPENED,
    MAXIMUM_DEPTH_REACHED: NOT_OPENED,
    TAR_REFUSED_BY_SECURITY_FILTER: NOT_OPENED,
    TAR_CONTENT_PARTLY_MOVED: NOT_OPENED,
    ZSTD_NOT_SUPPORTED: NOT_OPENED,
    SEVEN_ZIP_BINARY_MISSING: NOT_OPENED,

    PROVISIONAL_DIRECTORY_ALREADY_OCCUPIED: STILL_IN_TREE,
    DESTINATION_ALREADY_OCCUPIED: STILL_IN_TREE,
    ARCHIVE_KEPT_AFTER_SUCCESSFUL_EXTRACTION: STILL_IN_TREE,
    EXTRACTION_KEPT_UNDER_PROVISIONAL_NAME: STILL_IN_TREE,
    DIRECTORY_OF_A_DIFFERENT_ORIGIN_DISCARDED: STILL_IN_TREE,
    ARCHIVE_OUTSIDE_THE_ANALYSED_ROOT: STILL_IN_TREE,
    FLATTENING_FINISHED_WITH_UNOPENED_ARCHIVES: LOG_ONLY,

    RECOGNISED_BY_CONTENT: WIDENED,
}

# MAXIMUM_DEPTH_REACHED is recorded ONE CONTAINER AT A TIME, and that is the net
# gain this report brings over its logging message: that message says archives
# "may remain unopened", with neither list nor count. A second code naming the
# event itself was written and withdrawn -- it split one cause in two, and made
# the amputation count mix a container with an event.

# The six prose keys the command used until now, kept so the trail of the code
# review that named them is not lost. This is NOT a second table of cause
# texts: it maps a code to its FORMER KEY, which no consumer reads.
ORIGINAL_AMPUTATION_NAMES = {
    OFFICE_CONTAINER_EXCLUDED: "office container refused",
    SEVERAL_TARS_ONLY_FIRST_EXTRACTED:
        "several tars in a .7z envelope, only the first extracted",
    EXTRACTION_FAILED: "nested archive failed to extract",
    MAXIMUM_DEPTH_REACHED: "maximum nesting depth reached",
    TAR_REFUSED_BY_SECURITY_FILTER: "tar archive refused by the security filter",
    TAR_CONTENT_PARTLY_MOVED: "tar content only partly moved into its destination",
}


# --- The logging format strings ----------------------------------------------
#
# A DIFFERENT OBJECT from CAUSE_TEXTS, and the distinction is worth keeping in
# mind: the tables below hold the exact `logging` FORMAT STRINGS emitted by
# `unboxr.extraction`, which is how a record is recognised without reading its
# formatted message. They exist for two consumers and no other:
#
#   - `--quiet`, which must never drop below what declares an amputation. The
#     most frequent amputation of all -- an office container being refused -- is
#     emitted at the INFORMATIONAL level, so a quiet mode that merely raised the
#     threshold to warnings would silence it;
#   - the exhaustivity ratchet in the test suite, which walks the AST of
#     `extraction.py` and requires every warning it emits to appear in one table
#     or the other. Without that, a warning added later is counted by nothing
#     and named by nothing -- which is how the partial-move amputation went
#     uncounted on the day it was written (code review, 9 September 2026).
#
# They are NOT what a consumer translates. That is the code.
AMPUTATION_MESSAGES = {
    OFFICE_CONTAINER_EXCLUDED: (
        "%s: office container, excluded from extraction -- its "
        "content is not the material this tool opens."
    ),
    SEVERAL_TARS_ONLY_FIRST_EXTRACTED: (
        "The .7z envelope contains %s .tar files. Only the first in "
        "sorted order is extracted: %s. NOT EXTRACTED: %s. No "
        "conclusion can be drawn from the absence of a finding on "
        "those archives."
    ),
    EXTRACTION_FAILED: (
        "Extraction of %s (%s) failed: %s (archive kept as is). "
        "Its content is NOT in the extracted tree."
    ),
    MAXIMUM_DEPTH_REACHED: (
        "Maximum depth (%s) reached: flattening stops, archives may "
        "remain unopened. Their content is NOT in the extracted tree."
    ),
    TAR_REFUSED_BY_SECURITY_FILTER: (
        "Tar member refused by the security filter: %s (%s). The "
        "archive is NOT extracted: no conclusion can be drawn from "
        "the absence of a finding on its content."
    ),
    TAR_CONTENT_PARTLY_MOVED: (
        "%s: the extracted content could not be moved into %s in "
        "full. That directory now holds an INCOMPLETE extraction: no "
        "conclusion can be drawn from the absence of a finding on "
        "its content."
    ),
}

# Warnings the module emits that are NOT amputations, each under the code that
# names it. The two tables together must be EXHAUSTIVE over the warnings of
# `unboxr.extraction`; a test requires it.
NOT_AN_AMPUTATION = {
    PROVISIONAL_DIRECTORY_ALREADY_OCCUPIED: (
        "%s: its provisional extraction directory %s already holds content, "
        "left by an earlier run over this workspace; the two are mixed there, "
        "with no further warning."
    ),
    DESTINATION_ALREADY_OCCUPIED: (
        "Destination %s already holds content; extracting into it merges "
        "the two, with no further warning."
    ),
    ARCHIVE_KEPT_AFTER_SUCCESSFUL_EXTRACTION: (
        "%s was extracted successfully but could not be removed (%s): the "
        "archive is kept, and its content stays under the provisional name "
        "%s. Its content IS in the extracted tree."
    ),
    EXTRACTION_KEPT_UNDER_PROVISIONAL_NAME: (
        "%s: the extracted content could not be renamed to %s (%s): it stays "
        "under its provisional name %s. Its content IS in the extracted tree, "
        "under that name."
    ),
    FLATTENING_FINISHED_WITH_UNOPENED_ARCHIVES: (
        "Flattening finished, but %s archive(s) were left unopened: %s. "
        "Their content is NOT in the extracted tree."
    ),
    ARCHIVE_OUTSIDE_THE_ANALYSED_ROOT: (
        "Archive outside the analysed root, provisional name derived from the "
        "absolute path: %s. The produced name depends on the machine."
    ),
    DIRECTORY_OF_A_DIFFERENT_ORIGIN_DISCARDED: (
        "%s: %s already held content as a directory of a different origin; it "
        "is discarded, not merged, to make room for this extraction."
    ),
}

# Not an amputation: the corpus GROWS here, because an archive was recognised by
# its content.
CORPUS_WIDENING_MESSAGE = (
    "%s: archive recognised by its CONTENT (%s) -- extension "
    "absent or misleading."
)


def text_for(code: str) -> str:
    """The English text of a cause code.

    An UNKNOWN code degrades to a text that NAMES it as unknown, and never to
    an empty string: a consumer reading this across a language boundary must be
    able to tell "a code from a version I do not know" from "nothing to
    report". Three states, never two.
    """
    known = CAUSE_TEXTS.get(code)
    if known is not None:
        return known
    return f"unknown cause code '{code}': this report was produced by another version"


@dataclass(frozen=True)
class CapabilityProfile:
    """What this machine can open, MEASURED and never supposed.

    Declared in every report, including a report that opened nothing: an
    omission asserts. A profile that appeared only when the binary had been
    needed would read as "not applicable" rather than "binary absent", and the
    two are not the same fact.

    `recognised_extensions` and `extensions_needing_seven_zip` are COMPUTED from
    the extension table, never written as literals: the same discipline the
    README already applies, where a one-liner counts them rather than a figure
    that would drift.

    No guarantee on the corpus when the 7-Zip binary is absent. The profile
    DECLARES that divergence -- two machines, one archive, two corpora -- it
    does not close it.

    The tar security filter has no entry here, and its absence is deliberate:
    the Python floor makes the filter unconditional, so there is no capability
    left to probe and no degraded mode to declare.
    """

    seven_zip_binary: str | None
    recognised_extensions: int
    extensions_needing_seven_zip: int

    @property
    def seven_zip_available(self) -> bool:
        return self.seven_zip_binary is not None


@dataclass(frozen=True)
class ContainerRecord:
    """One container, one cause. `path` is a POSIX relative path wherever the
    chain knows the root it was found under, and the file NAME otherwise --
    never an absolute path, which would depend on the machine and reopen the
    divergence guarantee 3 of the determinism contract exists to close.

    `level` is the flattening level the container was met at: 0 for the one the
    caller handed over, 1 and up for a nested one, `None` where the chain has no
    level to give.
    """

    code: str
    path: str
    level: int | None = None
    detail: str = ""


@dataclass
class ExtractionReport:
    """What the chain met, and what it did about it.

    `capability` has NO DEFAULT on purpose: a report cannot be built without
    one, which is what makes "declared in every report" true by construction
    rather than by discipline.

    `depth_limit` is the bound that applied, `depth_reached` the level actually
    traversed. They are two different numbers and reporting only the first would
    say nothing about what happened.
    """

    capability: CapabilityProfile
    opened: list = field(default_factory=list)
    not_opened: list = field(default_factory=list)
    still_in_tree: list = field(default_factory=list)
    widened: list = field(default_factory=list)
    depth_reached: int = 0
    depth_limit: int | None = None

    _KIND_FIELDS = {
        OPENED: "opened",
        NOT_OPENED: "not_opened",
        STILL_IN_TREE: "still_in_tree",
        WIDENED: "widened",
    }

    def record(self, code: str, path, level=None, detail: str = "") -> None:
        """File one container under one cause.

        The identity of an entry is the pair (code, path): recording the same
        pair again changes nothing. That is what makes this a report and not a
        log -- `categorize_archive` is reached from four call sites, one inside
        a comprehension re-evaluated at every level.

        An UNDECLARED code raises, and only an undeclared code does. That is a
        programming error, caught on the first run; everything a real run can
        hand over -- a path that is not a string, a level that is not an int --
        is filed as given. A record that raised mid-run would abort the
        flattening and leave every remaining archive unopened with no trace at
        all: the guard would become what amputates the corpus, which is the one
        thing it must never be.
        """
        kind = CAUSE_KINDS[code]           # an undeclared code has no home
        target_name = self._KIND_FIELDS.get(kind)
        if target_name is None:            # LOG_ONLY: named, and filed nowhere
            return
        target = getattr(self, target_name)
        text_path = "" if path is None else str(path)
        for existing in target:
            if existing.code == code and existing.path == text_path:
                return
        target.append(ContainerRecord(code=code, path=text_path, level=level,
                                      detail="" if detail is None else str(detail)))

    def amputation_count(self) -> int:
        """How many containers are NOT in the tree the caller gets back.

        Containers, not log records. The command used to count the latter, by
        matching on the format string of every record passing through its
        handler; one office document seen at four call sites and at every level
        counted several times over.
        """
        return len(self.not_opened)


@dataclass(frozen=True)
class PreparedSource:
    """What `prepare_source` hands back.

    NAMED FIELDS, not a tuple. The arity went from three pieces to four, and a
    later story adds a fifth; three positional pieces already read poorly when
    unpacked, four read worse. It is also the literal reading of "a report whose
    FIELD cannot be omitted" -- a field has a name.

    The three pieces that were already there keep exactly their meaning: the
    flattened tree, the distribution nature of the resolved unit, and the BARE
    hexadecimal SHA-256 of the received input (`None` for a directory, which is
    not a single file and has nothing to hash).
    """

    tree: Path
    nature: str
    digest: str | None
    report: ExtractionReport
