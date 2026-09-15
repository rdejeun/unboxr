"""The `unboxr` command line.

A DELIBERATE FLOOR, and one that has now been added to three times. It opens
an archive into a destination directory, says where the result is, and
summarises what could not be opened. On request -- and only on request -- it
also writes the extraction document: a CycloneDX inventory of the corpus, one
file per component with its digest, plus every container that was not opened
and why. On request again, that document says which other BOM it belongs to.

WHAT IS STILL NOT THIS FLOOR. There is no self-check gate, no strict mode, and
no verdict of any kind. The command does not fetch, open or resolve the BOM it
is given the URN of, and it does not compose that URN: it is handed one, it
checks its shape, and it refuses what it cannot recognise.

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

This module is the ONLY place in the package that configures logging, and the
only place that writes a file the caller asked for. The library never does
either (see `unboxr/__init__.py`): `unboxr.sbom` RETURNS a structure, and the
writing is a separate gesture, taken here.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from . import __version__
from . import sbom
from .extraction import is_url, new_report, prepare_source, resolve_extraction_root
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
# emitter cannot drift apart. Verified in code review, story 14.3.
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="unboxr",
        description="Open an archive, and the archives nested inside it, into a "
                    "destination directory.",
        epilog="unboxr renders no verdict on what it extracts. Containers it "
               "cannot or will not open are announced: what could not be opened "
               "cannot be reported on.",
    )
    parser.add_argument(
        "archive",
        help="Path to a local archive, or a public http(s) URL. A URL is the "
             "only input that makes unboxr touch the network.",
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
        "--version", action="version", version=f"unboxr {__version__}",
    )
    return parser


def check_linked_bom(parser, linked_bom, document_path) -> None:
    """Refuse a link that has no object, or no recognisable shape, NOW.

    DECIDED FROM THE ARGUMENTS ALONE, WHICH IS WHY IT COMES FIRST. Nothing
    here touches the file system: the two faults are readable in `argv` and
    nothing about the state of the machine can change the answer. A refusal
    that cannot be pre-empted by an unrelated file-system state is a refusal
    that always names the reason that actually applies.

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
    SAME function `prepare_source` itself calls (story 14.8, AC-1.4): two
    independent computations of that path is exactly how `EXTRACTED_TREE_NAME`
    and this function's own former `destination / EXTRACTED_TREE_NAME` used
    to stay in step only because the value never varied. A URL is never a
    local directory, and is not probed as one.

    A FAILED PROBE IS DECLARED, never silently read as "not a directory" --
    the same discipline `_resolved` above applies to its own failure. Treating
    an unreadable `archive` as if it were an archive-style source would let
    the containment check below run against the WRONG tree, switching the
    refusal off without saying so. Reviewed in story 14.4.
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
    (story 14.8, AC-2).

    ONLY THE DEFAULT MODE IS CHECKED HERE. `--no-archive-dir` keeps its own,
    older rule -- DESTINATION must be empty or absent -- checked in `main`
    where it always has been (AC-4.2). `--replace` has nothing to check here
    at all: the archive occupying its own future path is not a collision to
    refuse, it is the whole point of the option (AC-3.1), and
    `resolve_extraction_root` makes that path the archive's own by
    definition.

    THE REFUSAL IS ON EXISTENCE, NOT ON BEING NON-EMPTY (AC-2.2) -- the
    opposite rule from `--no-archive-dir`, and deliberately so: at the level
    of the archive's own name, `unboxr` claims a name that belongs to nobody
    yet, not a directory it is willing to add to. DESTINATION itself may
    hold other things (AC-2.4).

    ONE SPECIAL CASE NAMES ITS OWN CAUSE (AC-5.3, AC-2.3): when what already
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
    # story's AC-1.4 warns drifts silently the day the guard above changes.
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
    nothing under it is left to stay allowed (AC-4.3). Comparison is on
    RESOLVED paths, never on strings: two spellings of one path, or a link
    pointing into the tree, name the same target.

    TWO MORE TARGETS NAME SOMETHING THAT WOULD STOP EXISTING THE INSTANT THE
    DOCUMENT IS WRITTEN, for the same underlying reason as the tree itself,
    and are refused here for it (review of story 14.4): the SOURCE ARCHIVE --
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

    # DESTINATION HAS NO VALUE UNDER `--replace` (AC-3.2 forbids it), so this
    # refusal has no object there: the tree-containment check above already
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


def configure_logging(verbose: bool, quiet: bool) -> None:
    """Set up logging for the command line, and only for it."""
    package_logger = logging.getLogger("unboxr")
    package_logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))

    if quiet:
        handler.addFilter(_QuietFilter())
    package_logger.addHandler(handler)


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
    # must still say it. Verified in code review, story 14.3.
    for entry in report.widened:
        logger.info("Recognised by content -- %s: %s", entry.path,
                    text_for(entry.code))


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # FIRST OF ALL THE REFUSALS, because it is the only one decidable without
    # touching the file system at all. See `check_linked_bom`.
    check_linked_bom(parser, args.linked_bom, args.sbom)

    # DECIDABLE FROM argv ALONE, next: the shape of the invocation itself,
    # before a single path on disk is looked at (story 14.8, AC-2/AC-3/AC-4).
    # `--replace` and `--no-archive-dir` being mutually exclusive is already
    # enforced by `build_parser`'s own argument group.
    if args.replace and args.destination is not None:
        parser.error("DESTINATION is not accepted with --replace: the "
                     "archive is extracted in place, on its own path (AC-3.2)")
    if not args.replace and args.destination is None:
        parser.error("the following arguments are required: destination "
                     "(omit it only together with --replace)")

    is_source_url = is_url(args.archive)
    if args.replace and is_source_url:
        parser.error("--replace is refused on a URL: there is no local "
                     "file to replace (AC-3.3)")

    # A SOURCE THAT IS ALREADY A DIRECTORY has neither an archive to replace
    # nor a wrapper directory to omit: `prepare_source` extracts nothing on
    # this branch (D-D). Both options are refused here, with their cause,
    # rather than silently accepted and ignored (AC-3.4, AC-4.5).
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
        # NON-EMPTY IS REFUSED ONLY UNDER `--no-archive-dir` (AC-4.2). The
        # default mode drops this rule (AC-2.4): DESTINATION may hold other
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

    configure_logging(args.verbose, args.quiet)
    logger = logging.getLogger("unboxr.cli")

    # THE REPORT IS CREATED HERE, BEFORE THE RUN, AND HELD ACROSS IT. That is
    # what makes the failure path below able to declare: `prepare_source`
    # returns nothing when it raises, and the amputations that happened before
    # the failure would go with it.
    report = new_report()

    try:
        prepared = prepare_source(args.archive, workspace=destination,
                                  report=report, replace=args.replace,
                                  no_archive_dir=args.no_archive_dir)
    except Exception as exc:
        logger.error("%s: %s", exc.__class__.__name__, exc)
        # `summarise` too, on this path, not just the numeric reminder: this
        # is the exact moment the report exists to serve -- everything it
        # holds from before the failure (containers opened, amputations
        # already announced) would otherwise go unsaid, contradicting the
        # module docstring's own claim that the failure path can declare.
        # Verified in code review, story 14.3.
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
        _write_document(args.sbom, report, None, args.archive, None,
                        sbom.SOURCE_UNDETERMINED, logger,
                        linked_bom=args.linked_bom)
        return 1

    summarise(report, logger)
    if report.amputation_count():
        logger.warning(ORACLE_REMINDER, report.amputation_count())

    logger.info("Distribution nature: %s", prepared.nature)
    if prepared.digest is not None:
        logger.info("Input digest: sha256:%s", prepared.digest)
    source_kind = (sbom.SOURCE_IS_DIRECTORY if prepared.nature == "directory"
                   else sbom.SOURCE_IS_ARCHIVE)
    written = _write_document(args.sbom, report, prepared.tree, args.archive,
                              prepared.digest, source_kind, logger,
                              linked_bom=args.linked_bom)
    # `stdout` carries the tree whatever happened to the document: the
    # extraction is not lost because a write failed.
    print(prepared.tree)
    return 0 if written else 1


def _write_document(document_path, report, tree, source, source_digest,
                    source_kind, logger: logging.Logger,
                    linked_bom=None) -> bool:
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
            source_kind=source_kind, linked_bom=linked_bom)
        sbom.write_document(document, document_path)
    except Exception as exc:
        logger.error("the extraction document could not be written to %s: "
                     "%s: %s", document_path, exc.__class__.__name__, exc)
        return False
    logger.info("Extraction document written: %s", document_path)
    return True


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
