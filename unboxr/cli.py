"""The `unboxr` command line.

A DELIBERATE FLOOR, and one that has now been added to once. It opens an
archive into a destination directory, says where the result is, and summarises
what could not be opened. It writes no document and offers no option beyond
verbosity and version; the document, and the options it will need, are later
work and are not designed here.

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

`unboxr` has no self-check gate, no strict mode, and renders no verdict of any
kind.

This module is the ONLY place in the package that configures logging. The
library never does (see `unboxr/__init__.py`).
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from . import __version__
from .extraction import new_report, prepare_source
from .report import AMPUTATION_MESSAGES, text_for

ORACLE_REMINDER = (
    "%s container(s) were not opened during this run. What could not be opened "
    "cannot be reported on: absence of a finding is never evidence of absence."
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
        help="Directory to unpack under. It must be empty or absent; the "
             "extracted tree is created in DESTINATION/extracted.",
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
        "--version", action="version", version=f"unboxr {__version__}",
    )
    return parser


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

    NO DOCUMENT IS WRITTEN and nothing structured reaches `stdout`, which stays
    reserved for the path of the extracted tree -- the one output of this
    program that is not a logging record. A consumer piping `unboxr a.zip d`
    into something else must not find a summary in the middle of it.
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

    destination: Path = args.destination
    if destination.exists() and not destination.is_dir():
        parser.error(f"destination is not a directory: {destination}")
    if destination.is_dir() and any(destination.iterdir()):
        parser.error(f"destination exists and is not empty: {destination}")

    configure_logging(args.verbose, args.quiet)
    logger = logging.getLogger("unboxr.cli")

    # THE REPORT IS CREATED HERE, BEFORE THE RUN, AND HELD ACROSS IT. That is
    # what makes the failure path below able to declare: `prepare_source`
    # returns nothing when it raises, and the amputations that happened before
    # the failure would go with it.
    report = new_report()

    try:
        prepared = prepare_source(args.archive, workspace=destination,
                                  report=report)
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
        return 1

    summarise(report, logger)
    if report.amputation_count():
        logger.warning(ORACLE_REMINDER, report.amputation_count())

    logger.info("Distribution nature: %s", prepared.nature)
    if prepared.digest is not None:
        logger.info("Input digest: sha256:%s", prepared.digest)
    print(prepared.tree)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
