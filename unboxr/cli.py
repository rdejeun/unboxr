"""The `unboxr` command line.

A DELIBERATE FLOOR, not a finished interface. It does one thing: open an
archive into a destination directory and say where the result is. It reports
nothing structured, writes no document, and offers no option beyond verbosity
and version. Later work will add a structured report and a document; do not
design their options here, and do not grow this module in anticipation of them.

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
from .extraction import prepare_source

# The SIX amputations of the corpus, named one by one.
#
# An amputation is a container that was NOT opened: whatever it held is absent
# from the extracted tree, so absence of a finding downstream proves nothing
# about it. The counter below drives the closing reminder.
#
# The keys are the exact logging format strings emitted by `unboxr.extraction`.
# Matching on the format string -- not on the formatted message, and not on the
# level -- is what makes this a counter on NAMED amputations rather than a
# counter on warnings: one warning of the module, the fallback-naming one, is
# NOT an amputation and must not be counted. A test walks the AST of
# `extraction.py` and fails if any of these strings is no longer emitted there,
# so a reworded message cannot silently stop being counted.
AMPUTATION_MESSAGES = {
    "office container refused": (
        "%s: office container, excluded from extraction -- its "
        "content is not the material this tool opens."
    ),
    "several tars in a .7z envelope, only the first extracted": (
        "The .7z envelope contains %s .tar files. Only the first in "
        "sorted order is extracted: %s. NOT EXTRACTED: %s. No "
        "conclusion can be drawn from the absence of a finding on "
        "those archives."
    ),
    "nested archive failed to extract": (
        "Extraction of %s (%s) failed: %s (archive kept as is). "
        "Its content is NOT in the extracted tree."
    ),
    "maximum nesting depth reached": (
        "Maximum depth (%s) reached: flattening stops, archives may "
        "remain unopened. Their content is NOT in the extracted tree."
    ),
    "tar archive refused by the security filter": (
        "Tar member refused by the security filter: %s (%s). The "
        "archive is NOT extracted: no conclusion can be drawn from "
        "the absence of a finding on its content."
    ),
    # Added on 9 September 2026, with the repair that produced it: a tar whose
    # staged content could not be moved into the destination in full leaves an
    # INCOMPLETE tree. Incomplete is a kind of absent, and the caller must not
    # read the missing part as "nothing was there".
    "tar content only partly moved into its destination": (
        "%s: the extracted content could not be moved into %s in "
        "full. That directory now holds an INCOMPLETE extraction: no "
        "conclusion can be drawn from the absence of a finding on "
        "its content."
    ),
}

# Warnings the module emits that are NOT amputations, each with its reason.
# This set exists so that the two together are EXHAUSTIVE over the warnings of
# `unboxr.extraction`: a test requires every warning to be in one list or the
# other. Without it, a warning added later is counted by nothing and named by
# nothing -- which is exactly how the partial-move amputation above went
# uncounted the day it was written (code review, 9 September 2026).
NOT_AN_AMPUTATION = {
    # Nothing is lost: the two contents end up in the same directory. The
    # warning exists because a SILENT merge is untraceable, not because the
    # corpus shrank.
    "%s: destination %s already holds content; extracting into it "
    "merges the two, with no further warning.",
    "Destination %s already holds content; extracting into it merges "
    "the two, with no further warning.",
    # The content IS in the extracted tree; only the source archive survived.
    "%s was extracted successfully but could not be removed (%s): the "
    "archive is kept alongside its own extracted content. Its content "
    "IS in the extracted tree.",
    # A RECAP of amputations already counted one by one. Counting it again
    # would inflate the total by one per run.
    "Flattening finished, but %s archive(s) were left unopened: %s. "
    "Their content is NOT in the extracted tree.",
    # A naming caveat, not a loss -- and the reason the counter matches on
    # named amputations rather than on warnings.
    "Archive outside the analysed root, fallback naming derived from the "
    "absolute path: %s. The produced name depends on the machine.",
}

# Not an amputation: the corpus GROWS here, because an archive was recognised by
# its content. Named for the same reason -- a corpus that grows without a trace
# is no better than one that shrinks without a trace -- and kept out of the
# counter on purpose.
CORPUS_WIDENING_MESSAGE = (
    "%s: archive recognised by its CONTENT (%s) -- extension "
    "absent or misleading."
)

ORACLE_REMINDER = (
    "%s container(s) were not opened during this run. What could not be opened "
    "cannot be reported on: absence of a finding is never evidence of absence."
)


class AmputationCounter(logging.Filter):
    """Counts the named amputations passing through the package logger."""

    def __init__(self) -> None:
        super().__init__()
        self.count = 0

    def filter(self, record: logging.LogRecord) -> bool:
        if record.msg in AMPUTATION_MESSAGES.values():
            self.count += 1
        return True


class _QuietFilter(logging.Filter):
    """Under `--quiet`, keeps warnings AND every named amputation.

    `--quiet` never drops below what declares an amputation. The most frequent
    amputation of all -- an office container being refused -- is emitted at the
    informational level, so a quiet mode that simply raised the threshold to
    warnings would silence it. Muting an amputation on request would contradict
    the positive-only oracle this package is built on.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno >= logging.WARNING or record.msg in AMPUTATION_MESSAGES.values()


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


def configure_logging(verbose: bool, quiet: bool) -> AmputationCounter:
    """Set up logging for the command line, and only for it."""
    package_logger = logging.getLogger("unboxr")
    package_logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))

    # THE COUNTER GOES ON THE HANDLER, AND FIRST.
    #
    # On the logger it would never fire: `unboxr.extraction` emits on its own
    # child logger, and a parent's FILTERS are not applied to a propagated
    # record -- only its HANDLERS are. A counter installed on `unboxr` itself
    # would sit there reading zero for ever, and the oracle reminder would never
    # be shown on a run that did amputate the corpus.
    #
    # First, because `logging` stops at the first filter that rejects: behind
    # the quiet filter, the counter would stop seeing whatever quiet mode drops.
    counter = AmputationCounter()
    handler.addFilter(counter)
    if quiet:
        handler.addFilter(_QuietFilter())
    package_logger.addHandler(handler)
    return counter


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    destination: Path = args.destination
    if destination.exists() and not destination.is_dir():
        parser.error(f"destination is not a directory: {destination}")
    if destination.is_dir() and any(destination.iterdir()):
        parser.error(f"destination exists and is not empty: {destination}")

    counter = configure_logging(args.verbose, args.quiet)
    logger = logging.getLogger("unboxr.cli")

    try:
        tree, nature, digest = prepare_source(args.archive, workspace=destination)
    except Exception as exc:
        logger.error("%s: %s", exc.__class__.__name__, exc)
        if counter.count:
            logger.warning(ORACLE_REMINDER, counter.count)
        return 1

    if counter.count:
        logger.warning(ORACLE_REMINDER, counter.count)

    logger.info("Distribution nature: %s", nature)
    if digest is not None:
        logger.info("Input digest: sha256:%s", digest)
    print(tree)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
