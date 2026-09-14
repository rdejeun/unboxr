"""unboxr -- deterministic recursive archive extraction, standard library only.

`unboxr` opens a container, then the containers it finds inside it, and hands
back a directory -- together with a REPORT of what it could not open. It renders
no verdict on what it extracted.

Read `unboxr.extraction` for the positive-only oracle reminder and the full
determinism contract, and `unboxr.report` for the report itself; all of it is
part of the published interface, not commentary.

This package NEVER configures logging. It attaches a `NullHandler` to its root
logger, which is the one thing a library may do: without it, `logging`'s
handler of last resort writes warnings to stderr, so a caller that has
configured nothing would still see output it never asked for. Applications
configure handlers and levels themselves; `unboxr.cli` does it for the command
line, and for nothing else.
"""

from __future__ import annotations

import logging

from . import report
from . import sbom
from .extraction import (
    ARCHIVE_SIGNATURES,
    CATEGORIES_NEEDING_SEVEN_ZIP,
    CATEGORY_BY_EXT,
    CATEGORY_IF_NOT_A_TAR,
    NATIVE_TAR_MODES,
    NATURE_BY_EXTENSION,
    NOT_EXTRACTED_EXTENSIONS,
    PROVISIONAL_DIGEST_LENGTH,
    SORTED_EXTENSIONS,
    categorize_archive,
    categorize_by_content,
    download_source,
    extract_archive,
    extract_plain_bz2,
    extract_plain_gzip,
    extract_plain_lzma,
    extract_plain_xz,
    extract_tar_7z,
    extract_tar_lzma,
    extract_with_7zip,
    find_7zip_binary,
    flatten_nested_archives,
    is_archive,
    is_url,
    new_report,
    prepare_source,
    probe_capability_profile,
    resolve_archive_name,
    resolve_distribution_nature,
    resolve_extraction_root,
    UnsupportedFormatError,
)
from .report import (
    CapabilityProfile,
    CAUSE_TEXTS,
    ContainerRecord,
    ExtractionReport,
    ORACLE_REMINDER_SENTENCE,
    PATH_FRAMES,
    PreparedSource,
    text_for,
)
from .sbom import (
    BOM_LINK_DOCUMENT_PATTERN,
    DIGEST_STATES,
    InvalidBomLinkError,
    LINKED_BOM_COMMENT,
    PROPERTY_NAMES,
    build_document,
    is_bom_link_to_a_document,
    serialise,
    write_document,
)

# THE single source of truth for the version. `pyproject.toml` reads it from
# here through `[tool.setuptools.dynamic]`. The reverse direction is forbidden:
# reading the version back from installed metadata fails whenever the package is
# used straight from a clone, which is exactly how it is used today.
# 1.0.0: the extraction report became a returned value, which is the last
# thing this package was missing to be usable by a consumer that never
# configured logging. The arity of `prepare_source` changed with it -- the
# second declared departure from the signature this code was carved out of, and
# the reason the change lands on a major version rather than being slipped into
# a minor one. It declares NOTHING about publication: no hosting is available,
# and no consumer is wired to this package yet.
# 1.1.0: the extraction document. `unboxr.sbom` projects the report and the
# tree onto a CycloneDX inventory, every record gained a digest and the frame
# of its path, and the command gained one option to write it. ALL ADDITIONS --
# nothing that existed changed shape, every new parameter defaults to what the
# previous behaviour was -- so a MINOR version, never a break.
# 1.2.0: the document says which other BOM it belongs to. One native field
# more (`externalReferences` at the root, never a property of this package's
# own), one command option, and a check of the URN's shape that the published
# schema does not perform. ADDITIONS again -- a document produced without the
# new option is byte-for-byte what the previous version produced -- so a MINOR
# version.
# 2.0.0: the level-0 extraction root stopped being the fixed name `extracted`
# and started obeying the SAME rule the determinism contract already stated
# for a nested archive -- its own name, verbatim (story 14.8 of the upstream
# project, crypto-scan). That is a CHANGE OF SHAPE, not an addition: every
# caller of `prepare_source`, and every invocation of the command line, gets a
# tree at a DIFFERENT path than before, with nothing to opt into or out of.
# `EXTRACTED_TREE_NAME`, a published name in `__all__`, is REMOVED rather than
# deprecated -- the value it named no longer exists to be pointed at. Two
# command-line options are ADDED to name the other two modes (`--replace`,
# `--no-archive-dir`), which on their own would be a minor release; it is the
# breaking change to the default that decides the major, exactly as it did
# for 1.0.0's change of arity. "Nobody consumes this package yet" was already
# true at 1.0.0 and was explicitly not the reason for its major either: the
# reason, both times, is that the version block stays a readable ledger of
# what changed shape and what only grew.
__version__ = "2.0.0"

logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    "__version__",
    # The extraction report: what was opened, and what was not
    "report",
    "CapabilityProfile",
    "CAUSE_TEXTS",
    "ContainerRecord",
    "ExtractionReport",
    "ORACLE_REMINDER_SENTENCE",
    "PATH_FRAMES",
    "PreparedSource",
    "new_report",
    "probe_capability_profile",
    "text_for",
    "UnsupportedFormatError",
    # The document: the corpus as a record that outlives the run
    "sbom",
    "DIGEST_STATES",
    "PROPERTY_NAMES",
    "build_document",
    "serialise",
    "write_document",
    # The link to another BOM. The pattern and its predicate are public for a
    # named reason: a caller forming such a URN in the other direction reads
    # them from here instead of transcribing the pattern a second time.
    "BOM_LINK_DOCUMENT_PATTERN",
    "InvalidBomLinkError",
    "LINKED_BOM_COMMENT",
    "is_bom_link_to_a_document",
    # Tables
    "ARCHIVE_SIGNATURES",
    "CATEGORIES_NEEDING_SEVEN_ZIP",
    "CATEGORY_BY_EXT",
    "CATEGORY_IF_NOT_A_TAR",
    "NATIVE_TAR_MODES",
    "NATURE_BY_EXTENSION",
    "NOT_EXTRACTED_EXTENSIONS",
    "PROVISIONAL_DIGEST_LENGTH",
    "SORTED_EXTENSIONS",
    # Recognition
    "categorize_archive",
    "categorize_by_content",
    "is_archive",
    # `is_url` is deliberately public: it answers a question of its own ("is
    # this string a public HTTP(S) URL?") that callers ask before they ever
    # decide to extract anything, and at least one known consumer calls it
    # without going anywhere near an archive.
    "is_url",
    # Acquisition and extraction
    "download_source",
    "extract_archive",
    "extract_plain_bz2",
    "extract_plain_gzip",
    "extract_plain_lzma",
    "extract_plain_xz",
    "extract_tar_7z",
    "extract_tar_lzma",
    "extract_with_7zip",
    "find_7zip_binary",
    "flatten_nested_archives",
    # End-to-end entry point
    "prepare_source",
    "resolve_archive_name",
    "resolve_distribution_nature",
    "resolve_extraction_root",
]
