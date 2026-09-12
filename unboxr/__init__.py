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
    resolve_distribution_nature,
    UnsupportedFormatError,
)
from .report import (
    CapabilityProfile,
    CAUSE_TEXTS,
    ContainerRecord,
    ExtractionReport,
    PreparedSource,
    text_for,
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
__version__ = "1.0.0"

logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    "__version__",
    # The extraction report: what was opened, and what was not
    "report",
    "CapabilityProfile",
    "CAUSE_TEXTS",
    "ContainerRecord",
    "ExtractionReport",
    "PreparedSource",
    "new_report",
    "probe_capability_profile",
    "text_for",
    "UnsupportedFormatError",
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
    "resolve_distribution_nature",
]
