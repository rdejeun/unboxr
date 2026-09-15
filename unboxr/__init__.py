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
# 2.0.1: six internal correctness fixes found in adversarial code review of
# 2.0.0 (15 September 2026), none of which touches a public signature or the
# shape of what any caller observes on a correct run: a false
# `DESTINATION_ALREADY_OCCUPIED` report entry fired on every single URL +
# `--no-archive-dir` run (the just-downloaded copy was counted against
# itself); the URL naming rule was computed twice, independently, in
# `resolve_archive_name` and `download_source` -- now the latter calls the
# former; `resolve_archive_name`'s local branch gained the same empty-name
# fallback its URL branch already had; `_extract_replacing_archive_with_
# its_own_content`, a private function, lost a parameter it never read;
# `check_extraction_target` threads `replace`/`no_archive_dir` through
# instead of a literal `False` duplicating its own guard, and its second
# `parser.error` no longer falls through unconditionally. A PATCH version:
# nothing that existed changed shape, and nothing was added.
# 2.1.0: the document became readable. Its keys come out in the order
# `bom-1.7.schema.json` declares them rather than alphabetically, every
# `property` and every `hash` is folded onto ONE line, and the calculated
# timestamp stops at the second it actually measures instead of offering six
# decimals taken when the document was built. SAME KEYS AND SAME COMPONENTS,
# and reading the text back gives the object it always gave. ONE VALUE DOES
# CHANGE, and it is the timestamp: fewer digits, floored, so the document now
# names an instant up to a second earlier than the build. Writing "same
# values" here, two sentences after announcing the change, would be this
# ledger contradicting itself inside one entry -- the exact defect it exists
# to prevent. A document is half as tall for the rest (measured on a flat zip
# of two files: 189 lines down to 90).
# MINOR AND NOT A PATCH: the BYTES a caller stores change, so a consumer
# comparing a document written by 2.0.1 with one written here finds them
# different for a reason that has nothing to do with the corpus.
# AND MINOR RATHER THAN MAJOR, WHICH IS THE HARDER CALL AND DESERVES THE REAL
# ARGUMENT. "No public signature moved" is NOT that argument: it is narrower
# than the rule 2.0.0 applied to itself, and by 2.0.0's own wording -- every
# caller gets a different result with nothing to opt into -- output that
# changes for every caller would be a major. What settles it is that byte
# identity was never promised ACROSS versions: the determinism contract
# (README, "The extraction document is not a fifth guarantee") already scopes
# comparison to one machine under one version of `unboxr`, precisely because
# the document carries what THAT machine can open. A consumer who compared
# across versions was relying on something this package declined to promise.
# THE COST, SO THAT NOBODY HAS TO DISCOVER IT: `serialise` is about 7.5x
# slower and peaks at 4-5x the memory (20 000 components: 124 ms and 22 MB
# become 936 ms and 88 MB). Three passes now stack -- ordering, encoding,
# folding -- where there was one. Accepted rather than optimised: the fold's
# safety argument rests on the pass being simple enough to check by reading
# it, and the README scopes this document to "a few thousand files".
# The order tables are module-level in `unboxr.sbom` and deliberately NOT
# exported: they are how this package presents a document, not part of what
# it promises about one.
# 2.1.1: ten fixes from the adversarial code review of 2.1.0 (15 September
# 2026), none of which changes what the document says. THREE ARE BEHAVIOUR,
# and all three restore or complete what 2.1.0 meant to do: a dictionary held
# in a TUPLE is now ordered like any other (`json.dumps` encodes a tuple as an
# array, so skipping it left exactly the construction-order dependence the key
# table exists to remove); a CIRCULAR document raises `ValueError: Circular
# reference detected` again, as it did before the ordering pass existed,
# instead of exhausting the stack; and `build_document` writes the BOM link in
# the schema's order, so the dictionary it RETURNS and the text `serialise`
# produces no longer disagree. The rest are diagnostics and prose: the
# contradiction message now names the cycle instead of every key downstream of
# it, a table written as a bare string is refused rather than read one letter
# per key, the fold refuses `NaN` and the infinities rather than claiming it
# validated JSON, the order tables are read-only, the depth ceiling and the
# timestamp's loss of discriminating power are written down, and this ledger
# stopped saying "same values" one sentence after announcing that the
# timestamp changed. A PATCH version: no public signature moved, and no
# document this package builds comes out differently.
# 2.2.0: the command can say what THIS machine opens. `--list-formats`
# projects the extension tables onto FOUR states -- opened by the standard
# library, delegated to a 7-Zip binary, recognised and refused, recognised and
# deliberately not opened -- with `--json` for the same thing in a shape a
# consumer can read, and the projection itself
# (`extraction.project_format_support`) computes every count from the tables at
# the moment of the call. FOUR STATES AND NOT TWO is the substance of the
# entry: a two-column listing has nowhere to put the Zstandard extensions and
# no column at all for the office containers, and a listing that dropped the
# delegated extensions on a machine without the binary would assert unboxr does
# not know them.
# A MINOR version: no public signature moved, no document changed a byte, and
# no archive that was extracted before is extracted differently.
# WHAT IS NOT PURE ADDITION -- THREE THINGS, written down rather than glossed
# over, because the first draft of this entry claimed "no existing invocation
# produces a different result" and the third item below is a counter-example.
# (a) `archive` became an optional positional, so argparse no longer writes
# "the following arguments are required: archive" itself -- `main` writes it,
# in argparse's own words with the new condition appended. Same code 2, same
# refusal, a longer sentence. It is the same move `destination` made at 2.0.0.
# (b) The USAGE LINE of `--help` changed with it: `[archive]` is advertised
# optional unconditionally, where it read as mandatory before. A one-line
# usage cannot say "optional only with --list-formats"; the option's own help
# text says it, and `main` enforces it.
# (c) AND THE ONE THAT IS A BEHAVIOURAL REGRESSION ON AN INVOCATION THAT
# WORKED: `--l` and `--li` were valid abbreviations of `--linked-bom` and now
# exit 2 with "ambiguous option", because argparse's prefix matching finds
# `--list-formats` as well. Measured on 15 September 2026. It is the whole
# reason the sentence "no existing invocation produces a different result"
# does not appear in this entry.
# WHAT WAS NOT DONE ABOUT IT, AND WHY. The option keeps its name: it was
# chosen deliberately, and renaming a documented option to protect an
# abbreviation that was never documented trades a real name for a shadow one.
# `allow_abbrev=False` was rejected too -- it would kill EVERY abbreviation of
# every option at once, which is a far wider break than the two this costs.
# `--link`, `--linked` and the full `--linked-bom` are unaffected, and the
# ambiguity is now pinned by a test so that it is a declared fact rather than
# a surprise met in the field.
# NOTHING IS EXPORTED. `project_format_support` and the state names are read
# by `unboxr.cli` straight from `unboxr.extraction`; neither `__all__` nor the
# imports above grew, because adding a name to the published surface is a
# decision of its own and this release did not need one.
__version__ = "2.2.0"

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
