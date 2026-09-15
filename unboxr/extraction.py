"""Recursive, deterministic archive extraction -- standard library only.

`unboxr` opens a container and, level by level, the containers it finds inside
it. That is all it does. It renders no verdict of any kind on what it extracts:
it does not classify, does not score, and knows nothing about the content it
hands back.

POSITIVE-ONLY ORACLE
--------------------
What could not be opened cannot be reported on: absence of a finding is never
evidence of absence. Every container that `unboxr` refuses, skips or fails to
open amputates the corpus its caller will go on to use, and every such
amputation is RETURNED, in the report `prepare_source` hands back (see
`unboxr.report`), and announced through the logging system besides (see
"Logging" below). The report is what makes it inescapable: a caller cannot
obtain the tree without also receiving it, whereas a caller who configured no
logging handler hears nothing. A silent corpus is worse than a small one.

DETERMINISM CONTRACT
--------------------
`unboxr` guarantees the following four properties. Everything else belongs to
the consumer.

1. Traversal order. Flattening, and the selection of the single `.tar` inside a
   `.7z` envelope, both iterate in the order of the POSIX relative path. The
   result does not depend on the order in which the file system happens to
   enumerate directory entries.

2. Extraction directory names. Two names, and they are not the same promise.

   (a) The FINAL name. EVERY archive -- at any nesting level, level 0
       included: the one handed to `prepare_source` directly, or the one
       `download_source` just wrote for a URL -- is flattened into a
       directory carrying that archive's own name, in full and verbatim:
       extension included, no case folding, no stripping. `toto.jar` yields
       `toto.jar/`. The name is INHERITED from the input rather than built
       here, so two archives that differ by a single character can no longer
       land in one directory and merge their content. Level 0 has two other
       modes besides this default one -- see `resolve_extraction_root` and
       `unboxr.cli` for `--replace` and `--no-archive-dir`.

   (b) The PROVISIONAL name. That final path is held by the archive itself
       until it is removed, so the extraction is first written under a name
       derived from the SHA-256 digest of the archive's POSIX relative path --
       never from `hash()`, never from a rank, never from an absolute path. It
       is therefore invariant across interpreter runs, invariant across the
       nesting level at which the archive is met, and independent of every
       other archive in the tree. It has to be: it can stop being provisional
       (see the non-guarantees below).

   ONE name, and one only, is FABRICATED here: the `_decompressed` suffix a
   single-file decompression falls back on when stripping the matched
   extension leaves no name at all
   -- one named literally `.gz`, `.pack.gz`, `.lzma`, `.xz`, `.bz2` or `.bz`,
   where no natural name exists to give the payload. It is required to match no
   recognised extension, failing which the payload would be re-detected as an
   archive at the next level and reported as an amputation that never happened.

3. POSIX paths. Every path used as a sort key or as a component of a produced
   name goes through `.as_posix()`. The PROVISIONAL name above is a valid path
   component on Windows and on Linux alike, made of digits, letters `a-f` and
   `_` only. The FABRICATED name is too, but it is not limited to that
   character set: it carries whatever the archive's own name did before the
   matched extension was stripped away, a literal `.` included in the
   degenerate case above (`.gz` yields `.gz_decompressed`). The FINAL name is
   not this package's to promise at all: it is the name the input already
   carries on the file system it came from.

4. The corpus report. Every amputation of the corpus -- a container refused by
   policy, one recognised and not opened for want of a capability, one that
   failed to be read, one still closed when flattening stopped -- is in the
   report `prepare_source` RETURNS, and the report is returned on EVERY way
   out, the one that extracts nothing included. A report may also be passed IN,
   and one that was survives the exception that ends a run. Each entry carries
   a stable cause CODE; its English text is derived from that code by one
   table, in `unboxr.report`, and never written a second time.

THE EXTRACTION DOCUMENT IS NOT A FIFTH GUARANTEE
-----------------------------------------------
`unboxr.sbom` produces the same bytes for the same tree, the serial number and
the timestamp aside -- which the document names itself, in a field of its own.
That is an OBSERVATION, and it is deliberately NOT added to the four
guarantees above. The document carries what THIS machine can open, so one
archive yields two different documents on two machines whose 7-Zip
availability differs, legitimately and by design; promising byte-identity would
make this contract false the first time that happened. Comparing two documents
is something to do on one machine, under one version of this package.

Saying so is not pedantry: a reader who observed the stability and found the
contract silent would conclude a promise that is not there.

WHAT THE CONTRACT DOES NOT GUARANTEE
------------------------------------
- No symbolic-link containment in flattening. Links inside an extracted tree
  are left exactly as the archive wrote them.
- No exclusion of tooling directories such as `__pycache__`, `.git` or
  `.venv`. That is the consumer's policy, applied after extraction; `unboxr`
  has no notion of them.
- No guarantee on any document a consumer builds downstream from the extracted
  tree.
- No guarantee on the corpus when the 7-Zip binary is absent. How many of the
  recognised extensions need it is COUNTED on the machine that asks --
  `unboxr --list-formats`, or `project_format_support()` under it -- rather
  than written down anywhere as a figure that would drift.
- No guarantee that the tree produced is identical to the one produced before
  the tar security filter was made mandatory: the filter refuses archives that
  earlier versions extracted. In exchange the behaviour is now stable from one
  Python release to the next -- the filter being requested explicitly, the
  change of default in Python 3.14 has no effect here.
- No guarantee on what the report says about CONTENT. It names containers,
  what became of them, and -- since the extraction document -- the SHA-256
  digest of each one that could still be read when it was filed. It opens
  nothing to look inside, it says nothing about what any of it MEANS, and AN
  ABSENT ENTRY ESTABLISHES NOTHING -- the oracle is positive only, here as
  everywhere else in this package.
- No guarantee that the provisional extraction name stays provisional. It is
  normally transitory -- the directory is renamed as soon as the archive is
  gone -- but it becomes the DEFINITIVE name of that directory whenever the
  rename fails, and a failed extraction leaves it behind too. It is
  deterministic in both cases, which is the whole reason it is a digest rather
  than a temporary directory.
- No guarantee that the extraction root is a valid path component. Its name is
  INHERITED from the input -- the archive's own name as given, or the last
  segment of its URL -- exactly as guarantee 2(a) already only inherits,
  never validates, the FINAL name of an archive nested at any deeper level;
  this extends that same non-guarantee down to level 0, the root the whole
  tree grows from (story 14.8 of the upstream project, crypto-scan).

LOGGING
-------
This module never configures logging. It emits on `logging.getLogger(__name__)`
and the package installs nothing but a `NullHandler` on its root logger (see
`unboxr/__init__.py`). Importing `unboxr` and running a full extraction writes
nothing to stdout and nothing to stderr. Configuring handlers, levels and
formats is the application's job; `unboxr.cli` does it for the command line and
for nothing else.
"""

from __future__ import annotations

import bz2
import gzip
import hashlib
import logging
import lzma
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from urllib.parse import urlparse

from .report import (
    ARCHIVE_KEPT_AFTER_SUCCESSFUL_EXTRACTION,
    ARCHIVE_OUTSIDE_THE_ANALYSED_ROOT,
    CapabilityProfile,
    DESTINATION_ALREADY_OCCUPIED,
    DIRECTORY_OF_A_DIFFERENT_ORIGIN_DISCARDED,
    DOWNLOADED_COPY_KEPT_ALONGSIDE_THE_TREE,
    EXTRACTION_FAILED,
    EXTRACTION_KEPT_UNDER_PROVISIONAL_NAME,
    ExtractionReport,
    INPUT_CONTAINER_OPENED,
    MAXIMUM_DEPTH_REACHED,
    NESTED_CONTAINER_OPENED,
    OFFICE_CONTAINER_EXCLUDED,
    PreparedSource,
    PATH_FRAME_UNKNOWN,
    PATH_IS_BARE_NAME,
    PATH_IS_TREE_RELATIVE,
    PROVISIONAL_DIRECTORY_ALREADY_OCCUPIED,
    RECOGNISED_BY_CONTENT,
    SEVEN_ZIP_BINARY_MISSING,
    SEVERAL_TARS_ONLY_FIRST_EXTRACTED,
    TAR_CONTENT_PARTLY_MOVED,
    TAR_REFUSED_BY_SECURITY_FILTER,
    ZSTD_NOT_SUPPORTED,
)

logger = logging.getLogger(__name__)


class UnsupportedFormatError(RuntimeError):
    """A container RECOGNISED, and refused for want of a capability.

    A SUBCLASS of `RuntimeError`, deliberately: these three refusals have
    always been raised as `RuntimeError`, and every `except RuntimeError`
    already written against this package must keep catching them. What is new
    is the `code` attribute, which lets the site that catches the exception
    tell a refusal from a READ FAILURE instead of filing both under one generic
    cause.

    The code is ADDED to the message, never REPLACING any of it -- true of all
    three sites. The oracle reminder itself is unchanged only at the
    Zstandard site, where it already carried one; the two 7-Zip sites
    (missing binary, unsupported delegated format) gain the reminder sentence
    here, they did not already have it. Corrected in code review, story 14.3:
    this docstring previously claimed the reminder, too, was unchanged
    everywhere.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


# --- Filling the report, without ever becoming what amputates the corpus -----
#
# A guard must never be the thing that shortens the corpus. The occupancy check
# in `flatten_nested_archives` sits outside its `try` for exactly that reason:
# an exception there would abort the whole flattening and leave every remaining
# archive unopened with no record at all. THE BOOKKEEPING INHERITS THAT
# CONSTRAINT. `_record` therefore swallows whatever the report does, including a
# report a caller subclassed badly: losing one entry is bad, losing the rest of
# the extraction is worse.
#
# It is not a silent fallback in the sense this project forbids elsewhere. There
# is no alternative result being chosen here and no conclusion being drawn --
# only a note that could not be taken.
def _reportable_path_and_frame(path, root=None):
    """The path a record carries, AND what that path is relative to.

    ONE predicate, one home. The frame is only knowable HERE -- this is the
    function that either succeeded in making the path relative to a root or
    fell back on the bare name -- and it used to be dropped on the way out.
    Recovering it afterwards from the cause code is not possible and must not
    be attempted: four call sites pass `location or <path>`, so one code yields
    a relative path in one run and a bare name in another. A second predicate
    written elsewhere is the duplicated predicate this project has already been
    told off for once.

    NEVER an absolute path. It would depend on the machine, and reopen the
    first of the two inter-platform divergences guarantee 3 of the determinism
    contract exists to close.
    """
    if isinstance(path, str):
        # Already computed by the caller, against something this package cannot
        # see. UNKNOWN, which excludes nothing downstream -- never guessed to be
        # relative because it happens to contain a slash.
        return path, PATH_FRAME_UNKNOWN
    path = Path(path)
    if root is not None:
        try:
            return path.relative_to(root).as_posix(), PATH_IS_TREE_RELATIVE
        except ValueError:
            pass
    return path.name, PATH_IS_BARE_NAME


def _reportable_path(path, root=None) -> str:
    """The path alone. Used as a sort key and as a `location`: both want a
    string, and neither has anything to do with the frame."""
    return _reportable_path_and_frame(path, root)[0]


def _digest_of_existing_file(path) -> str | None:
    """The digest of a file that is still there, or `None` -- never a raise.

    THE THREE STATES ARE NOT INTERCHANGEABLE and none of them is an error: a
    path that names a directory, one whose file has already been removed, and
    one whose bytes could not be read all yield `None` here, and the record is
    filed all the same. What must never happen is the opposite -- a digest
    failing and taking the record, or the rest of the flattening, with it. That
    is why nothing escapes: a note that could not be taken, never a failure.

    Hashing itself goes through `_sha256_digest_of_file` and nowhere else: a
    second implementation of the same digest is exactly the duplication this
    project has already paid for.
    """
    if path is None:
        return None
    try:
        candidate = Path(path)
        if not candidate.is_file():
            return None
        return _sha256_digest_of_file(candidate)
    except Exception:
        return None


def _record(report, code: str, path, root=None, level=None, detail: str = "",
            *, digest: str | None = None, digest_of=None) -> None:
    """File one container under one cause, or do nothing at all.

    TWO WAYS TO GIVE A DIGEST, and they are not the same gesture. `digest_of`
    names a file to hash HERE, in the window where it still exists; `digest`
    hands over one already taken, which the first-level container does because
    `prepare_source` hashed the received input before extracting it and reading
    those bytes a second time would buy nothing.

    NEITHER CAN FAIL THE RECORD. The computation happens outside the `try`
    below and swallows its own failures, so a digest that cannot be taken
    leaves the field at `None` and the container is still filed. A record lost
    because its digest could not be read would be the guard amputating the
    corpus.

    THE HASH IS SKIPPED WHEN IT WOULD BE THROWN AWAY. `report.record()`
    dedupes on `(code, path)`, first filing wins -- but that check used to run
    AFTER the hash, so a file re-examined at every flattening level (an office
    container left in place, a residual archive) paid for a full read each
    time even though only the first filing was ever kept. `already_recorded`
    runs the SAME test before spending the I/O. The pre-check is best-effort:
    if it cannot even be attempted, the hash still runs -- exactly today's
    behaviour, never a new way to lose a digest.
    """
    if report is None:
        return
    if digest is None and digest_of is not None:
        try:
            skip = report.already_recorded(
                code, _reportable_path_and_frame(path, root)[0])
        except Exception:
            skip = False
        if not skip:
            digest = _digest_of_existing_file(digest_of)
    try:
        text_path, frame = _reportable_path_and_frame(path, root)
        report.record(code, text_path, level=level, detail=detail,
                      digest=digest, path_frame=frame)
    except Exception:       # see the section comment above `_reportable_path`
        # RECONSIDERED in code review, story 14.3: narrowing this to `KeyError`
        # (the one documented case, an undeclared code) looked like a genuine
        # fix for a defect that hides real call-site bugs. It is not --
        # `tests/test_report_of_the_chain.py::test_recording_never_becomes_
        # what_amputates_the_corpus` deliberately hands a report whose
        # `record()` raises a bare `RuntimeError` and asserts that flattening
        # still completes: a guard must never be the thing that shortens the
        # corpus, including against a caller-supplied report subclassed badly.
        # Kept broad, on purpose, and tested as such.
        pass


def _note_depth(report, limit=None, reached=None) -> None:
    """The bound that applied, and the level actually traversed: two numbers."""
    if report is None:
        return
    if limit is not None:
        report.depth_limit = limit
    if reached is not None:
        report.depth_reached = reached


# Categorisation of EVERY recognised extension. Matching is done with
# "endswith", from the longest suffix to the shortest (see SORTED_EXTENSIONS),
# so that a compound extension (e.g. ".tar.gz") is recognised before its plain
# ending (e.g. ".gz") which, on its own, names a different format.
CATEGORY_BY_EXT = {
    # --- ZIP-shaped archives (the container is a zip, whatever the extension) ---
    ".zip": "zip", ".jar": "zip", ".whl": "zip", ".egg": "zip",

    # --- tar + compression natively supported by the tarfile module ---
    ".tar": "tar_plain",
    ".tar.gz": "tar_gz", ".tgz": "tar_gz",
    ".tar.bz2": "tar_bz2", ".tbz2": "tar_bz2",
    ".tar.xz": "tar_xz", ".txz": "tar_xz",

    # --- tar + lzma: tarfile cannot read it natively -> manual decompression
    #     (lzma module) to a temporary .tar, then ordinary tarfile ---
    ".tar.lzma": "tar_lzma", ".tlz": "tar_lzma",

    # --- tar wrapped in a 7z envelope: needs the 7-Zip binary to lift the .7z
    #     envelope, which yields a .tar then read by tarfile ---
    ".tar.7z": "tar_7z",

    # --- plain compression of A SINGLE FILE (not a multi-file archive),
    #     handled natively by the standard library ---
    ".gz": "plain_gzip", ".pack.gz": "plain_gzip",
    ".lzma": "plain_lzma",

    # --- "one-level" formats (a single archive/compression layer) delegated to
    #     an external 7-Zip binary: 7z.exe on Windows, 7zz/7z/7za on Unix.
    #     These are the formats 7-Zip extracts natively with `x`. ---
    ".7z": "external_7zip", ".rar": "external_7zip", ".iso": "external_7zip",
    ".rpm": "external_7zip", ".arj": "external_7zip", ".cab": "external_7zip",
    ".chm": "external_7zip", ".cpio": "external_7zip", ".cramfs": "external_7zip",
    ".dmg": "external_7zip", ".fat": "external_7zip", ".gpt": "external_7zip",
    ".hfs": "external_7zip", ".ihex": "external_7zip", ".lzh": "external_7zip",
    ".mbr": "external_7zip", ".msi": "external_7zip", ".nsis": "external_7zip",
    ".ntfs": "external_7zip", ".qcow2": "external_7zip", ".squashfs": "external_7zip",
    ".udf": "external_7zip", ".uefi": "external_7zip", ".vdi": "external_7zip",
    ".vhd": "external_7zip", ".vhdx": "external_7zip", ".vmdk": "external_7zip",
    ".xar": "external_7zip", ".deb": "external_7zip", ".z": "external_7zip",

    # --- plain compression of A SINGLE FILE, second batch ---
    #     The table handled ".gz" and ".lzma" alone, but neither ".xz" nor
    #     ".bz2", while ".tar.xz" and ".tar.bz2" were recognised: an
    #     unintentional asymmetry, measured 19 August 2026 in the upstream
    #     project (crypto-scan, story 05.0). Both formats are in the standard
    #     library (`lzma` and `bz2` modules) -- no dependency. ---
    ".xz": "plain_xz",
    ".bz2": "plain_bz2", ".bz": "plain_bz2",

    # --- ecosystem package containers ---
    #     These are ZIPs and TARs carrying a conventional extension: only their
    #     RECOGNITION was missing, no new extraction function is required. They
    #     are the raw material of any consumer -- a Ruby, NuGet, Android or Java
    #     package shipped as is was not opened at all, so its content never
    #     reached the caller (measured 19 August 2026 in the upstream project,
    #     crypto-scan, story 05.0). ---
    ".apk": "zip", ".aar": "zip", ".war": "zip", ".ear": "zip", ".sar": "zip",
    ".nupkg": "zip", ".xpi": "zip", ".ipa": "zip", ".pyz": "zip", ".zipx": "zip",
    ".gem": "tar_plain",
    ".tbz": "tar_bz2", ".tb2": "tar_bz2", ".tz": "tar_gz",

    # --- Zstandard: RECOGNISED, but NOT EXTRACTABLE ---
    #     `compression.zstd` only enters the standard library with Python 3.14
    #     (PEP 784), and the official 7-Zip does not handle the format either
    #     (checked against 19.00). The format is therefore declared HERE so that
    #     the chain REFUSES IT OUT LOUD rather than ignoring it in silence: an
    #     Arch `.pkg.tar.zst`, or the payload of a recent RPM, used to cross
    #     `flatten_nested_archives()` without a word, and that silence read
    #     downstream as an empty container. Never reclassify these extensions
    #     out of the table: `is_archive()` would return `False` and the silence
    #     would be back. ---
    ".zst": "zstd_unsupported", ".zstd": "zstd_unsupported",
    ".tar.zst": "zstd_unsupported", ".tar.zstd": "zstd_unsupported",
}

# Sorted by decreasing length: mandatory so that ".tar.gz" is matched before
# ".gz" (otherwise "archive.tar.gz" would be miscategorised as "plain_gzip").
# Rebuilt automatically on every addition to the table above, so later entries
# (".xz", ".bz2"...) land AFTER their compound variants with no intervention.
SORTED_EXTENSIONS = sorted(CATEGORY_BY_EXT.keys(), key=len, reverse=True)

# Containers we know how to open but CHOOSE not to open. They are all ZIP
# archives -- a `.docx` carries the `PK\x03\x04` header, indistinguishable from
# an ordinary `.zip`.
#
# Why this list exists. These formats used to be left out BY OMISSION: they
# simply were not in `CATEGORY_BY_EXT`, and categorisation was purely
# extensional. Adding content-based identification removed that implicit
# safeguard -- hence this EXPLICIT policy.
#
# Why exclude them -- three reasons in the original, one surviving here as a
# design precedent, two retired with a pointer rather than dropped outright
# (a silently dropped reason is exactly the anti-pattern this module argues
# against elsewhere):
#   1. retired -- the upstream project's own recognised-extensions table never
#      covered markup formats either, so excluding them here changed nothing
#      that table already decided (see the upstream project, crypto-scan,
#      story 05.0);
#   2. retired -- excluding them protected an upstream coverage metric
#      (EPIC-05) that has no object in a standalone package;
#   3. kept -- it mirrors a design precedent from a downstream consumer,
#      ExtractCode, whose `default_kinds` set excludes the `docs` category
#      (measured 19 August 2026 in the upstream project, crypto-scan,
#      story 05.0).
# The generic reason underneath reason 3: an office container expands to
# presentation markup and packaging parts, which is not the material a caller
# asked to open.
#
# The exclusion is EXTENSIONAL and stays that way: a `.docx` renamed to `.bin`
# will be extracted as a zip. That is consistent with the positive-only oracle
# -- nothing in the bytes tells an office document from an ordinary archive.
# This list states a policy about what a file DECLARES itself to be, never a
# verdict on what it is.
#
# No override, and no injection point. The list is frozen. The reason is not
# "there is only one consumer" -- there are TWO, `categorize_archive()` and
# `prepare_source()`, and `categorize_archive()` has four callers of its own, so
# no single injection point would make an override effective. Injecting on one
# side only would make the refusal and the error message disagree, bringing back
# a defect fixed 20 August 2026 in the upstream project. What stands here is an
# assumed default policy, reversible only by a change that would propagate the
# parameter across five signatures and test both consumers together.
NOT_EXTRACTED_EXTENSIONS = frozenset({
    # OOXML (Word, Excel, PowerPoint and their macro and template variants)
    ".docx", ".docm", ".dotx", ".potm", ".potx", ".ppsm", ".ppsx", ".pptm",
    ".pptx", ".sldx", ".xlsm", ".xlsx", ".xltm", ".xltx",
    # OpenDocument (ODF) and its packaging extension
    ".odt", ".ods", ".odp", ".odg", ".odf", ".otg", ".otp", ".ots", ".oxt",
    # StarOffice / OpenOffice.org, predating ODF
    ".sxw", ".sxc", ".sxi", ".sxd", ".sxg", ".sxm",
    ".stw", ".stc", ".sti", ".std",
    ".sdw", ".sdc", ".sdd", ".smf",
    # E-book
    ".epub",
})

NATIVE_TAR_MODES = {"tar_plain": "r:", "tar_gz": "r:gz", "tar_bz2": "r:bz2", "tar_xz": "r:xz"}


def is_url(text: str) -> bool:
    """True if the string is a public HTTP(S) URL."""
    scheme = urlparse(text).scheme
    return scheme in ("http", "https")


# Header magic numbers, used to recognise an archive whose extension is absent,
# lost or misleading. Each value is given with the format it comes from, so a
# reviewer can check it against a primary source without leaving this file -- a
# wrong signature produces a wrong corpus.
#
# POSITIVE-ONLY ORACLE. A recognised signature PROVES the file is an archive; an
# absent signature proves NOTHING and simply leaves the decision where it was.
# Never infer "this file is not an archive" from it.
#
# The table does NOT try to cover `libmagic`: the gap is an order of magnitude
# wide, and closing it is not an objective (measured 19 August 2026 in the
# upstream project, crypto-scan, story 05.0). It covers the formats the chain
# already handles, plus Zstandard, which it knows precisely how to REFUSE.
ARCHIVE_SIGNATURES = (
    # ZIP -- APPNOTE.TXT, 4.3: local file header, end of central directory
    # (empty archive), and data descriptor.
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip"),
    (b"PK\x07\x08", "zip"),
    # gzip -- RFC 1952, 2.3.1: ID1 = 0x1f, ID2 = 0x8b.
    (b"\x1f\x8b", "tar_gz"),
    # bzip2 -- "BZh" signature followed by the compression level.
    (b"BZh", "tar_bz2"),
    # xz -- XZ format specification, 2.1.1.1: 0xFD followed by "7zXZ\0".
    (b"\xfd7zXZ\x00", "tar_xz"),
    # LZMA "alone" -- properties byte 0x5d, then dictionary size.
    # Assumed heuristic: this format has no standardised magic number.
    (b"\x5d\x00\x00", "tar_lzma"),
    # 7z -- "7z" followed by 0xBCAF271C.
    (b"7z\xbc\xaf\x27\x1c", "external_7zip"),
    # RAR -- "Rar!\x1a\x07", common to versions 4 and 5.
    (b"Rar!\x1a\x07", "external_7zip"),
    # Zstandard -- RFC 8878, 3.1.1: magic 0xFD2FB528, little-endian.
    # Recognised in order to be REFUSED OUT LOUD, never extracted (see table).
    (b"\x28\xb5\x2f\xfd", "zstd_unsupported"),
)

# When a compression signature does NOT wrap a tar archive, the category
# retained is that of the single compressed file. `tarfile.is_tarfile()`
# decides -- it actually opens the file, so AFTER signature recognition, never
# before.
CATEGORY_IF_NOT_A_TAR = {
    "tar_gz": "plain_gzip",
    "tar_bz2": "plain_bz2",
    "tar_xz": "plain_xz",
    "tar_lzma": "plain_lzma",
}


def categorize_by_content(path: Path):
    """
    Categorise an archive from its first bytes, when the extension said
    nothing. A complement to `categorize_archive()`, never a replacement.

    Reason: a public package contains archives whose extension was lost,
    renamed, or never existed -- vendored modules, test blobs, files truncated
    by a transfer. As long as categorisation was purely extensional, those
    archives crossed `flatten_nested_archives()` without a word and their
    content was never handed to the caller, which then reported on content that
    had never been read (measured in the upstream project, crypto-scan,
    story 05.0).

    Returns `(category, "")` -- the empty string signals that no extension
    matched, which `_name_without_extension()` already knows how to read.
    """
    try:
        with open(path, "rb") as handle:
            header = handle.read(8)
    except OSError:
        # Unreadable, missing, a directory: no conclusion is drawn from it.
        return None, None

    for signature, category in ARCHIVE_SIGNATURES:
        if not header.startswith(signature):
            continue
        # bzip2 ALWAYS follows "BZh" with the compression level (1-9, informal
        # RFC of the format). Without this check, a file whose first three
        # bytes coincide with "BZh" by chance is categorised as an archive --
        # measured in code review on 20 August 2026 in the upstream project, on
        # a `.py` file that had nothing to do with bzip2.
        if signature == b"BZh" and not (b"1" <= header[3:4] <= b"9"):
            continue
        if category in CATEGORY_IF_NOT_A_TAR:
            try:
                if not tarfile.is_tarfile(path):
                    return CATEGORY_IF_NOT_A_TAR[category], ""
            except Exception:
                # Positive-only oracle: a truncated or corrupt stream does not
                # allow tar to be told from a single compressed file, but the
                # signature IS recognised -- so the safest hypothesis (single
                # file) is kept, exactly as the OSError case already did.
                # `tarfile.is_tarfile()` can raise far more than `OSError` on a
                # corrupt stream: the `gzip` module raises a BARE `EOFError`
                # (not an `OSError` subclass) when the stream is cut before the
                # end marker -- reproduced in code review on 20 August 2026 in
                # the upstream project (crypto-scan, story 05.0): a truncated
                # gzip file crashed the whole of `flatten_nested_archives()`,
                # which calls `is_archive()` with no `try/except` at all.
                return CATEGORY_IF_NOT_A_TAR[category], ""
        return category, ""
    return None, None


def categorize_archive(path: Path, *, report=None, root=None, level=None):
    """
    Returns (category, matched_extension), or (None, None) if unrecognised.

    `report`, `root` and `level` are optional and change no decision taken
    here: they let the two facts this function alone observes -- a container set
    aside by policy, and a container recognised by its content -- reach the
    report. `root` is what turns a path into a relative one; `level` is the
    flattening level the caller was at.

    THE IDENTITY OF AN ENTRY IS THE PAIR (code, path). This function is reached
    from four call sites, one of them inside the sorted comprehension of
    `flatten_nested_archives`, re-evaluated at every level: recording the same
    container again changes nothing, which is what the report guarantees and
    what a log cannot.

    Three steps, in this order -- the order IS the contract:
      1. declared exclusion: an office container is set aside WITHOUT a single
         byte being read, and the omission is announced;
      2. extension: cheaper than a read, more explicit on review, and the only
         step able to tell a ".tar.gz" from a ".gz";
      3. content: fallback on magic numbers, as a positive-only oracle.
    """
    # (1) Exclusion policy, BEFORE any read. Without this step, step (3) would
    #     let the packaging parts of office documents into the corpus -- a
    #     regression measured 19 August 2026 in the upstream project
    #     (crypto-scan, story 05.0) on a minimal `.docx`.
    #     Comparison by `endswith`, NOT by `Path.suffix`: `Path.suffix` returns
    #     "" for a file named literally ".docx" (with no stem), which bypassed
    #     the policy -- measured in code review on 20 August 2026. Same style as
    #     step (2), which already tests this way.
    name = path.name.lower()
    if any(name.endswith(ext) for ext in NOT_EXTRACTED_EXTENSIONS):
        logger.info("%s: office container, excluded from extraction -- its "
                    "content is not the material this tool opens.", path.name)
        # Still on disk: an office container is set aside, never opened,
        # so nothing has removed it.
        _record(report, OFFICE_CONTAINER_EXCLUDED, path, root, level,
                digest_of=path)
        return None, None

    # (2) Extension.
    for ext in SORTED_EXTENSIONS:
        if name.endswith(ext):
            return CATEGORY_BY_EXT[ext], ext

    # (3) Content. The message makes the widening of the corpus auditable: a
    #     corpus that grows without a trace is no better than a corpus that
    #     shrinks without a trace.
    category, ext = categorize_by_content(path)
    if category is not None:
        logger.info("%s: archive recognised by its CONTENT (%s) -- extension "
                    "absent or misleading.", path.name, category)
        # Still on disk: recognition reads the first bytes, it extracts
        # nothing.
        _record(report, RECOGNISED_BY_CONTENT, path, root, level,
                digest_of=path)
    return category, ext


def is_archive(path: Path, *, report=None, root=None, level=None) -> bool:
    """
    Tells whether the file is a supported archive, by extension then by
    content.

    The optional reporting arguments are handed straight to
    `categorize_archive`; they change nothing about the answer.

    Returns `True` for a format that is recognised but NOT extractable
    (Zstandard): this is deliberate. Returning `False` would bring back the
    silence this table exists to remove -- the extraction failure itself is
    logged by the caller.
    """
    return categorize_archive(path, report=report, root=root,
                              level=level)[0] is not None


def download_source(url: str, dest_dir: Path) -> Path:
    """Download the public archive pointed at by `url` into `dest_dir`."""
    # `dest_dir` is not guaranteed to exist yet: the CLI's own documented
    # normal case is a destination that is absent, and nothing upstream of
    # this call creates it for the URL path. Without this line the write
    # below raised FileNotFoundError, caught by the broad except and
    # misreported as a network failure -- verified in code review on
    # 8 September 2026.
    # In its own `try`: `mkdir(exist_ok=True)` absorbs FileExistsError only when
    # the path is a DIRECTORY. A destination that exists as a plain file raises,
    # and outside a guard that exception escaped the RuntimeError contract this
    # function's docstring and message present as its only failure mode --
    # verified in code review on 9 September 2026. It must not be folded into
    # the download `try` below either: that one names a network cause, which
    # this is not.
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise RuntimeError(
            f"The download destination '{dest_dir}' could not be prepared "
            f"({exc.__class__.__name__}: {exc}). It exists but is not a usable "
            f"directory, or it cannot be created."
        ) from exc
    # REUSES `resolve_archive_name`, never reimplements it: the two computed
    # the same rule independently until code review on 15 September 2026 --
    # exactly the kind of drift AC-1.4 (story 14.8) warns a name computed in
    # two places will eventually suffer. `resolve_extraction_root`'s own
    # default-mode target depends on this name matching where the file is
    # actually written, for every URL under the default mode.
    file_name = resolve_archive_name(url)
    local_path = dest_dir / file_name
    logger.info("Downloading from: %s", url)
    try:
        with urllib.request.urlopen(url, timeout=120) as response:
            with open(local_path, "wb") as f:
                shutil.copyfileobj(response, f)
    except Exception as exc:
        raise RuntimeError(
            f"Download of '{url}' failed ({exc.__class__.__name__}: {exc}). "
            f"Check network connectivity and, where applicable, the outbound "
            f"access authorisation for this domain."
        ) from exc
    logger.info("Downloaded: %s (%s bytes)", local_path, local_path.stat().st_size)
    return local_path


def _ensure_safe_extraction_path(dest: Path, member: str) -> None:
    """Prevent extraction outside `dest` (path traversal / zip-slip guard)."""
    target = (dest / member).resolve()
    dest_resolved = dest.resolve()
    # NOT a string-prefix comparison: `str(target).startswith(str(dest_resolved))`
    # is fooled by a sibling directory whose name merely extends `dest`'s name
    # (e.g. dest=".../out" and target=".../out_evil/file" -- verified in code
    # review on 8 September 2026). Containment is a PATH relationship, checked
    # on path components.
    if target != dest_resolved and dest_resolved not in target.parents:
        raise ValueError(f"Path traversal attempt detected in the archive: {member}")


def _extract_zip_with_checks(zip_path: Path, dest: Path) -> None:
    with zipfile.ZipFile(zip_path) as z:
        for info in z.infolist():
            _ensure_safe_extraction_path(dest, info.filename)
        z.extractall(dest)


# --- Tar security filter -----------------------------------------------------
#
# A DECLARED DIVERGENCE from the transported original, and the reason it needs a
# function of its own. `TarFile.extractall(filter="data")` refuses absolute
# paths, links pointing outside the destination, and special files -- but as far
# as the caller is concerned it refuses them in silence: the exception names the
# member, nothing names the amputation. A refused tar is a container that was
# NOT opened, which is exactly what the positive-only oracle requires to be
# announced. So the filter is passed as a callable that announces the amputation
# and then re-raises, rather than as the string "data".
#
# It refuses the ARCHIVE, not the member: `data_filter` raises, extraction
# stops, and nothing of that archive is extracted. That is the behaviour the
# determinism contract declares as NOT guaranteed to match earlier versions.
def _declaring_data_filter(member: tarfile.TarInfo, dest_path: str) -> tarfile.TarInfo | None:
    try:
        return tarfile.data_filter(member, dest_path)
    except tarfile.FilterError as exc:
        logger.warning("Tar member refused by the security filter: %s (%s). The "
                       "archive is NOT extracted: no conclusion can be drawn from "
                       "the absence of a finding on its content.", member.name, exc)
        raise


def _extract_tar_with_checks(tar_path: Path, dest: Path, mode: str = "r:*",
                             *, report=None, location=None) -> None:
    with tarfile.open(tar_path, mode) as t:
        for member in t.getmembers():
            _ensure_safe_extraction_path(dest, member.name)
        # Extracted to a STAGING directory first, never straight into `dest`.
        # `extractall` writes members one by one; if `data_filter` refuses a
        # LATER member, earlier ones are already on disk, which contradicts
        # the log above and the comment below ("nothing of that archive is
        # extracted") -- verified in code review on 8 September 2026. Staging
        # makes the claim true FOR A REFUSAL: nothing is written to `dest`
        # until the whole archive has been extracted somewhere else, so a
        # refused archive leaves `dest` exactly as it was. It does NOT make
        # the move itself atomic -- see the `moved_any` branch below, which
        # announces a move that stopped part-way rather than claiming an
        # untouched destination it cannot deliver.
        staging = Path(tempfile.mkdtemp(prefix="unboxr_tar_staging_"))
        moved_any = False
        try:
            t.extractall(staging, filter=_declaring_data_filter)
            dest.mkdir(parents=True, exist_ok=True)
            for item in staging.iterdir():
                moved_any = True
                target = dest / item.name
                if item.is_dir() and target.is_dir() and not target.is_symlink():
                    # `shutil.move` moves a directory INSIDE an existing
                    # directory of the same name, which turns a second
                    # extraction into `x/x/...`. `extractall(dest)` merged in
                    # place, and this reproduces that -- verified in code
                    # review on 9 September 2026.
                    shutil.copytree(item, target, dirs_exist_ok=True,
                                    symlinks=True)
                    shutil.rmtree(item)
                else:
                    if target.is_dir() and not target.is_symlink():
                        # A directory sitting at this path is about to be
                        # discarded to make room for a node of a different
                        # shape from this extraction -- not merged. Silent
                        # for an EMPTY directory: nothing is lost. Announced
                        # when it holds content, the same discipline as every
                        # other collision this module already declares rather
                        # than hides.
                        #
                        # Reachable, among other routes, when an EARLIER
                        # flattening pass over a reused workspace renamed a
                        # nested archive to a directory at this exact path,
                        # and this extraction's own raw member -- not yet
                        # opened -- now lands on that same name. Measured in
                        # code review, story 14.2 of the upstream project,
                        # crypto-scan.
                        try:
                            target_held_content = any(target.iterdir())
                        except OSError:
                            target_held_content = False
                        if target_held_content:
                            logger.warning(
                                "%s: %s already held content as a directory "
                                "of a different origin; it is discarded, not "
                                "merged, to make room for this extraction.",
                                tar_path, target)
                            # THE RECORDED PATH IS THE TAR ARCHIVE, not the
                            # directory being discarded -- `location` is the
                            # tar's own reportable path. So there IS a file to
                            # hash, and it is `tar_path`, which the extraction
                            # above has not removed. Measured 13 September
                            # 2026: the story that asked for this read the
                            # recorded path as the directory.
                            _record(report,
                                    DIRECTORY_OF_A_DIFFERENT_ORIGIN_DISCARDED,
                                    location or tar_path,
                                    digest_of=tar_path)
                        shutil.rmtree(target)
                    elif target.exists() or target.is_symlink():
                        target.unlink()
                    shutil.move(str(item), str(target))
        except Exception as exc:
            # Two failures, told apart by `moved_any`. Before the first move
            # nothing has left the staging directory and `dest` really is
            # exactly as it was -- that is what staging buys, and the claim
            # above stays true. Once a move has happened, rolling back is not
            # possible: what was in `dest` before is indistinguishable from
            # what has just been moved in. So the partial state is ANNOUNCED
            # rather than left silent, and the exception still propagates.
            # The exception is TAGGED with the cause just recorded, and
            # re-raised as the SAME object -- not wrapped. The caller (in
            # `flatten_nested_archives` and `prepare_source`) reads the code
            # off the exception with `getattr(exc, "code", EXTRACTION_FAILED)`
            # and records it again for the same (container, code) pair, which
            # the report's own (code, path) deduplication then collapses into
            # the one entry already filed here. Left untagged, that fallback
            # always lands on the generic `EXTRACTION_FAILED` instead -- a
            # SECOND, contradictory entry for one container, counted twice by
            # `amputation_count()`. Verified in code review, story 14.3.
            if moved_any:
                logger.warning("%s: the extracted content could not be moved "
                               "into %s in full. That directory now holds an "
                               "INCOMPLETE extraction: no conclusion can be "
                               "drawn from the absence of a finding on its "
                               "content.", tar_path, dest)
                # FILED TWICE -- here and again in the caller, off the
                # tagged exception. The first filing wins, so the digest has to
                # be taken here or it is dropped in silence.
                _record(report, TAR_CONTENT_PARTLY_MOVED,
                        location or tar_path, detail=str(exc),
                        digest_of=tar_path)
                exc.code = TAR_CONTENT_PARTLY_MOVED
            elif isinstance(exc, tarfile.FilterError):
                # The filter refuses the ARCHIVE, not the member: nothing of it
                # reaches `dest`. Recorded HERE rather than in the filter
                # itself, which runs once per member and would file the same
                # container as many times as the archive has entries -- the
                # report deduplicates, but the cause belongs where the archive
                # is known, not where a member is.
                # Filed twice, like the branch above: the digest belongs to
                # the first filing.
                _record(report, TAR_REFUSED_BY_SECURITY_FILTER,
                        location or tar_path, detail=str(exc),
                        digest_of=tar_path)
                exc.code = TAR_REFUSED_BY_SECURITY_FILTER
            raise
        finally:
            # Discarded on every path, success included: on success it is empty,
            # on failure it holds what must not reach `dest`.
            shutil.rmtree(staging, ignore_errors=True)


def _name_without_extension(path: Path, matched_ext: str) -> str:
    name = path.name
    if matched_ext and name.lower().endswith(matched_ext):
        return name[: -len(matched_ext)]
    return path.stem


# Length of the digest kept for the provisional name. Sixteen hexadecimal
# characters = 64 bits: the probability of a collision between two archives of
# the same package is negligible next to that of a real archive name literally
# carrying the shape produced here (a residual limit, recorded upstream).
PROVISIONAL_DIGEST_LENGTH = 16


def _provisional_name_from_relative_path(relative_posix: str) -> str:
    """The one place the digest scheme of a provisional name is written.

    Shared by `_provisional_extraction_name` (nested archives, and the URL
    and `--replace` cases at level 0, all of which reduce to a path relative
    to SOME root -- see `_provisional_name_at_level_zero`) so the two never
    drift into two different shapes for what is, in both cases, "the same
    archive, held under a name nobody else can already be holding".
    """
    digest = hashlib.sha256(relative_posix.encode("utf-8")).hexdigest()[:PROVISIONAL_DIGEST_LENGTH]
    return f"archive_{digest}"


def _provisional_extraction_name(archive: Path, root: Path, *, report=None,
                                 level=None) -> str:
    """
    The name an extraction is held under while the archive it comes from still
    occupies its final path: extract here, remove the archive, then rename.

    A nested archive's final directory is its own name, verbatim, and no file
    system tolerates a file and a directory of the same name in one parent --
    hence the detour, taken for EVERY archive and not as a fallback.

    A digest of the POSIX relative path, not a counter or a temporary
    directory, because this name can stop being provisional (see the
    non-guarantees below) and must then still be deterministic. A positional
    counter was tried and withdrawn for three measured defects -- see story
    3.1 of the upstream project, crypto-scan.

    The produced name is a valid path component on Windows and on Linux alike:
    digits, letters `a-f` and `_` only, none of `< > : " / \\ | ? *`.
    """
    try:
        relative = archive.relative_to(root).as_posix()
    except ValueError:
        # `rglob` always yields paths under `root`; this branch covers the case
        # of a caller passing an unrelated root, rather than failing a whole run
        # over a directory name. The absolute path depends on the machine -- a
        # declared stopgap, not the nominal case. It is the only naming caveat
        # this module announces, and it is rare: the name itself is now produced
        # for every archive, this warning only for one outside the root.
        logger.warning("Archive outside the analysed root, provisional name derived "
                       "from the absolute path: %s. The produced name depends on "
                       "the machine.", archive)
        # Declared, not just logged: `ARCHIVE_OUTSIDE_THE_ANALYSED_ROOT` names
        # exactly this branch and was, until code review on 12 September 2026,
        # never actually reached -- the code was declared in `report.py` and
        # never recorded anywhere. `root=None`: `_reportable_path` cannot make
        # this path relative to a root it just fell outside of.
        # `root=None` above: the path is a BARE NAME, and the frame now
        # says so. The file itself is there -- this branch only names it.
        _record(report, ARCHIVE_OUTSIDE_THE_ANALYSED_ROOT, archive, None, level,
                digest_of=archive)
        relative = archive.as_posix()
    return _provisional_name_from_relative_path(relative)


def _provisional_name_at_level_zero(archive: Path) -> str:
    """
    The provisional name for the FIRST-level archive: the one the caller
    handed in, or the one `download_source` just wrote for a URL.

    No `root` for this archive exists yet -- the tree it will seed has not
    been created -- so `_provisional_extraction_name`'s notion of "the path
    relative to the analysed root" has no object here. Reusing it as is would
    fire its `ARCHIVE_OUTSIDE_THE_ANALYSED_ROOT` branch, and its warning with
    it, on EVERY nominal run: a local archive is essentially never a child of
    the workspace it is about to populate. That would be exactly the noise
    story 14.8 measured and refused to reintroduce.

    The relative path that DOES have a meaning at level 0 is the archive's
    own name, taken relative to its own immediate parent -- the one directory
    it is unambiguously "under", whether that parent is the workspace a URL
    was downloaded into or an arbitrary directory the caller pointed at on
    their own file system. `archive.relative_to(archive.parent)` never raises,
    so this never warns and never falls back to an absolute, machine-dependent
    path -- both properties `_provisional_extraction_name` only manages to
    keep for the nested case.
    """
    return _provisional_name_from_relative_path(archive.name)


# THE ONLY NAME `unboxr` FABRICATES, and the shape it is required to keep.
#
# The four extractors below name their output `_name_without_extension(...)`,
# which is the natural name in every real case: `notes.txt.gz` yields
# `notes.txt`. The `_decompressed` suffix only ever plays for an archive whose
# name is entirely consumed by the matched extension -- one named literally
# `.gz`, `.pack.gz`, `.lzma`, `.xz`, `.bz2` or `.bz` -- where no natural name
# exists to take its place.
#
# The name produced must match no extension of CATEGORY_BY_EXT. That property
# was accidental; it is a requirement from now on, and it is tested. A file
# named `.gz` IS recognised as an archive, so a "cleaner" name that fell back on
# a known extension would have the payload re-detected as an archive at the next
# level, fail to extract, and be reported as an amputation that never happened
# -- measured 12 September 2026, and the reason the suffix stays.
def extract_plain_gzip(path: Path, dest: Path, matched_ext: str) -> None:
    """Decompress a plain gzip file (not a tar archive): one single output file."""
    dest.mkdir(parents=True, exist_ok=True)
    output_name = _name_without_extension(path, matched_ext) or f"{path.stem}_decompressed"
    with gzip.open(path, "rb") as f_in, open(dest / output_name, "wb") as f_out:
        shutil.copyfileobj(f_in, f_out)


def extract_plain_lzma(path: Path, dest: Path, matched_ext: str) -> None:
    """Decompress a plain .lzma file (not a tar archive): one single output file."""
    dest.mkdir(parents=True, exist_ok=True)
    output_name = _name_without_extension(path, matched_ext) or f"{path.stem}_decompressed"
    with lzma.open(path, "rb") as f_in, open(dest / output_name, "wb") as f_out:
        shutil.copyfileobj(f_in, f_out)


def extract_plain_xz(path: Path, dest: Path, matched_ext: str) -> None:
    """Decompress a plain .xz file (not a tar archive): one single output file."""
    dest.mkdir(parents=True, exist_ok=True)
    output_name = _name_without_extension(path, matched_ext) or f"{path.stem}_decompressed"
    with lzma.open(path, "rb") as f_in, open(dest / output_name, "wb") as f_out:
        shutil.copyfileobj(f_in, f_out)


def extract_plain_bz2(path: Path, dest: Path, matched_ext: str) -> None:
    """Decompress a plain .bz2 file (not a tar archive): one single output file."""
    dest.mkdir(parents=True, exist_ok=True)
    output_name = _name_without_extension(path, matched_ext) or f"{path.stem}_decompressed"
    with bz2.open(path, "rb") as f_in, open(dest / output_name, "wb") as f_out:
        shutil.copyfileobj(f_in, f_out)


def extract_tar_lzma(path: Path, dest: Path, *, report=None,
                     location=None) -> None:
    """tar+lzma: decompress to a temporary .tar, then extract normally."""
    dest.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(suffix=".tar")
    os.close(fd)
    tmp_tar_path = Path(tmp_path)
    try:
        with lzma.open(path, "rb") as f_in, open(tmp_tar_path, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
        _extract_tar_with_checks(tmp_tar_path, dest, mode="r:", report=report,
                                 location=location or path.name)
    finally:
        tmp_tar_path.unlink(missing_ok=True)


def find_7zip_binary() -> str | None:
    """
    Look for a 7-Zip binary available on the system:
      1. On the PATH:
           - Windows: 7z.exe, 7za.exe, 7z
           - Unix   : 7zz (next-generation p7zip), 7z, 7za, 7zr
      2. On Windows, if absent from the PATH: default 7-Zip installation
         locations (Windows 11), including installation through winget (App
         Installer puts its links in WindowsApps, but the official 7-zip.org
         installer uses Program Files by default).
    Returns the path found, or None if 7-Zip cannot be found.
    """
    if platform.system() == "Windows":
        path_candidates = ["7z.exe", "7za.exe", "7z"]
    else:
        path_candidates = ["7zz", "7z", "7za", "7zr"]

    for candidate in path_candidates:
        path = shutil.which(candidate)
        if path:
            return path

    if platform.system() == "Windows":
        # Default installation directories on Windows 11, including the 32/64
        # bit variants and alternative roots (a drive other than C:, the
        # ProgramW6432 variable for a 32-bit process on a 64-bit OS).
        candidate_roots = [
            os.environ.get("ProgramFiles"),            # e.g. C:\Program Files
            os.environ.get("ProgramW6432"),            # guaranteed 64-bit view
            os.environ.get("ProgramFiles(x86)"),       # e.g. C:\Program Files (x86)
            r"C:\Program Files",
            r"C:\Program Files (x86)",
        ]
        for root in candidate_roots:
            if not root:
                continue
            for exe_name in ("7z.exe", "7za.exe"):
                candidate_path = Path(root) / "7-Zip" / exe_name
                if candidate_path.is_file():
                    return str(candidate_path)

    return None


def extract_with_7zip(archive_path: Path, dest: Path, binary: str) -> None:
    """Delegate extraction to an external 7-Zip binary (formats the stdlib will not do)."""
    dest.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [binary, "x", "-y", f"-o{dest}", str(archive_path)],
        capture_output=True, text=True, timeout=600,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Extraction through {binary} failed: {result.stderr.strip()[:400] or result.stdout.strip()[:400]}"
        )


def extract_tar_7z(path: Path, dest: Path, *, report=None,
                   location=None) -> None:
    """tar wrapped in a 7z envelope: lift the envelope with 7-Zip, then read the .tar."""
    binary = find_7zip_binary()
    if not binary:
        raise UnsupportedFormatError(
            SEVEN_ZIP_BINARY_MISSING,
            "The .tar.7z format needs a 7-Zip binary (7z/7zz/7za), not found on the PATH. "
            "Install p7zip (Unix) or 7-Zip (Windows). The content is NOT extracted: no "
            "conclusion can be drawn from the absence of a finding on this archive."
        )
    dest.mkdir(parents=True, exist_ok=True)
    tmp_dir = Path(tempfile.mkdtemp(prefix="tar7z_"))
    try:
        extract_with_7zip(path, tmp_dir, binary)
        # Sort on the POSIX relative path, the same idiom as guarantee 1 of the
        # determinism contract: without it, the `.tar` retained -- and therefore
        # THE WHOLE EXTRACTED CORPUS -- depended on the file system enumeration
        # order (measured in code review on 2 September 2026 in the upstream
        # project, crypto-scan).
        found_tars = sorted(tmp_dir.rglob("*.tar"),
                            key=lambda c: c.relative_to(tmp_dir).as_posix())
        if not found_tars:
            raise RuntimeError("No .tar file found after decompressing the .7z envelope")
        if len(found_tars) > 1:
            # A silent choice between several corpora is a mute fallback: every
            # fallback announces itself, with its cause. ABSENCE NOT ESTABLISHED
            # for the archives left out.
            others = ", ".join(t.relative_to(tmp_dir).as_posix() for t in found_tars[1:])
            logger.warning("The .7z envelope contains %s .tar files. Only the first in "
                           "sorted order is extracted: %s. NOT EXTRACTED: %s. No "
                           "conclusion can be drawn from the absence of a finding on "
                           "those archives.", len(found_tars),
                           found_tars[0].relative_to(tmp_dir).as_posix(), others)
            # The recorded path names the .7z ENVELOPE, which is `path` and
            # is still on disk; the tars left out are inside it.
            _record(report, SEVERAL_TARS_ONLY_FIRST_EXTRACTED,
                    location or path.name, detail=others,
                    digest_of=path)
        _extract_tar_with_checks(found_tars[0], dest, mode="r:", report=report,
                                 location=location or path.name)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def extract_archive(archive_path: Path, dest: Path, *, report=None,
                    location=None) -> None:
    """
    Extract an archive into `dest`, whatever its format among those recognised
    by CATEGORY_BY_EXT, with path-traversal protection for the zip/tar formats
    handled natively.

    `location` is the path a record should carry for this archive -- the caller
    knows the root it was found under, this function does not.

    THE `categorize_archive` CALL BELOW DELIBERATELY GETS NO REPORT. Reaching
    this function means the caller already categorised the archive, with the
    report and with the relative path; handing it over a second time would file
    the same container again under the bare file NAME, which is a different
    string and therefore a second entry for one container.
    """
    dest.mkdir(parents=True, exist_ok=True)
    category, ext = categorize_archive(archive_path)

    if category == "zip":
        _extract_zip_with_checks(archive_path, dest)
    elif category in NATIVE_TAR_MODES:
        _extract_tar_with_checks(archive_path, dest,
                                 mode=NATIVE_TAR_MODES[category],
                                 report=report, location=location)
    elif category == "tar_lzma":
        extract_tar_lzma(archive_path, dest, report=report, location=location)
    elif category == "tar_7z":
        extract_tar_7z(archive_path, dest, report=report, location=location)
    elif category == "plain_gzip":
        extract_plain_gzip(archive_path, dest, ext)
    elif category == "plain_lzma":
        extract_plain_lzma(archive_path, dest, ext)
    elif category == "plain_xz":
        extract_plain_xz(archive_path, dest, ext)
    elif category == "plain_bz2":
        extract_plain_bz2(archive_path, dest, ext)
    elif category == "zstd_unsupported":
        # Recognised, and refused OUT LOUD. The message carries its cause
        # because how an absent finding reads downstream depends on it: a corpus
        # amputated without a trace reads as an empty one. See the positive-only
        # oracle at the top of this module. This is NFR-13 of the upstream
        # project (crypto-scan): a silent heuristic fallback is the anti-pattern
        # this branch exists to avoid.
        raise UnsupportedFormatError(
            ZSTD_NOT_SUPPORTED,
            f"Zstandard archive recognised but not extractable: '{archive_path.name}'. "
            f"The standard library only provides `compression.zstd` from "
            f"Python 3.14 onwards (PEP 784) -- this interpreter is "
            f"{sys.version_info.major}.{sys.version_info.minor} -- and the official 7-Zip "
            f"does not handle the format either. The content is NOT extracted: no "
            f"conclusion can be drawn from the absence of a finding on this archive."
        )
    elif category == "external_7zip":
        binary = find_7zip_binary()
        if not binary:
            raise UnsupportedFormatError(
                SEVEN_ZIP_BINARY_MISSING,
                f"Format '{ext}' needs a 7-Zip binary (7z/7zz/7za), not found on the "
                f"PATH. Install p7zip (Unix: package p7zip-full, binary 7zz/7z) or "
                f"7-Zip (Windows: 7z.exe, https://www.7-zip.org/). The content is NOT "
                f"extracted: no conclusion can be drawn from the absence of a finding "
                f"on this archive."
            )
        extract_with_7zip(archive_path, dest, binary)
    else:
        # Last-resort fallback: historical zip/tar auto-detection when no
        # extension matched.
        if zipfile.is_zipfile(archive_path):
            _extract_zip_with_checks(archive_path, dest)
        elif tarfile.is_tarfile(archive_path):
            _extract_tar_with_checks(archive_path, dest, report=report,
                                     location=location)
        else:
            raise ValueError(f"Archive format unrecognised or unsupported: {archive_path}")


def flatten_nested_archives(root: Path, max_depth: int = 10,
                            report=None) -> None:
    """
    Recursive flattening: many public packages (repositories, releases,
    tarballs, .rpm/.deb system packages, .iso images...) themselves contain
    sub-archives (vendored modules, sub-packages, a .tar.gz nested in a .zip, a
    .gz wrapping a .tar, and so on). This function finds and extracts those
    nested archives, level by level, until there are none left or the maximum
    depth is reached.

    `report`, when given, is filled AS THE EXTRACTION HAPPENS and never by
    walking the finished tree: an archive is REMOVED once it is opened, so a
    container that was opened no longer exists as a file to be walked. The
    archives still present when flattening stops are, by definition, still
    there -- reading them at that instant is still "during the extraction".
    """
    # Archives already attempted and left in place: a failed extraction never
    # removes its source, so an unguarded re-scan re-discovers and re-attempts
    # the SAME archive at every subsequent level -- inflating the amputation
    # count and misattributing the final warning below to nesting depth rather
    # than to one persistently failing archive. Verified in code review on
    # 8 September 2026.
    #
    # TWO sets, and they are not the same question. `attempted_archives` says
    # "do not offer this one again", and an archive that was extracted but
    # could not be REMOVED belongs to it -- it is still on disk and would be
    # re-discovered for ever. `amputated_archives` says "this content is NOT in
    # the extracted tree", which is false of that same archive. Merging the two
    # would make the closing recap assert an amputation that did not happen.
    # Verified in code review on 9 September 2026.
    attempted_archives: set[Path] = set()
    amputated_archives: set[Path] = set()

    _note_depth(report, limit=max_depth, reached=0)

    for level in range(1, max_depth + 1):
        # Sort on the POSIX relative path: independent of the file system and of
        # the machine. This is guarantee 1 of the determinism contract.
        found_archives = sorted(
            (p for p in root.rglob("*")
             if p.is_file() and p not in attempted_archives
             and is_archive(p, report=report, root=root, level=level)),
            key=lambda c: c.relative_to(root).as_posix(),
        )
        if not found_archives:
            if amputated_archives:
                # The run ends on a success message, but the corpus is short of
                # every archive in the ledger. Each was announced when it
                # failed; without this recap the LAST word of the run is an
                # unqualified "finished", which reads as completeness -- the
                # exact opposite of the positive-only oracle. Verified in code
                # review on 9 September 2026.
                logger.warning("Flattening finished, but %s archive(s) were "
                               "left unopened: %s. Their content is NOT in the "
                               "extracted tree.", len(amputated_archives),
                               ", ".join(sorted(str(p) for p in amputated_archives)))
            logger.info("Flattening finished after %s level(s).", level - 1)
            _note_depth(report, reached=level - 1)
            return

        logger.info("Level %s: %s nested archive(s) found.", level, len(found_archives))
        _note_depth(report, reached=level)
        for archive in found_archives:
            _, matched_ext = categorize_archive(archive)
            # FOUR STEPS, IN THIS ORDER, and the order is forced by the file
            # system. The final directory of a nested archive is the archive's
            # OWN NAME, verbatim -- `toto.jar` gives `toto.jar/`, `toto.zip`
            # gives `toto.zip/`, so two archives that used to strip to the same
            # base name can no longer merge. But that name is occupied by the
            # archive itself until it is removed, and no file system tolerates a
            # file and a directory of the same name in one parent. Hence:
            # extract under a provisional name, remove the archive, rename.
            provisional_dest = archive.parent / _provisional_extraction_name(
                archive, root, report=report, level=level)
            final_dest = archive.parent / archive.name
            # THE COLLISION GUARD, ON THE PROVISIONAL NAME. It cannot bear on
            # `final_dest`: that path is the archive's own, so nothing can hold
            # it while the archive is there. The provisional name, on the other
            # hand, is DETERMINISTIC -- that is what it is for -- and
            # `attempted_archives` is local to this call. So a workspace where
            # an earlier run left a provisional directory behind, because ITS
            # rename failed, hands the same directory to this one, already
            # populated, and the two contents mix with no trace.
            #
            # That is the narrow route to THIS guard, measured 12 September
            # 2026. A run whose rename SUCCEEDED leaves the final directory
            # holding the member's own name, so re-unpacking the same outer
            # archive over that workspace no longer reaches here.
            #
            # It does not follow that a reused workspace then fails loudly at
            # the first level in every case: that is only true when the OUTER
            # container is zip-shaped, where `zipfile` cannot write a file
            # where a directory already sits. A tar- or 7z-shaped outer
            # container does not fail at all -- its own merge logic
            # (`_extract_tar_with_checks`, below) discards the stale directory
            # and writes the raw member in its place. That merge used to be
            # silent for this exact shape of collision; it is not any more --
            # see the warning there -- but it remains a REPLACEMENT, not a
            # failure. Measured in code review, story 14.2 of the upstream
            # project, crypto-scan.
            #
            # `is_dir()` first, and the read guarded: the path may exist and NOT
            # be a directory, in which case `iterdir()` raises -- and this check
            # sits before the `try` below, so the exception would abort the
            # WHOLE flattening and leave every remaining archive unopened
            # without a single record. The collision CHECK must never be what
            # amputates the corpus. Verified in code review on 9 September 2026.
            occupied = False
            if provisional_dest.is_dir():
                try:
                    occupied = any(provisional_dest.iterdir())
                except OSError:
                    # Unreadable destination: the extraction below will fail on
                    # it and be announced there, with its cause.
                    occupied = False
            if occupied:
                # The message states what is OBSERVED and names the one cause
                # that can produce it, which is no longer "another archive":
                # the provisional name is derived from this archive's own path,
                # so only an earlier run over the same workspace can have
                # written there.
                logger.warning("%s: its provisional extraction directory %s "
                               "already holds content, left by an earlier run "
                               "over this workspace; the two are mixed there, "
                               "with no further warning.", archive, provisional_dest)
                # Before extraction: the archive is still a file.
                _record(report, PROVISIONAL_DIRECTORY_ALREADY_OCCUPIED,
                        archive, root, level, digest_of=archive)
            try:
                extract_archive(archive, provisional_dest, report=report,
                                location=_reportable_path(archive, root))
            except Exception as exc:
                logger.warning("Extraction of %s (%s) failed: %s (archive kept as is). "
                               "Its content is NOT in the extracted tree.",
                               archive, matched_ext, exc)
                # The CODE is read off the exception, with an EXPLICIT fallback
                # on the generic failure for anything that does not carry one:
                # a corrupt archive stays a FAILURE. Guessing a refusal there
                # would have the report say this tool does not open zip files.
                # A failed extraction never removes its source: the archive
                # is still there, and hashing it is what lets a reader tell one
                # unreadable container from another.
                _record(report, getattr(exc, "code", EXTRACTION_FAILED),
                        archive, root, level, detail=str(exc),
                        digest_of=archive)
                attempted_archives.add(archive)
                amputated_archives.add(archive)
                continue
            # THE WINDOW. This runs AFTER a successful extraction and
            # BEFORE `archive.unlink()` below: the container still exists, and
            # this is the only instant in the whole run at which it does. A
            # walk of the finished tree cannot produce this digest, because by
            # then the file is gone.
            _record(report, NESTED_CONTAINER_OPENED, archive, root, level,
                    digest_of=archive)
            try:
                archive.unlink()  # drop the archive once flattened in place
            except FileNotFoundError:
                # The archive is already gone -- not a removal failure. It
                # was found by `rglob` and extracted just above, so this can
                # only be external interference (another process, an
                # antivirus quarantine). Nothing here blocks the rename
                # below: reporting "the archive is kept" would be false, and
                # skipping the rename would strand perfectly good content
                # under its provisional name for no reason. Measured in code
                # review, story 14.2 of the upstream project, crypto-scan.
                pass
            except OSError as exc:
                # Extraction above already succeeded: reporting this as an
                # extraction failure would be false -- the content IS in the
                # extracted tree, only its source archive could not be
                # removed (e.g. a lock held by another process). Verified in
                # code review on 8 September 2026.
                #
                # It joins the ledger all the same. The archive is still on
                # disk, so an unguarded re-scan re-discovers and re-extracts it
                # at EVERY subsequent level -- the very defect the ledger was
                # added to close, re-opened by this branch. Verified in code
                # review on 9 September 2026.
                #
                # The message names the PROVISIONAL directory, because that is
                # where the content actually is: the rename below is skipped --
                # its target is still the archive.
                logger.warning("%s was extracted successfully but could not be "
                               "removed (%s): the archive is kept, and its "
                               "content stays under the provisional name %s. "
                               "Its content IS in the extracted tree.",
                               archive, exc, provisional_dest)
                # The archive could NOT be removed: it is still on disk,
                # which is the whole point of this branch.
                _record(report, ARCHIVE_KEPT_AFTER_SUCCESSFUL_EXTRACTION,
                        archive, root, level, detail=str(exc),
                        digest_of=archive)
                attempted_archives.add(archive)
                continue
            try:
                # `final_dest.exists()` is checked FIRST, rather than letting
                # `Path.rename()` decide on its own: on POSIX, renaming onto
                # an EMPTY existing directory succeeds silently, replacing it
                # with no exception raised -- while the identical precondition
                # raises `FileExistsError` on Windows, caught below. Checking
                # first makes an already-occupied `final_dest` behave the
                # same, declared, way on both platforms, rather than being
                # silent on one of them. Measured in code review, story 14.2
                # of the upstream project, crypto-scan.
                if final_dest.exists():
                    raise OSError(f"a directory or file already exists at {final_dest}")
                provisional_dest.rename(final_dest)
            except OSError as exc:
                # NOT an amputation: the content is on disk and complete, only
                # under a name the consumer did not ask for. Announced all the
                # same -- the same discipline as the partial move of the tar
                # staging area, and the reason the provisional name has to be
                # deterministic: here it stops being provisional.
                logger.warning("%s: the extracted content could not be renamed "
                               "to %s (%s): it stays under its provisional name "
                               "%s. Its content IS in the extracted tree, under "
                               "that name.", archive, final_dest, exc,
                               provisional_dest)
                # NO DIGEST, and not for want of trying: `archive.unlink()`
                # above SUCCEEDED -- that is how control reaches the rename --
                # so the file is gone. `None` says "not computed here", which
                # is the truth.
                _record(report, EXTRACTION_KEPT_UNDER_PROVISIONAL_NAME,
                        archive, root, level, detail=str(exc))

    logger.warning("Maximum depth (%s) reached: flattening stops, archives may "
                   "remain unopened. Their content is NOT in the extracted tree.",
                   max_depth)
    # THE NET GAIN OVER THAT MESSAGE, which says archives "may" remain
    # unopened, with neither list nor count. Those archives are on disk at this
    # instant -- that is what being still unopened means -- so naming them here
    # is still recording DURING the extraction, not walking a finished tree.
    # Archives already in the ledger are left out: each is recorded as the
    # failure it was, at the moment it failed.
    _record_residual_archives(report, root, attempted_archives)


def _record_residual_archives(report, root: Path, attempted: set) -> None:
    """Name every container still unopened when flattening stopped.

    ONE `rglob` over the whole tree, re-running `categorize_archive` (via
    `is_archive`) on files the main loop's own per-level scans already looked
    at -- a second pass the (code, path) deduplication in `ExtractionReport`
    makes safe, since every `OFFICE_CONTAINER_EXCLUDED`/`RECOGNISED_BY_CONTENT`
    it re-files was already filed once. Kept rather than threading a carried-
    over visited-set through the flattening loop: this function only runs
    once, when the depth bound is actually reached, and it is the one place
    that still needs to see files the main loop never got to (residual, more
    nested than the bound allows) -- which a purely incremental set could not
    tell apart from files already seen. Measured in code review, story 14.3.
    """
    if report is None:
        return
    try:
        residual = sorted(
            (p for p in root.rglob("*")
             if p.is_file() and p not in attempted
             and is_archive(p, report=report, root=root, level=None)),
            key=lambda c: _reportable_path(c, root),
        )
        for archive in residual:
            # `level=None`, not the depth BOUND that was reached: this single
            # closing pass has no per-level information left to give -- it is
            # exactly the case `ContainerRecord.level`'s own docstring
            # declares ("`None` where the chain has no level to give"), and
            # reporting the bound in its place read as the archive's own
            # nesting depth, which it is not. Verified in code review, story
            # 14.3: was `max_depth` unconditionally, on every residual entry.
            # Residual archives are on disk at this instant -- that is what
            # being still unopened means -- so reading them here is still
            # recording DURING the extraction.
            _record(report, MAXIMUM_DEPTH_REACHED, archive, root, None,
                    digest_of=archive)
    except Exception:       # a note that could not be taken, never a failure
        pass


# Nature of the analysed unit. A table SEPARATE from CATEGORY_BY_EXT, which
# answers a different question (which extraction function to call) and stays
# unchanged. Three states, never two: "source", "built", "undetermined". An
# extension absent from this table, or one whose convention is NOT
# distinguishable from the extension alone (no sourced primary reference to
# date), yields "undetermined" -- never guess.
#
# Scope settled over the EIGHT ecosystems a consumer commonly parses (npm,
# cargo, composer, maven, nuget, gem, golang, pypi): for SIX of them the actual
# convention does NOT distinguish source from built by the file extension alone
#   - npm      : a SINGLE shape (`.tgz` via `npm pack`/`npm publish`) -- no
#     source/built distinction in the ecosystem itself;
#   - cargo    : `.crate` is not even an extension recognised by CATEGORY_BY_EXT
#     (no extraction) -- out of scope;
#   - composer : Packagist only references a `dist` archive (generic zip/tar),
#     with no naming convention of its own;
#   - nuget/gem: see below (an ambiguity SPECIFIC to each, unsourceable from the
#     extension alone);
#   - golang   : the module proxy serves source code in a generic `.zip`,
#     indistinguishable from other uses of `.zip` by the extension alone.
# The TWO remaining ecosystems (maven, pypi) each provide a reliable
# EXTENSION-ONLY signal, sourced below.
NATURE_BY_EXTENSION = {
    # PyPA: the wheel is THE "built distribution" format of the Python
    # ecosystem, by definition of the specification -- no ambiguity possible.
    # Source: https://packaging.python.org/en/latest/glossary/ (read on
    # 31 August 2026).
    ".whl": "built",

    # setuptools (legacy, predecessor of the wheel): "the preferred binary
    # distribution format" for EasyInstall -- the same status as the wheel,
    # older. Source:
    # https://setuptools.pypa.io/en/latest/deprecated/python_eggs.html
    # (read on 31 August 2026).
    ".egg": "built",

    # Java/Maven: a .jar is the DEFAULT build artefact (compiled classes). The
    # SPECIAL CASE of the Maven source jar -- suffix "-sources.jar", the
    # OFFICIAL convention of the maven-source-plugin "sources" classifier -- is
    # handled SEPARATELY by `_is_maven_source_jar()` below, on the FILE NAME,
    # not on the extension alone (the pattern cannot live in this table).
    # Source: https://maven.apache.org/plugins/maven-source-plugin/jar-mojo.html
    # (read on 31 August 2026).
    ".jar": "built",

    # NuGet: "A NuGet package is a single ZIP file ... that contains compiled
    # code (DLLs)". A .nupkg ALWAYS wraps compiled binaries, never raw source.
    # Source: https://learn.microsoft.com/en-us/nuget/what-is-nuget
    # (read on 31 August 2026).
    ".nupkg": "built",
}


def _is_maven_source_jar(file_name: str) -> bool:
    """
    OFFICIAL convention of the maven-source-plugin "sources" classifier:
    `{artifactId}-{version}-sources.jar`. See NATURE_BY_EXTENSION above.
    """
    return file_name.lower().endswith("-sources.jar")


def resolve_distribution_nature(file_name: str, matched_extension: str | None) -> str:
    """
    Resolve the SOURCE / BUILT / UNDETERMINED nature of an archive from its file
    name and from the extension ALREADY MATCHED by `categorize_archive` --
    computed once, reused here. Reads no data file of any kind: this is a code
    policy, not a catalogue.
    """
    if matched_extension == ".jar" and _is_maven_source_jar(file_name):
        return "source"
    return NATURE_BY_EXTENSION.get(matched_extension, "undetermined")


# --- SHA-256 digest of the received input ------------------------------------
#
# 1 MiB, a block size TAKEN OVER from a packaging helper of the upstream project
# whose comment carries the measurement that justifies it. It is NOT re-justified
# here: no fresh measurement was made for this move, and inventing a motive would
# pass a reuse off as a decision.
_HASHING_BLOCK_SIZE = 1 << 20


def _sha256_digest_of_file(path: Path) -> str:
    """
    BARE hexadecimal SHA-256 of a file, read BY BLOCKS.

    Returns 64 hexadecimal characters with NO prefix: the `sha256:` is added by
    the caller, at the moment it builds whatever it builds, never here.

    READ BY BLOCKS, NOT AN ENTIRE `f.read()`. The discipline applies to any
    potentially large file: a `read()` with no argument would return the SAME
    digest, so no test on the value can tell the two apart -- what holds this is
    a boundary guard over the source of this function.

    A READ FAILURE PROPAGATES, IT DOES NOT DEGRADE. At the only call site
    (`prepare_source`), `categorize_archive` has just confirmed an existing
    archive file: a failure here is a real ANOMALY -- permissions, disk,
    antivirus -- not an expected case. It stops the run with the native
    exception, exactly as a missing source does. Converting it into a "digest
    not computable" would conflate two opposite things: "not computable BY
    NATURE" (a directory -- a normal case, and one that returns `None`) and
    "unexpected read failure".
    """
    # Named `digest_bytes`, NOT `digest`: `_provisional_extraction_name` already
    # uses that name for a hash of a PATH, unrelated to a hash of CONTENT --
    # reusing the identifier would recreate exactly the confusion this module
    # warns about (noted in code review on 7 September 2026 in the upstream
    # project).
    #
    # Do not confuse this digest with a downstream tool's digest of what IT
    # produces from the extracted tree: this one condenses the RECEIVED INPUT,
    # before extraction; a consumer's own digest of its own output is a
    # different object, at a different point in the pipeline, and does not
    # supersede this one (generalised from a distinction specific to the
    # upstream project's second processing stage).
    digest_bytes = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(_HASHING_BLOCK_SIZE), b""):
            digest_bytes.update(block)
    return digest_bytes.hexdigest()


# The two `CATEGORY_BY_EXT` categories that route through a 7-Zip binary
# rather than the standard library. Named here, once, rather than as a
# literal repeated at every site that needs the same count -- this project has
# already paid for a second source of truth on an extension count more than
# once (`NOT_EXTRACTED_EXTENSIONS`). Verified in code review, story 14.3.
CATEGORIES_NEEDING_SEVEN_ZIP = ("external_7zip", "tar_7z")

# The `CATEGORY_BY_EXT` categories that are RECOGNISED AND REFUSED. The format
# is in the table precisely so that the chain refuses it OUT LOUD rather than
# ignoring it, and no machine opens it: not one with 7-Zip installed -- the
# official binary does not handle Zstandard either -- and not one running a
# newer Python, since `compression.zstd` would need code that does not exist
# here. Named once, next to the tuple above and for the same reason: a literal
# repeated at every site that needs the same set is a second source of truth,
# which this project has already paid for.
#
# THE DAY A CATEGORY IS ADDED THAT NOTHING OPENS, IT GOES HERE. Leaving it out
# no longer files it under a favourable state in silence -- see
# `CATEGORIES_OPENED_BY_THE_STANDARD_LIBRARY` below and the anomaly it makes
# possible -- but it still has to go here for the listing to say anything true
# about it.
CATEGORIES_REFUSED = ("zstd_unsupported",)

# The `CATEGORY_BY_EXT` categories the STANDARD LIBRARY opens on its own: no
# binary, no dependency, nothing to install, the same answer on every machine.
#
# WHY THIS TUPLE EXISTS AT ALL, when the two above could have been complemented
# to get it. Because that complement WAS the defect. `project_format_support`
# used to file every category belonging to neither of the two tuples above
# under this state through a bare `else:`, which made the FAVOURABLE state the
# fall-through default of the projection. MEASURED in code review on
# 15 September 2026: adding `".lz4": "lz4_unsupported"` to `CATEGORY_BY_EXT`
# WITH a correct dispatch branch raising `UnsupportedFormatError`, and
# forgetting `CATEGORIES_REFUSED`, left the entire test suite green and made
# the listing print `.lz4` under "opened here and on every machine" -- telling a
# caller, to their face, that a format works where the extraction raises.
#
# THE RULE THIS TUPLE ENFORCES, and the reason a third list is cheaper than the
# bug it closes: membership in each state is read from a POSITIVE list, and a
# category belonging to NONE of the three is a NAMED ANOMALY
# (`UnclassifiedCategoryError`), never a classification by elimination. A
# forgotten category now stops the listing with the category's own name in the
# message, at the first run, instead of being announced as openable everywhere.
# The alternative -- keeping the `else:` and adding a test that enumerates the
# categories -- was rejected: it puts the enumeration in the suite rather than
# in the code, so the code would still be wrong and only the test would know.
CATEGORIES_OPENED_BY_THE_STANDARD_LIBRARY = (
    "zip",
    "tar_plain", "tar_gz", "tar_bz2", "tar_xz", "tar_lzma",
    "plain_gzip", "plain_lzma", "plain_xz", "plain_bz2",
)


class UnclassifiedCategoryError(ValueError):
    """The projection met something the three category lists do not cover.

    TWO FAULTS, ONE CLASS, and both are faults of the TABLES rather than of any
    input a caller supplies -- which is why neither degrades into a listing
    that prints anyway:

      - a `CATEGORY_BY_EXT` category in none of `CATEGORIES_NEEDING_SEVEN_ZIP`,
        `CATEGORIES_REFUSED` and `CATEGORIES_OPENED_BY_THE_STANDARD_LIBRARY`.
        Printing it under any of the four states would assert something about
        it that nobody wrote down;
      - an extension that reaches two states at once, which is the only way the
        two tables can stop being disjoint. The totals would still add up --
        both the per-state counts and the sum over them move together -- so
        nothing arithmetic would notice.

    A SUBCLASS of `ValueError`, deliberately: this says "the data handed to this
    projection is not something it can classify", which is what `ValueError`
    means, and a caller already guarding against bad tables keeps catching it.
    """


# The four states every recognised extension is sorted into by
# `project_format_support`.
#
# FOUR, AND NEVER TWO. A listing with an "opened" column and a "not opened" one
# has nowhere to put the Zstandard extensions: under "opened" it promises an
# extraction that raises, under "not opened" it reads as "install something"
# for a format no installation fixes. And it has no column at all for the
# containers this package recognises and CHOOSES not to open, which would then
# be absent from the listing altogether -- absent from a listing is not read as
# "unknown", it is read as "unrecognised". An omission asserts.
#
# The names are the keys of the machine-readable rendering, so they are written
# for a consumer to match on, not for prose: `unboxr.cli` holds the headings a
# human reads, and this module holds no English sentence a renderer would have
# to reuse.
STATE_OPENED_BY_THE_STANDARD_LIBRARY = "opened_by_the_standard_library"
STATE_DELEGATED_TO_SEVEN_ZIP = "delegated_to_seven_zip"
STATE_RECOGNISED_AND_REFUSED = "recognised_and_refused"
STATE_RECOGNISED_AND_NOT_OPENED = "recognised_and_not_opened"

# Declared as a tuple, in the order a reader should meet them, because the
# rendering iterates THIS rather than the keys of a dictionary it built: a
# state that stopped being produced would then vanish from the listing without
# a word, which is the failure mode the four states exist to prevent.
FORMAT_SUPPORT_STATES = (
    STATE_OPENED_BY_THE_STANDARD_LIBRARY,
    STATE_DELEGATED_TO_SEVEN_ZIP,
    STATE_RECOGNISED_AND_REFUSED,
    STATE_RECOGNISED_AND_NOT_OPENED,
)

# The one state whose answer is a property of the MACHINE and not of this
# package. Written down rather than inferred from `openable_here` being false,
# because the two are not the same question and a consumer that conflated them
# would advise installing 7-Zip to open a `.zst` -- which no installation of
# anything will ever do.
_STATE_DEPENDS_ON_THE_MACHINE = STATE_DELEGATED_TO_SEVEN_ZIP


def probe_capability_profile() -> CapabilityProfile:
    """What this machine can open, MEASURED once and declared in every report.

    ONE PROBE PER RUN, UP FRONT. `find_7zip_binary()` is otherwise called
    LAZILY, at the point of use and with no caching, so a run that meets no
    delegated format never calls it at all -- and the report of such a run
    would say nothing about the machine it ran on. A profile that only appeared
    once 7-Zip had been needed would read "not applicable" where the truth is
    "binary absent". An omission asserts.

    The cost is one `shutil.which` more per run, and it is declared rather than
    hidden. The lazy calls are deliberately left where they are: they are what
    actually decides an extraction, and making them read a cached profile would
    add a second source of truth for one `shutil.which`.

    The two counts are COMPUTED from the extension table, never written as
    literals -- the same discipline `project_format_support` applies to the
    listing the command prints, and the README to the counts it quotes: not
    one of them is a figure typed out, because a typed figure drifts in
    silence.

    NOTHING HERE PROBES THE TAR FILTER, and that is not an oversight: the
    declared Python floor makes the filter unconditional, so there is no
    capability left to detect and no degraded mode to declare.
    """
    return CapabilityProfile(
        seven_zip_binary=find_7zip_binary(),
        recognised_extensions=len(CATEGORY_BY_EXT),
        extensions_needing_seven_zip=sum(
            1 for category in CATEGORY_BY_EXT.values()
            if category in CATEGORIES_NEEDING_SEVEN_ZIP),
    )


def project_format_support() -> dict:
    """What THIS machine does with every extension this package recognises.

    A PROJECTION AND NOTHING ELSE. Every extension, every count and every total
    below is read or derived, at the moment of the call, from `CATEGORY_BY_EXT`,
    `CATEGORIES_NEEDING_SEVEN_ZIP`, `CATEGORIES_REFUSED`,
    `CATEGORIES_OPENED_BY_THE_STANDARD_LIBRARY` and
    `NOT_EXTRACTED_EXTENSIONS`. Not one figure is written as a literal -- the
    discipline `probe_capability_profile` already applies to the two counts
    it declares in every report, and the one the README applies by sending a
    reader to this listing instead of quoting a number at them. A figure
    typed once is a figure that drifts the day an extension is added, and it
    drifts in SILENCE.

    IT LIVES HERE BECAUSE THE TABLES DO. `unboxr.cli` renders what this returns
    and nothing more. A projection written in the command would be a second
    reading of these same tables, to disagree with this one the first time a
    format is added -- exactly how `EXTRACTED_TREE_NAME` and its two
    independent computations stayed in step only for as long as the value never
    varied.

    PURE, EXCEPT FOR THE ONE MEASUREMENT THE ANSWER DEPENDS ON. The presence of
    a 7-Zip binary is MEASURED, by the same `find_7zip_binary()` every
    extraction uses: one `shutil.which` sweep -- plus, on Windows, a look at the
    default install locations -- no archive opened, no network reached, nothing
    written anywhere. And its absence is NAMED (`seven_zip_binary` is `None`,
    and the delegated state carries `openable_here: False`), never expressed as
    a shorter list: the delegated extensions stay in the listing on a machine
    that cannot open a single one of them, because dropping them would assert
    they are not recognised at all.

    THE STATES PARTITION, AND THAT IS CHECKED HERE RATHER THAN HOPED FOR. Every
    key of `CATEGORY_BY_EXT` lands in exactly one of the first three states,
    each read from its OWN positive list; a category in none of them raises
    `UnclassifiedCategoryError` instead of falling through into the favourable
    one. And `NOT_EXTRACTED_EXTENSIONS` has to be disjoint from
    `CATEGORY_BY_EXT` for the fourth state to be a state and not an annotation,
    so an extension reaching two states raises the same anomaly. Both checks
    are here, in the code, and not only in the suite: a projection that can
    only be wrong in a way its own tests would catch is still a projection that
    ships wrong.

    THE LISTING IS ABOUT NAMES. An extension is what a file DECLARES itself to
    be: `categorize_by_content` recognises archives whose name says nothing,
    and the refusal of an office container is extensional too -- a `.docx`
    renamed to `.bin` is extracted as the zip it is. Neither this function nor
    any list of extensions promises anything about bytes. The caller is told so
    in the note `unboxr.cli` prints underneath.

    Returns a dictionary of built-in types only, ready for `json.dumps` and for
    a text renderer alike: ONE structure, two renderings, and no total computed
    a second time on the way to either.
    """
    binary = find_7zip_binary()

    extensions_by_state = {name: [] for name in FORMAT_SUPPORT_STATES}
    for extension, category in CATEGORY_BY_EXT.items():
        # THREE POSITIVE TESTS AND NO `else:`. The favourable state is read
        # from its own list like the other two, so a category nobody sorted
        # stops the listing by name instead of being announced as openable on
        # every machine. See `CATEGORIES_OPENED_BY_THE_STANDARD_LIBRARY` for
        # the mutation that measured what the `else:` cost.
        if category in CATEGORIES_NEEDING_SEVEN_ZIP:
            state = STATE_DELEGATED_TO_SEVEN_ZIP
        elif category in CATEGORIES_REFUSED:
            state = STATE_RECOGNISED_AND_REFUSED
        elif category in CATEGORIES_OPENED_BY_THE_STANDARD_LIBRARY:
            state = STATE_OPENED_BY_THE_STANDARD_LIBRARY
        else:
            raise UnclassifiedCategoryError(
                f"{extension!r} is categorised as {category!r}, which belongs "
                f"to none of CATEGORIES_NEEDING_SEVEN_ZIP, CATEGORIES_REFUSED "
                f"and CATEGORIES_OPENED_BY_THE_STANDARD_LIBRARY. A category "
                f"this projection cannot place is not filed under the "
                f"favourable state by elimination: add it to the list that "
                f"describes what this machine actually does with it.")
        extensions_by_state[state].append(extension)
    extensions_by_state[STATE_RECOGNISED_AND_NOT_OPENED].extend(
        NOT_EXTRACTED_EXTENSIONS)

    # THE SECOND WAY THE PARTITION CAN STOP BEING ONE, and the only one the
    # loop above cannot see: an extension present in BOTH tables lands in two
    # states, and every total still adds up -- its state's count and the sum
    # over the states move together, identically. Nothing arithmetic notices,
    # which is exactly why this is a test on the extensions themselves.
    seen = [extension
            for name in FORMAT_SUPPORT_STATES
            for extension in extensions_by_state[name]]
    if len(seen) != len(set(seen)):
        duplicated = sorted({e for e in seen if seen.count(e) > 1})
        raise UnclassifiedCategoryError(
            f"{duplicated} reach more than one state: CATEGORY_BY_EXT and "
            f"NOT_EXTRACTED_EXTENSIONS have stopped being disjoint, so the "
            f"four states are no longer a partition and every total below "
            f"would still add up.")

    # SORTED, because the output of this command has to be comparable with
    # itself. `CATEGORY_BY_EXT` iterates in insertion order and
    # `NOT_EXTRACTED_EXTENSIONS` is a frozenset, whose iteration order is a
    # property of the interpreter run; a listing two runs apart would differ
    # for a reason that has nothing to do with the machine it measured.
    states = {}
    for name in FORMAT_SUPPORT_STATES:
        extensions = sorted(extensions_by_state[name])
        states[name] = {
            "extensions": extensions,
            "count": len(extensions),
            # Only the standard-library state is open unconditionally. The
            # delegated one is open exactly when the binary was found, and the
            # two remaining states are closed on EVERY machine -- which is why
            # neither of them is "unavailable here".
            "openable_here": (name == STATE_OPENED_BY_THE_STANDARD_LIBRARY
                              or (name == STATE_DELEGATED_TO_SEVEN_ZIP
                                  and binary is not None)),
            "depends_on_this_machine": name == _STATE_DEPENDS_ON_THE_MACHINE,
        }

    return {
        "seven_zip_binary": binary,
        "recognised_extensions": len(CATEGORY_BY_EXT),
        "not_extracted_extensions": len(NOT_EXTRACTED_EXTENSIONS),
        # Summed over the states rather than added up from the two tables a
        # second time, so that this total and the per-state counts printed
        # above it cannot disagree.
        #
        # AND IT IS NOT A CHECK ON THE PARTITION, which is what this comment
        # claimed until code review on 15 September 2026 -- "if the partition
        # above ever stopped being one, this total would move". It does not:
        # an extension in both tables inflates a state's count and this sum by
        # exactly one each, so the two agree on a wrong number. The partition
        # is checked where it can actually be seen, on the extensions
        # themselves, a few lines above -- and it RAISES rather than printing.
        "listed_extensions": sum(state["count"] for state in states.values()),
        # NAMED FOR ITS TYPE, and renamed for it. `openable_here` is a BOOLEAN
        # inside every state ("does this machine open this state?"); a count
        # carrying the same key at the top level put one name on two types in
        # one machine-readable document, which is a consumer's bug waiting to
        # be written. Measured in code review, 15 September 2026.
        "extensions_openable_here": sum(state["count"]
                                        for state in states.values()
                                        if state["openable_here"]),
        "states": states,
    }


def new_report() -> ExtractionReport:
    """An empty report, carrying this machine's capability profile.

    The way to obtain one to hand to `prepare_source`: an `ExtractionReport`
    cannot be built without a profile, and this is what measures it.
    """
    return ExtractionReport(capability=probe_capability_profile())


def resolve_archive_name(source: str) -> str:
    """The FINAL name the extraction root will carry, verbatim -- WITHOUT
    downloading a URL to find out.

    A local archive keeps its own file name. A URL never touches the network
    here: it is the last segment of the URL's path, or `"downloaded_archive"`
    when it gives none. `download_source` calls THIS function rather than
    recomputing the rule, so a caller deciding where the tree will land
    (`unboxr.cli`, refusing an unusable `--sbom` path before anything is
    extracted) does not have to download first to learn it, and the two can
    never drift apart the way `EXTRACTED_TREE_NAME`'s own two independent
    computations once did.

    The local branch falls back the same way as the URL branch does, for a
    source whose own name component is empty (code review, 15 September
    2026) -- a defensive floor: nothing observed today reaches it, since a
    source resolving to an empty name is a directory in every case measured,
    and a directory source never calls this function at all.
    """
    if is_url(source):
        return Path(urlparse(source).path).name or "downloaded_archive"
    return Path(source).name or "unnamed_archive"


def resolve_extraction_root(source: str, workspace: Path | None, *,
                            replace: bool = False,
                            no_archive_dir: bool = False) -> Path:
    """
    THE single point where `workspace`, an archive's name and the three modes
    of story 14.8 combine into the directory the extracted tree will occupy.
    Both `prepare_source` (which extracts there) and `unboxr.cli` (which has
    to know this path BEFORE calling `prepare_source`, to refuse an unusable
    `--sbom` path or an already-occupied target before anything is written)
    call this -- never recompute it apart. Two independent computations of
    the same name are exactly how `EXTRACTED_TREE_NAME`, a shared literal,
    and `cli.py`'s own `destination / EXTRACTED_TREE_NAME` used to stay in
    step only because the value never varied; the day it started depending on
    the archive and the mode, that would have stopped being true.

    `replace`: the archive's own current path -- no workspace enters into it
    at all, which is also why DESTINATION is refused alongside `--replace`
    before this is ever reached.
    `no_archive_dir`: `workspace` itself, with no directory named after the
    archive created beneath it.
    Neither: `workspace / <the archive's own name>` -- the default (AC-1).

    Touches no file system: `is_url` and a path split, nothing else. That is
    what lets `unboxr.cli` call it before the destination, or even the
    archive, is known to exist.
    """
    if replace:
        return Path(source)
    if no_archive_dir:
        return workspace
    return workspace / resolve_archive_name(source)


def _extract_replacing_archive_with_its_own_content(
        local_path: Path, *, report, digest_hex: str) -> Path:
    """
    Extract `local_path` under a provisional name, remove the archive, then
    rename the extraction onto the path the archive itself just vacated --
    EXACTLY the three-step dance `flatten_nested_archives` already performs
    for a nested archive (story 14.8, AC-5), reused rather than reinvented.

    THE ONLY TWO CALLERS THAT NEED THIS AT LEVEL 0. `--replace`, where the
    final path IS the archive's own path by definition (D-A/D-B of the
    story); and a URL under the default mode, where the downloaded copy sits
    at `workspace / resolve_archive_name(source)` -- the exact path the
    default mode's target already is, by construction, every single time
    (`download_source` writes it there). Neither is a pre-existing
    conflict to refuse: both are structural, and the archive is consumed the
    same way a nested one already is.

    A LOCAL archive without `--replace` is NEVER routed here: if its own
    parent happens to be the workspace, the target and the archive coincide
    by ACCIDENT of the caller's own arguments, not by construction, and that
    case is refused upstream instead (`unboxr.cli`, AC-2 / AC-5.3) -- an
    archive the caller did not ask to consume is never silently deleted.

    Returns the path ACTUALLY obtained: the intended final path when the
    rename succeeds, or the provisional path when it does not -- the tree
    the caller gets back must always be the one that is really there. A
    failure to extract is NOT caught here: it propagates, exactly as it does
    for the level-0 archive today, and `digest_hex` is threaded through
    rather than re-hashed, for the same reason `prepare_source` already
    reuses it once (the bytes are the same bytes).
    """
    final_dest = local_path
    provisional_dest = local_path.parent / _provisional_name_at_level_zero(local_path)

    # THE SAME COLLISION GUARD `flatten_nested_archives` applies to its own
    # provisional names, applied here: a workspace reused across runs, or a
    # previous run whose rename failed and left this exact name behind, must
    # never be silently merged into. `is_dir()` first, `iterdir()` guarded --
    # the check must never be what amputates the run it is protecting.
    occupied = False
    if provisional_dest.is_dir():
        try:
            occupied = any(provisional_dest.iterdir())
        except OSError:
            occupied = False
    if occupied:
        logger.warning("%s: its provisional extraction directory %s already "
                       "holds content, left by an earlier run over this "
                       "workspace; the two are mixed there, with no further "
                       "warning.", local_path, provisional_dest)
        _record(report, PROVISIONAL_DIRECTORY_ALREADY_OCCUPIED, local_path,
                level=0, digest=digest_hex)

    logger.info("Extracting archive: %s", local_path)
    try:
        extract_archive(local_path, provisional_dest, report=report,
                        location=local_path.name)
    except Exception as exc:
        _record(report, getattr(exc, "code", EXTRACTION_FAILED), local_path,
                level=0, detail=str(exc), digest=digest_hex)
        raise
    # THE WINDOW: the same instant `flatten_nested_archives` records for a
    # nested container -- the last moment the archive still exists on disk.
    _record(report, INPUT_CONTAINER_OPENED, local_path, level=0,
            digest=digest_hex)
    try:
        local_path.unlink()
    except FileNotFoundError:
        # Already gone: external interference, not a removal failure. The
        # extraction above already succeeded, so the rename below still runs.
        pass
    except OSError as exc:
        logger.warning("%s was extracted successfully but could not be "
                       "removed (%s): the archive is kept, and its content "
                       "stays under the provisional name %s. Its content IS "
                       "in the extracted tree.", local_path, exc,
                       provisional_dest)
        _record(report, ARCHIVE_KEPT_AFTER_SUCCESSFUL_EXTRACTION, local_path,
                level=0, detail=str(exc), digest=digest_hex)
        return provisional_dest
    try:
        # `final_dest.exists()` checked FIRST, exactly as the nested dance
        # does: POSIX replaces an empty directory silently on `rename()`,
        # Windows raises -- checking first makes an occupied `final_dest`
        # behave the same, declared way on both.
        if final_dest.exists():
            raise OSError(f"a directory or file already exists at {final_dest}")
        provisional_dest.rename(final_dest)
    except OSError as exc:
        logger.warning("%s: the extracted content could not be renamed to "
                       "%s (%s): it stays under its provisional name %s. Its "
                       "content IS in the extracted tree, under that name.",
                       local_path, final_dest, exc, provisional_dest)
        _record(report, EXTRACTION_KEPT_UNDER_PROVISIONAL_NAME, local_path,
                level=0, detail=str(exc))
        return provisional_dest
    return final_dest


def prepare_source(source: str, workspace: Path | None = None,
                   report: ExtractionReport | None = None, *,
                   replace: bool = False,
                   no_archive_dir: bool = False) -> PreparedSource:
    """
    Resolve a source in the 3 possible cases and always return a directory ready
    to be walked, together with the NATURE of the resolved unit and the SHA-256
    digest of the received input when it has one:
      1. Existing local directory   -> used as is, nature "directory".
      2. Local archive file (see the
         supported formats in
         CATEGORY_BY_EXT)           -> extracted and flattened recursively,
         nature resolved by `resolve_distribution_nature` ("source" / "built" /
         "undetermined").
      3. Public URL (http/https)    -> downloaded, then case 2: the nature is
         that of the DOWNLOADED ARCHIVE, never a fourth value "url" -- a URL is
         a means of access, not a nature. This is the only code path in the
         whole package that touches the network.

    The 3rd element is the hexadecimal digest of the RECEIVED ARCHIVE, or `None`
    when it has no meaning: a directory is not a single file, there is nothing to
    hash.

    `workspace` is the directory the archive is unpacked under; the tree
    returned is `resolve_extraction_root(source, workspace, replace=replace,
    no_archive_dir=no_archive_dir)` -- by default `workspace / <the archive's
    own name, verbatim>` (story 14.8, AC-1). When `workspace` is not given, a
    temporary directory is created and NEVER removed -- the caller owns it. A
    caller that runs repeatedly should pass a workspace it manages itself.

    `replace` and `no_archive_dir` select the other two modes (mutually
    exclusive; `unboxr.cli` enforces that and their own preconditions --
    `replace` takes no `workspace` at all, neither is honoured when `source`
    is already a directory -- before this function is ever called; this
    function itself prescribes no usage error, being a library):
      - `replace=True` extracts the archive IN PLACE and removes it: the
        final tree occupies the archive's own path. Refused upstream for a
        URL and for a directory source.
      - `no_archive_dir=True` extracts straight into `workspace`, with no
        directory named after the archive created beneath it.

    THE REPORT COMES BACK BY THE RETURN VALUE, AND MAY ALSO BE PASSED IN. The
    two are not redundant, and neither replaces the other:

      - the RETURN VALUE is what makes the "what could not be opened" field
        impossible to omit. A caller cannot obtain the tree without also
        receiving the report; a report offered only through an optional
        parameter would be omissible, and so would not be the invariant;
      - the PARAMETER is what makes it survive a `raise`. That is the moment
        the declaration matters most and the moment a return value does not
        exist -- an office container given as the source is refused, and THEN
        the run fails with nothing to return.

    The returned object is NAMED rather than positional. Three pieces already
    read poorly unpacked; a fourth reads worse, and "a report whose field
    cannot be omitted" is meant literally -- a field has a name. The three
    existing pieces keep exactly their meaning.
    """
    from_url = is_url(source)
    if replace:
        # `--replace` never takes a workspace (`unboxr.cli` refuses one
        # upstream): the archive's own parent stands in for it, exactly as
        # `resolve_extraction_root` already assumes for this mode.
        workspace = Path(source).parent
    else:
        workspace = workspace or Path(tempfile.mkdtemp(prefix="prepared_source_"))
    if report is None:
        report = new_report()

    if from_url:
        local_path = download_source(source, workspace)
    else:
        local_path = Path(source)
        if not local_path.exists():
            raise FileNotFoundError(f"Source not found: {local_path}")

    if local_path.is_dir():
        # NO computation is ATTEMPTED here: a directory has no single file to
        # hash, and condensing a tree walk would fabricate a digest of SOMETHING
        # ELSE. `None` is returned as such, never silently omitted.
        #
        # THE REPORT IS RETURNED HERE TOO, empty and explicit. This path
        # extracts nothing, which is exactly why the report must not be
        # missing: an absent report would read "not applicable" where the truth
        # is "nothing was refused". An omission asserts. It still carries the
        # capability profile -- the machine is what it is, whether or not
        # anything needed 7-Zip.
        return PreparedSource(tree=local_path, nature="directory", digest=None,
                              report=report)

    # Extension matched once, reused both for archive recognition AND for the
    # nature. `extract_archive`, further down, makes its own call: the total
    # number of calls -- and therefore the informational records
    # `categorize_archive` may emit -- is what it has always been.
    category, matched_extension = categorize_archive(local_path, report=report,
                                                    level=0)
    if category is None:
        # Tell "unrecognised" apart from "recognised but deliberately excluded":
        # without this hint, the message below contradicts the informational
        # record `categorize_archive()` has just emitted for an office container
        # -- measured in code review on 20 August 2026 in the upstream project
        # (crypto-scan, story 05.0).
        lowered_name = local_path.name.lower()
        exclusion_hint = ""
        if any(lowered_name.endswith(ext) for ext in NOT_EXTRACTED_EXTENSIONS):
            exclusion_hint = (
                " (this format is an office container, deliberately excluded "
                "from extraction -- see NOT_EXTRACTED_EXTENSIONS)"
            )
        raise ValueError(
            f"'{local_path}' is neither a directory nor a recognised archive "
            f"({sorted(CATEGORY_BY_EXT.keys())}){exclusion_hint}."
        )

    nature = resolve_distribution_nature(local_path.name, matched_extension)

    # HERE, AND NOWHERE ELSE. This is the ONLY point in the flow where both
    # origins converge -- a local archive given as the source, or the file
    # `download_source` has just written for a URL -- and the LAST point where
    # `local_path` still designates the complete archive, before
    # `extract_archive` scatters its content.
    #
    # For the URL case it is the only possible window: nothing outside this
    # function retains the downloaded file, so once it has returned nothing lets
    # the downloaded bytes be found again. Computing later would compute on
    # something else, or on nothing.
    #
    # The digest covers the FIRST-LEVEL archive, never a nested archive found by
    # the flattening below: what is attested is the input as it was GIVEN.
    digest_hex = _sha256_digest_of_file(local_path)
    logger.info("SHA-256 digest of the input: sha256:%s", digest_hex)

    target = resolve_extraction_root(source, workspace, replace=replace,
                                     no_archive_dir=no_archive_dir)

    # THE ARCHIVE OCCUPIES ITS OWN TARGET PATH, STRUCTURALLY, in exactly two
    # cases (story 14.8, AC-5): `--replace` (`target` IS `local_path`, by
    # definition of `resolve_extraction_root`), and a URL under the DEFAULT
    # mode (`download_source` wrote `local_path` at `workspace /
    # resolve_archive_name(source)`, which is what `target` already computes
    # to). Both go through the same provisional-name-then-rename dance
    # `flatten_nested_archives` already performs for a nested archive, reused
    # rather than reinvented, and the archive is CONSUMED in both.
    #
    # `replace or (from_url and not no_archive_dir)` NAMES those two cases --
    # deliberately NOT `target == local_path`, which happens to hold in a
    # THIRD case too: a local archive, no `--replace`, whose DESTINATION is
    # its own parent directory. There the collision is an ACCIDENT of the
    # caller's own arguments, not a structural certainty, and the archive was
    # never offered up to be consumed. `unboxr.cli` refuses that case
    # upstream instead (AC-2 / AC-5.3) before `prepare_source` is ever
    # called; this function does not render it impossible for a direct
    # library call that bypassed the refusal -- consistent with the rest of
    # this function, which prescribes no usage error, being a library.
    if replace or (from_url and not no_archive_dir):
        destination = _extract_replacing_archive_with_its_own_content(
            local_path, report=report, digest_hex=digest_hex)
    else:
        destination = target
        # The same collision guard `flatten_nested_archives` applies to its
        # nested destinations, applied to the FIRST-level one. Without it the
        # guard existed only below the top: a caller that reuses a workspace
        # -- the case this function's own docstring names -- poured a second
        # extraction into the first one with no trace at all. Verified in
        # code review on 9 September 2026. Same rule as below: state what is
        # OBSERVED, never a cause.
        #
        # `local_path` IS EXCLUDED FROM THE COUNT under `--no-archive-dir` for
        # a URL: `download_source`, a few lines above, has already written the
        # downloaded copy straight into `destination` (`no_archive_dir` makes
        # `target` -- and so `destination` -- `workspace` itself), so a run
        # that has touched nothing yet would otherwise see its own
        # just-downloaded file and misreport it as pre-existing content
        # (false `DESTINATION_ALREADY_OCCUPIED`, on every single such run).
        # Code review, 15 September 2026.
        if destination.is_dir():
            try:
                already_occupied = any(p for p in destination.iterdir()
                                       if not (from_url and no_archive_dir
                                               and p == local_path))
            except OSError:
                already_occupied = False
            if already_occupied:
                logger.warning("Destination %s already holds content; "
                               "extracting into it merges the two, with no "
                               "further warning.", destination)
                # NO DIGEST: `destination` is a DIRECTORY. Condensing a tree
                # walk into a value that reads like a file digest would
                # attest something else entirely.
                _record(report, DESTINATION_ALREADY_OCCUPIED, destination,
                        level=0)
        logger.info("Extracting archive: %s", local_path)
        # THE FIRST-LEVEL CONTAINER IS EXTRACTED OUTSIDE THE FLATTENING LOOP,
        # so neither the record of its opening nor the record of its failure
        # can come from there. Without this `try`, the single most visible
        # amputation of a run -- the source the caller named -- reached no
        # report at all.
        try:
            extract_archive(local_path, destination, report=report,
                            location=local_path.name)
        except Exception as exc:
            # REUSED, never recomputed: `digest_hex` was taken a few lines
            # above on these very bytes, at the one point both origins
            # converge.
            _record(report, getattr(exc, "code", EXTRACTION_FAILED), local_path,
                    level=0, detail=str(exc), digest=digest_hex)
            raise
        # Reused as well: same file, same bytes, digest already in hand.
        _record(report, INPUT_CONTAINER_OPENED, local_path, level=0,
                digest=digest_hex)
        # A URL, still lingering as a plain file inside `destination` under
        # `no_archive_dir` (its path there IS `target`'s own parent, unlike
        # the default mode where it IS `target`): consumed here too, so
        # `flatten_nested_archives` below never re-discovers it as a nested
        # archive of itself, and so `destination` ends up holding only the
        # tree (story 14.8, D-C) even though there was no rename dance to
        # fold this into.
        if from_url and no_archive_dir:
            try:
                local_path.unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                logger.warning("The downloaded copy %s could not be removed "
                               "(%s): it stays alongside the extracted tree "
                               "in %s.", local_path, exc, destination)
                _record(report, DOWNLOADED_COPY_KEPT_ALONGSIDE_THE_TREE,
                        local_path, level=0, detail=str(exc), digest=digest_hex)
    logger.info("Looking for nested archives (recursive flattening)...")
    flatten_nested_archives(destination, report=report)
    return PreparedSource(tree=destination, nature=nature, digest=digest_hex,
                          report=report)
