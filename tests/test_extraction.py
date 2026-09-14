"""The extraction chain must see what it used to ignore, and say what it cannot
open.

Why this file exists. Recognition used to be purely extensional: an archive
whose extension was absent, misleading or off-table crossed the chain WITHOUT A
SINGLE MESSAGE, and its content never reached the caller. A consumer then
reported on content that had never been read -- a silent fallback, applied to
the corpus itself.

These tests hold the three properties that fix it:
  1. an archive is recognised by its CONTENT when its extension says nothing;
  2. what is recognised but not extractable (Zstandard) is REFUSED AND SAID SO,
     never hushed;
  3. the widening does not overflow: office containers, which are zips, stay
     excluded -- explicitly, no longer by omission.

Property 3 is not cosmetic: without it, property 1 lets the packaging parts of
office documents into the corpus, where they are pure noise.

100% offline, standard library only. No network, no git, no 7-Zip binary, no
versioned fixture: every archive here is built on the spot.
"""

from __future__ import annotations

import bz2
import gzip
import io
import logging
import lzma
import shutil
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import unboxr.extraction as ux  # noqa: E402

# ---------------------------------------------------------------------------
# Non-regression invariants, spelled out on purpose. A table copied from the
# module would hold nothing: it would follow the very regression it is meant to
# catch.
#
# INHERITED COVERAGE GAP, DECLARED AND NOT CLOSED HERE: this literal freezes 47
# entries of a table that has 68. The 21 later entries are held by the
# equivalence proof in `transport/`, which compares the whole table against the
# original -- keys AND values. Widening this literal to 68 would duplicate that
# proof without adding anything, and would have to be rewritten the day the
# upstream table legitimately grows.
# ---------------------------------------------------------------------------
CATEGORY_BY_EXT_ORIGIN = {
    ".zip": "zip", ".jar": "zip", ".whl": "zip", ".egg": "zip",
    ".tar": "tar_plain",
    ".tar.gz": "tar_gz", ".tgz": "tar_gz",
    ".tar.bz2": "tar_bz2", ".tbz2": "tar_bz2",
    ".tar.xz": "tar_xz", ".txz": "tar_xz",
    ".tar.lzma": "tar_lzma", ".tlz": "tar_lzma",
    ".tar.7z": "tar_7z",
    ".gz": "plain_gzip", ".pack.gz": "plain_gzip",
    ".lzma": "plain_lzma",
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
}

# Zstandard header (RFC 8878, 3.1.1: magic number 0xFD2FB528, little-endian).
# No test extracts this format: the chain must precisely REFUSE to, so it is
# enough that the header be exact.
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


class _Capture(logging.Handler):
    """Captures package records, INCLUDING the case of no record at all.

    This replaces the `redirect_stdout` helper the suite used before the library
    was made silent. `assertLogs` will not do: it fails when nothing is logged,
    and several cases here legitimately log nothing. A capture that cannot
    express "zero events" cannot assert "zero events".
    """

    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.records = []

    def emit(self, record):
        self.records.append(record)

    def __enter__(self):
        self.logger = logging.getLogger("unboxr")
        self.previous_level = self.logger.level
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(self)
        return self

    def __exit__(self, *exc_info):
        self.logger.removeHandler(self)
        self.logger.setLevel(self.previous_level)
        return False

    @property
    def messages(self) -> str:
        return "\n".join(record.getMessage() for record in self.records)

    @property
    def levels(self) -> list[str]:
        return [record.levelname for record in self.records]


class _Bench(unittest.TestCase):
    """Builds its own fixtures: no binary is versioned in this repository."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="test_extraction_"))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    # -- factories ---------------------------------------------------------

    def _zip(self, name: str, members=(("code/aes.c", "static const int sbox[256];"),)):
        path = self.dir / name
        with zipfile.ZipFile(path, "w") as z:
            for arcname, content in members:
                z.writestr(arcname, content)
        return path

    def _tar(self, name: str, mode="w", members=(("src/sha256.c", "uint32_t K[64];"),)):
        path = self.dir / name
        with tarfile.open(path, mode) as t:
            for arcname, content in members:
                payload = content.encode("utf-8")
                info = tarfile.TarInfo(arcname)
                info.size = len(payload)
                t.addfile(info, io.BytesIO(payload))
        return path

    def _plain_compressed(self, name: str, opener, content=b"int key = 42;"):
        """A single compressed file -- NOT a tar archive."""
        path = self.dir / name
        with opener(path, "wb") as f:
            f.write(content)
        return path

    def _zstd(self, name: str):
        path = self.dir / name
        path.write_bytes(ZSTD_MAGIC + b"undecodable payload")
        return path

    def _capture(self, function, *args, **kwargs):
        with _Capture() as capture:
            result = function(*args, **kwargs)
        return result, capture


# ---------------------------------------------------------------------------
# Content-based identification
# ---------------------------------------------------------------------------
class TestContentIdentification(_Bench):

    def test_a_renamed_archive_is_recognised_by_its_content(self):
        """The case measured as failing before this behaviour existed."""
        source = self._tar("package.tar", mode="w:gz")
        renamed = self.dir / "package_without_extension.bin"
        source.rename(renamed)

        self.assertTrue(ux.is_archive(renamed))
        category, _ = ux.categorize_archive(renamed)
        self.assertEqual(category, "tar_gz")

    def test_an_ordinary_file_stays_unrecognised(self):
        """The oracle is POSITIVE ONLY: no signature, no conclusion."""
        ordinary = self.dir / "notes.txt"
        ordinary.write_text("this is not an archive", encoding="utf-8")
        self.assertFalse(ux.is_archive(ordinary))
        self.assertEqual(ux.categorize_archive(ordinary), (None, None))

    def test_an_empty_file_does_not_raise(self):
        empty = self.dir / "empty.bin"
        empty.write_bytes(b"")
        self.assertEqual(ux.categorize_archive(empty), (None, None))

    def test_content_recognition_announces_itself(self):
        source = self._zip("package.zip")
        renamed = self.dir / "opaque.data"
        source.rename(renamed)

        _, capture = self._capture(ux.categorize_archive, renamed)
        self.assertEqual(["INFO"], capture.levels)
        self.assertIn("opaque.data", capture.messages)
        self.assertIn("zip", capture.messages)

    def test_the_extension_wins_and_no_byte_is_read(self):
        """A known extension short-circuits content: that IS the imposed order."""
        archive = self._zip("package.zip")
        with mock.patch.object(ux, "categorize_by_content") as spy:
            category, ext = ux.categorize_archive(archive)
        spy.assert_not_called()
        self.assertEqual((category, ext), ("zip", ".zip"))

    def test_the_extension_wins_even_when_the_content_says_otherwise(self):
        """A zip named .tar.gz stays categorised by its name."""
        source = self._zip("trap.zip")
        liar = self.dir / "trap.tar.gz"
        source.rename(liar)
        category, ext = ux.categorize_archive(liar)
        self.assertEqual((category, ext), ("tar_gz", ".tar.gz"))

    def test_tar_gzip_against_plain_gzip(self):
        tar_gz = self._tar("a.tar", mode="w:gz")
        anonymous_tar_gz = self.dir / "a.data"
        tar_gz.rename(anonymous_tar_gz)

        gz_alone = self._plain_compressed("b.data", gzip.open)

        self.assertEqual(ux.categorize_archive(anonymous_tar_gz)[0], "tar_gz")
        self.assertEqual(ux.categorize_archive(gz_alone)[0], "plain_gzip")

    def test_tar_bzip2_against_plain_bzip2(self):
        tar_bz2 = self._tar("c.tar", mode="w:bz2")
        anonymous = self.dir / "c.data"
        tar_bz2.rename(anonymous)

        bz2_alone = self._plain_compressed("d.data", bz2.open)

        self.assertEqual(ux.categorize_archive(anonymous)[0], "tar_bz2")
        self.assertEqual(ux.categorize_archive(bz2_alone)[0], "plain_bz2")

    def test_tar_xz_against_plain_xz(self):
        tar_xz = self._tar("e.tar", mode="w:xz")
        anonymous = self.dir / "e.data"
        tar_xz.rename(anonymous)

        xz_alone = self._plain_compressed("f.data", lzma.open)

        self.assertEqual(ux.categorize_archive(anonymous)[0], "tar_xz")
        self.assertEqual(ux.categorize_archive(xz_alone)[0], "plain_xz")

    def test_extracting_the_renamed_archive_yields_its_content(self):
        """End to end: recognised, extracted, flattened."""
        inner = self._zip("inner.zip", members=(("crypto/aes.c", "sbox"),))
        outer = self.dir / "outer.tar"
        with tarfile.open(outer, "w:gz") as t:
            t.add(inner, arcname="vendor/inner.zip")
        inner.unlink()
        anonymous = self.dir / "package.opaque"
        outer.rename(anonymous)

        dest = self.dir / "output"
        self._capture(ux.extract_archive, anonymous, dest)
        self._capture(ux.flatten_nested_archives, dest)

        found = [p.name for p in dest.rglob("*") if p.is_file()]
        self.assertIn("aes.c", found)

    def test_a_truncated_gzip_does_not_make_categorize_archive_raise(self):
        """A gzip stream cut before its end raises a BARE `EOFError` (not an
        `OSError` subclass) from `tarfile.is_tarfile()`. Before the fix, that
        exception crossed `categorize_by_content()` and crashed the whole of
        `flatten_nested_archives()`, which calls `is_archive()` on every file of
        the tree with NO `try/except`."""
        buffer = io.BytesIO()
        with gzip.GzipFile(fileobj=buffer, mode="wb") as f:
            f.write(b"x" * 5000)
        complete_stream = buffer.getvalue()
        truncated = self.dir / "cut_by_transfer.bin"
        truncated.write_bytes(complete_stream[: len(complete_stream) // 2])

        # Must NOT raise: that is the defect fixed.
        category, _ = ux.categorize_archive(truncated)
        self.assertEqual(category, "plain_gzip")

        # And above all: it does not crash the flattening of a tree containing
        # it, the real case that motivated the fix.
        root = self.dir / "tree_with_broken_gzip"
        root.mkdir()
        shutil.move(str(truncated), root / "cut.bin")
        self._capture(ux.flatten_nested_archives, root)  # does not raise

    def test_a_two_byte_bzh_coincidence_without_a_digit_is_not_bz2(self):
        """bzip2 ALWAYS follows "BZh" with a digit 1-9. An ordinary file whose
        bytes start with "BZh" followed by something else is not a valid bzip2
        signature."""
        false_positive = self.dir / "coincidence.py"
        false_positive.write_bytes(b"BZh" + b"! not a compression level")
        self.assertEqual(ux.categorize_archive(false_positive), (None, None))
        self.assertFalse(ux.is_archive(false_positive))

    def test_a_real_bzh_with_a_digit_stays_recognised(self):
        """Non-regression of the previous fix: a real bzip2 (digit 1-9 after
        "BZh") must stay recognised."""
        real = self._plain_compressed("real.bz2data", bz2.open, b"content")
        # `_plain_compressed()` produces a real bz2 stream: its header already
        # carries a valid level digit (the bz2 module defaults to 9).
        category, _ = ux.categorize_archive(real)
        self.assertEqual(category, "plain_bz2")


# ---------------------------------------------------------------------------
# Zstandard: recognised, refused, said
# ---------------------------------------------------------------------------
class TestZstandardRecognisedButRefused(_Bench):

    def test_the_four_zstd_extensions_are_recognised(self):
        for name in ("p.zst", "p.zstd", "p.tar.zst", "p.tar.zstd"):
            with self.subTest(name=name):
                category, _ = ux.categorize_archive(self.dir / name)
                self.assertEqual(category, "zstd_unsupported")

    def test_is_archive_returns_true_never_false(self):
        """Returning False would sink back into the silence this corrects."""
        for name in ("p.zst", "p.tar.zst"):
            with self.subTest(name=name):
                self.assertTrue(ux.is_archive(self.dir / name))

    def test_the_zstd_signature_is_recognised_without_an_extension(self):
        anonymous = self._zstd("package.opaque")
        category, _ = ux.categorize_archive(anonymous)
        self.assertEqual(category, "zstd_unsupported")
        self.assertTrue(ux.is_archive(anonymous))

    def test_extraction_raises_carrying_its_cause(self):
        archive = self._zstd("package.tar.zst")
        with self.assertRaises(Exception) as caught:
            ux.extract_archive(archive, self.dir / "output")
        message = str(caught.exception)
        self.assertIn("Zstandard", message)
        self.assertIn("3.14", message)
        self.assertIn("PEP 784", message)
        # The message must say the content was NOT extracted: that is the
        # information on which reading an absent finding depends.
        self.assertRegex(message, r"(?i)not\s+extracted")

    def test_nested_the_existing_warning_is_emitted(self):
        """No new line: the `except` of the flattening already does the work."""
        root = self.dir / "tree"
        root.mkdir()
        (root / "readable.c").write_text("int a;", encoding="utf-8")
        zstd_path = root / "nested.tar.zst"
        zstd_path.write_bytes(ZSTD_MAGIC + b"...")

        _, capture = self._capture(ux.flatten_nested_archives, root)

        self.assertIn("WARNING", capture.levels)
        self.assertIn("nested.tar.zst", capture.messages)
        # The `[EXPLOITATION]` marker of the upstream prefix is gone: the level
        # carries it now. What must NOT be lost is the amputation itself being
        # named, so a consumer can read an absent finding correctly.
        self.assertIn("NOT in the extracted tree", capture.messages)
        # The archive is KEPT: we do not destroy what we could not read.
        self.assertTrue(zstd_path.exists())

    def test_at_the_root_prepare_source_propagates(self):
        """The message must CARRY ITS CAUSE at the root position too, not only
        on a direct call to `extract_archive()`."""
        archive = self._zstd("root.tar.zst")
        with self.assertRaises(Exception) as caught:
            with _Capture():
                ux.prepare_source(str(archive), workspace=self.dir / "ws")
        message = str(caught.exception)
        self.assertIn("Zstandard", message)
        self.assertRegex(message, r"(?i)not\s+extracted")


# ---------------------------------------------------------------------------
# Added formats
# ---------------------------------------------------------------------------
class TestAddedFormats(_Bench):

    def test_plain_xz_and_bz2_are_categorised(self):
        expected = {".xz": "plain_xz", ".bz2": "plain_bz2", ".bz": "plain_bz2"}
        for ext, category in expected.items():
            with self.subTest(ext=ext):
                self.assertEqual(ux.categorize_archive(Path("x" + ext))[0], category)

    def test_compound_variants_still_win(self):
        """Sorting by decreasing length must survive every addition."""
        for name, expected in ((".tar.xz", "tar_xz"), (".tar.bz2", "tar_bz2")):
            with self.subTest(name=name):
                self.assertEqual(ux.categorize_archive(Path("x" + name))[0], expected)

    def test_a_plain_xz_is_really_extracted(self):
        source = self._plain_compressed("data.xz", lzma.open, b"int key = 7;")
        dest = self.dir / "output_xz"
        ux.extract_archive(source, dest)
        produced = [p for p in dest.rglob("*") if p.is_file()]
        self.assertEqual(len(produced), 1)
        self.assertEqual(produced[0].read_bytes(), b"int key = 7;")

    def test_a_plain_bz2_is_really_extracted(self):
        source = self._plain_compressed("data.bz2", bz2.open, b"int key = 9;")
        dest = self.dir / "output_bz2"
        ux.extract_archive(source, dest)
        produced = [p for p in dest.rglob("*") if p.is_file()]
        self.assertEqual(len(produced), 1)
        self.assertEqual(produced[0].read_bytes(), b"int key = 9;")

    def test_ecosystem_zip_containers_are_recognised(self):
        for ext in (".apk", ".aar", ".war", ".ear", ".sar",
                    ".nupkg", ".xpi", ".ipa", ".pyz", ".zipx"):
            with self.subTest(ext=ext):
                self.assertEqual(ux.categorize_archive(Path("x" + ext))[0], "zip")

    def test_gem_is_a_tar_and_the_tar_variants_are_recognised(self):
        self.assertEqual(ux.categorize_archive(Path("x.gem"))[0], "tar_plain")
        self.assertEqual(ux.categorize_archive(Path("x.tbz"))[0], "tar_bz2")
        self.assertEqual(ux.categorize_archive(Path("x.tb2"))[0], "tar_bz2")
        self.assertEqual(ux.categorize_archive(Path("x.tz"))[0], "tar_gz")

    def test_no_new_extraction_function_for_the_ecosystem_formats(self):
        """These formats reuse `zip` and `tar_plain`: nothing else to write."""
        ecosystem_categories = {
            ux.CATEGORY_BY_EXT[e]
            for e in (".apk", ".aar", ".war", ".ear", ".sar", ".nupkg",
                      ".xpi", ".ipa", ".pyz", ".zipx", ".gem", ".tbz", ".tb2", ".tz")
        }
        self.assertTrue(ecosystem_categories <= {"zip", "tar_plain", "tar_bz2", "tar_gz"})

    def test_an_apk_is_really_extracted_as_a_zip(self):
        source = self._zip("app.apk", members=(("classes/Crypto.java", "AES"),))
        dest = self.dir / "output_apk"
        ux.extract_archive(source, dest)
        self.assertTrue((dest / "classes" / "Crypto.java").is_file())


# ---------------------------------------------------------------------------
# Office containers stay excluded
# ---------------------------------------------------------------------------
class TestOfficeContainerExclusion(_Bench):

    def _document(self, name: str):
        """A realistic office container: an OPC/ODF zip."""
        return self._zip(name, members=(
            ("[Content_Types].xml", "<Types/>"),
            ("word/document.xml", "<w:document/>"),
        ))

    def test_one_format_of_each_family_is_excluded(self):
        for name in ("report.docx", "notes.odt", "old.sxw", "book.epub"):
            with self.subTest(name=name):
                document = self._document(name)
                self.assertEqual(ux.categorize_archive(document), (None, None))
                self.assertFalse(ux.is_archive(document))

    def test_the_exclusion_precedes_any_byte_being_read(self):
        document = self._document("report.docx")
        with mock.patch.object(ux, "categorize_by_content") as spy:
            result = ux.categorize_archive(document)
        spy.assert_not_called()
        self.assertEqual(result, (None, None))

    def test_the_exclusion_announces_itself(self):
        document = self._document("report.docx")
        _, capture = self._capture(ux.categorize_archive, document)
        self.assertEqual(["INFO"], capture.levels)
        self.assertIn("report.docx", capture.messages)

    def test_the_exclusion_does_not_overflow_onto_an_ordinary_zip(self):
        ordinary = self._zip("package.zip")
        self.assertTrue(ux.is_archive(ordinary))
        self.assertEqual(ux.categorize_archive(ordinary)[0], "zip")

    def test_a_nested_office_document_is_not_flattened(self):
        root = self.dir / "tree"
        root.mkdir()
        (root / "code.c").write_text("int a;", encoding="utf-8")
        with zipfile.ZipFile(root / "manual.docx", "w") as z:
            z.writestr("word/document.xml", "<w:document/>")

        self._capture(ux.flatten_nested_archives, root)

        # The directory to forbid is `manual.docx`, the name of the container
        # itself: under the naming scheme in force it is what flattening WOULD
        # produce. The assertion used to read `manual_extracted`, a name nothing
        # can produce any more -- green while testing nothing at all.
        self.assertFalse((root / "manual.docx").is_dir())
        self.assertTrue((root / "manual.docx").is_file())
        self.assertNotIn("document.xml", [p.name for p in root.rglob("*")])

    def test_the_list_covers_the_four_announced_families(self):
        for ext in (".docx", ".xlsx", ".pptx",       # OOXML
                    ".odt", ".ods", ".odp",          # ODF
                    ".sxw", ".sxc", ".sdw",          # StarOffice
                    ".epub"):                        # EPUB
            with self.subTest(ext=ext):
                self.assertIn(ext, ux.NOT_EXTRACTED_EXTENSIONS)

    def test_no_excluded_extension_is_also_a_category(self):
        """An extension cannot be both excluded and extracted."""
        collision = set(ux.NOT_EXTRACTED_EXTENSIONS) & set(ux.CATEGORY_BY_EXT)
        self.assertEqual(collision, set())

    def test_a_file_named_literally_docx_stays_excluded(self):
        """`Path.suffix` returns "" for a file whose FULL NAME is ".docx" (no
        stem), which bypassed the exclusion policy as long as the test was on
        `.suffix` rather than on `name.endswith(ext)`, like step (2)."""
        bare = self._document(".docx")
        self.assertEqual(ux.categorize_archive(bare), (None, None))
        self.assertFalse(ux.is_archive(bare))


# ---------------------------------------------------------------------------
# Non-regression
# ---------------------------------------------------------------------------
class TestNonRegression(_Bench):

    def test_the_47_original_entries_keep_their_category(self):
        for ext, category in CATEGORY_BY_EXT_ORIGIN.items():
            with self.subTest(ext=ext):
                self.assertEqual(ux.CATEGORY_BY_EXT.get(ext), category)

    def test_none_of_the_47_original_entries_disappeared(self):
        missing = set(CATEGORY_BY_EXT_ORIGIN) - set(ux.CATEGORY_BY_EXT)
        self.assertEqual(missing, set())

    def test_the_fallback_branch_of_extract_archive_survives(self):
        """Kept for library use, neither removed nor extended."""
        import inspect
        source = inspect.getsource(ux.extract_archive)
        self.assertIn("zipfile.is_zipfile", source)
        self.assertIn("tarfile.is_tarfile", source)

    def test_every_declared_category_is_handled(self):
        """No category of the table may fall into the final fallback.

        CAUTION: this guard compares the VALUES of `CATEGORY_BY_EXT` against the
        SOURCE of `extract_archive`. Both sides were translated together, so on
        its own it would stay green while proving nothing about faithfulness to
        the original. What really holds the table is the equivalence proof in
        `transport/`. This test keeps its own, narrower value: it catches a
        category added to the table and forgotten in the dispatch chain."""
        import inspect
        source = inspect.getsource(ux.extract_archive)
        for category in set(ux.CATEGORY_BY_EXT.values()):
            with self.subTest(category=category):
                self.assertTrue(
                    category in source or category in ux.NATIVE_TAR_MODES,
                    f"category '{category}' is not handled by extract_archive()",
                )


# ---------------------------------------------------------------------------
# Names kept: the directory carries the archive name verbatim, the decompressed
# file its natural name
# ---------------------------------------------------------------------------
class TestNamesAreKept(_Bench):
    """The extraction directory of a nested archive is `archive.name`, verbatim.

    Two archives sharing a base name but not an extension used to strip to the
    same directory and merge their content behind a single warning. They now
    land in two directories that cannot collide, because a file name is unique
    in its own parent.
    """

    def _tree(self) -> Path:
        root = self.dir / "tree"
        root.mkdir()
        return root

    def _zip_at(self, path: Path, members=(("code/aes.c", "int a;"),)) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(path, "w") as z:
            for arcname, content in members:
                z.writestr(arcname, content)
        return path

    def _tar_gz_at(self, path: Path, members=(("src/sha.c", "int b;"),)) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(path, "w:gz") as t:
            for arcname, content in members:
                payload = content.encode("utf-8")
                info = tarfile.TarInfo(arcname)
                info.size = len(payload)
                t.addfile(info, io.BytesIO(payload))
        return path

    def _gzip_at(self, path: Path, content=b"int key = 42;") -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        with gzip.open(path, "wb") as f:
            f.write(content)
        return path

    def test_the_directory_carries_the_full_archive_name_extension_included(self):
        root = self._tree()
        self._zip_at(root / "toto.jar")
        self._capture(ux.flatten_nested_archives, root)

        self.assertTrue((root / "toto.jar").is_dir())
        self.assertTrue((root / "toto.jar" / "code" / "aes.c").is_file())
        self.assertFalse((root / "toto").exists())
        self.assertFalse((root / "toto_extracted").exists())

    def test_the_case_of_the_archive_name_is_not_transformed(self):
        """The name is INHERITED from the input, never rebuilt from it."""
        root = self._tree()
        self._zip_at(root / "MixedCase.JAR")
        self._capture(ux.flatten_nested_archives, root)

        produced = [p.name for p in root.iterdir() if p.is_dir()]
        self.assertEqual(["MixedCase.JAR"], produced)

    def test_a_double_extension_produces_one_directory_not_two_nested(self):
        """`.tar.gz` is read in a single pass by `tarfile`: no intermediate
        `.tar` is ever written, so no `toto.tar.gz/toto.tar/` can appear."""
        root = self._tree()
        self._tar_gz_at(root / "toto.tar.gz")
        self._capture(ux.flatten_nested_archives, root)

        self.assertTrue((root / "toto.tar.gz" / "src" / "sha.c").is_file())
        self.assertFalse((root / "toto.tar.gz" / "toto.tar").exists())

    def test_two_archives_of_the_same_stem_no_longer_merge(self):
        """The collision this whole naming scheme exists to remove."""
        root = self._tree()
        self._zip_at(root / "toto.jar", members=(("from_jar.c", "int j;"),))
        self._zip_at(root / "toto.zip", members=(("from_zip.c", "int z;"),))
        _, capture = self._capture(ux.flatten_nested_archives, root)

        self.assertTrue((root / "toto.jar" / "from_jar.c").is_file())
        self.assertTrue((root / "toto.zip" / "from_zip.c").is_file())
        self.assertFalse((root / "toto.jar" / "from_zip.c").exists())
        self.assertFalse((root / "toto.zip" / "from_jar.c").exists())
        self.assertNotIn("already holds", capture.messages)

    def test_the_produced_directory_is_not_rediscovered_as_an_archive(self):
        """`is_archive()` returns True for a DIRECTORY named `toto.jar` -- it
        tests the name, not the kind of node. The `p.is_file()` predicate of
        the search is the ONLY thing standing between this naming scheme and an
        endless rediscovery, so it is pinned here rather than assumed."""
        root = self._tree()
        self._zip_at(root / "toto.jar")
        self._capture(ux.flatten_nested_archives, root)

        produced = root / "toto.jar"
        self.assertTrue(produced.is_dir())
        self.assertTrue(ux.is_archive(produced),
                        "were this False, the assertion below would pass for "
                        "the wrong reason and the predicate could be dropped")

        _, capture = self._capture(ux.flatten_nested_archives, root)
        self.assertNotIn("nested archive(s) found", capture.messages)

    def test_a_nested_plain_gzip_yields_its_natural_name_inside_that_directory(self):
        """The trajectory no test covered: the two plain-compression tests of
        this suite call `extract_archive` directly and never assert a name."""
        root = self._tree()
        self._gzip_at(root / "notes.txt.gz", b"clear text")
        self._capture(ux.flatten_nested_archives, root)

        self.assertTrue((root / "notes.txt.gz").is_dir())
        self.assertEqual(b"clear text",
                         (root / "notes.txt.gz" / "notes.txt").read_bytes())
        self.assertFalse((root / "notes.txt_extracted").exists())
        self.assertFalse((root / "notes.txt.gz_extracted").exists())


# ---------------------------------------------------------------------------
# The one name unboxr fabricates, and the shape it has to keep
# ---------------------------------------------------------------------------
class TestTheFabricatedDecompressedName(_Bench):

    # The five degenerate names named by the contract, plus `.bz`, which the
    # table treats identically. Each with the compressor that writes it.
    DEGENERATE_ARCHIVES = ((".gz", gzip.open), (".pack.gz", gzip.open),
                           (".lzma", lzma.open), (".xz", lzma.open),
                           (".bz2", bz2.open), (".bz", bz2.open))

    def test_the_fabricated_name_matches_no_recognised_extension(self):
        """Accidental until it was measured, a requirement from now on.

        A payload named after a recognised extension would be re-detected as an
        archive at the next level, fail to extract, and be reported as an
        amputation that never happened. `.gz` is `is_archive() == True`;
        `.gz_decompressed` is not, and that is the whole reason for the suffix.

        The name is OBSERVED on the file the extractor writes, never recomputed
        here: a test that rebuilt the name from the same formula as the module
        would stay green on any change of that formula.
        """
        for extension, opener in self.DEGENERATE_ARCHIVES:
            with self.subTest(extension=extension):
                degenerate = self.dir / extension
                with opener(degenerate, "wb") as f:
                    f.write(b"payload, not an archive")
                self.assertTrue(
                    ux.is_archive(degenerate),
                    "the degenerate case this test is built on has moved")

                dest = self.dir / f"out{extension}"
                ux.extract_archive(degenerate, dest)
                produced = [p for p in dest.iterdir() if p.is_file()]
                self.assertEqual(1, len(produced))

                name = produced[0].name
                matched = [e for e in ux.SORTED_EXTENSIONS if name.lower().endswith(e)]
                self.assertEqual([], matched,
                                 f"'{name}' would be re-detected as an archive")
                self.assertFalse(ux.is_archive(produced[0]))

    def test_the_module_states_why_the_fabricated_name_has_that_shape(self):
        """A future tidy-up of the name would silently reintroduce the false
        amputation, so the motive lives next to the code, not only here."""
        import inspect
        source = inspect.getsource(ux)
        self.assertIn("_decompressed", source)
        self.assertIn("must match no extension of CATEGORY_BY_EXT", source)


# ---------------------------------------------------------------------------
# The provisional name: its guard, and the two paths on which it survives
# ---------------------------------------------------------------------------
class TestTheProvisionalName(_Bench):
    """Extract under a provisional name, remove the archive, rename.

    Each of the three steps can fail, and none of the three failures is an
    amputation of the corpus: the content is on disk in all of them. They are
    announced anyway, and what they announce is WHERE the content actually is.
    """

    def _tree(self) -> Path:
        root = self.dir / "tree"
        root.mkdir()
        return root

    def _zip_at(self, path: Path, members=(("code/aes.c", "int a;"),)) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(path, "w") as z:
            for arcname, content in members:
                z.writestr(arcname, content)
        return path

    def test_a_reused_workspace_can_land_on_a_populated_provisional_directory(self):
        """The ONLY collision this scheme leaves open, and the reason the guard
        moved rather than went away.

        The FINAL name cannot collide: it is the archive's own path, which no
        other node can hold while the archive is there. The PROVISIONAL name
        can. It is deterministic by design, and the ledger that stops an archive
        being offered twice is local to one call -- so a directory left under
        that name by an earlier run over the same workspace is met again, and
        the two contents mix.

        MEASURED, and it narrows the route rather than the risk: a run whose
        rename SUCCEEDED leaves no provisional directory and, better still,
        leaves the final one holding the member's own name -- so a plain re-run
        over that workspace no longer reaches this guard at all, it fails at the
        first level instead. What reaches the guard is a workspace where an
        earlier run's rename FAILED, which is exactly the path on which the
        provisional name became definitive.
        """
        root = self._tree()
        self._zip_at(root / "pkg.zip")
        provisional = ux._provisional_extraction_name(root / "pkg.zip", root)

        def refuse_rename(self, *args, **kwargs):
            raise OSError("rename refused by the file system")

        with mock.patch.object(Path, "rename", refuse_rename):
            self._capture(ux.flatten_nested_archives, root)
        self.assertTrue((root / provisional).is_dir(),
                        "the run must leave the provisional directory behind, "
                        "or this test proves nothing")

        # The workspace is reused: the archive is back at the same relative
        # path, and it can be, since the final name was never taken.
        self._zip_at(root / "pkg.zip", members=(("code/other.c", "int b;"),))
        _, capture = self._capture(ux.flatten_nested_archives, root)

        self.assertIn("already holds content", capture.messages)
        self.assertIn("earlier run over this workspace", capture.messages)
        self.assertIn("pkg.zip", capture.messages)

    def test_the_guard_survives_a_provisional_path_that_is_not_a_directory(self):
        """The guard sits OUTSIDE every `try`: an exception raised here would
        abort the whole flattening and leave every remaining archive unopened
        without a record. A plain file sitting at the provisional path used to
        be the way to raise one."""
        root = self._tree()
        archive = self._zip_at(root / "pkg.zip")
        blocker = root / ux._provisional_extraction_name(archive, root)
        blocker.write_text("not a directory", encoding="utf-8")
        self._zip_at(root / "second.zip", members=(("code/b.c", "int b;"),))

        _, capture = self._capture(ux.flatten_nested_archives, root)

        # The first archive fails -- and IS reported as an amputation, because
        # its content really did not reach the tree. The second one, which the
        # aborted run would have swallowed in silence, is extracted.
        self.assertIn("is NOT in the extracted tree", capture.messages)
        self.assertTrue((root / "second.zip" / "code" / "b.c").is_file())

    def test_an_archive_that_cannot_be_removed_says_where_its_content_is(self):
        """The rename is skipped here -- its target is the archive that could
        not be removed -- so the content stays under the provisional name, and
        the message has to name THAT, not a directory that does not exist."""
        root = self._tree()
        archive = self._zip_at(root / "locked.zip")
        provisional = ux._provisional_extraction_name(archive, root)

        def refuse_unlink(self, *args, **kwargs):
            raise OSError("held by another process")

        with mock.patch.object(Path, "unlink", refuse_unlink):
            _, capture = self._capture(ux.flatten_nested_archives, root)

        self.assertIn("could not be removed", capture.messages)
        self.assertIn(provisional, capture.messages)
        self.assertIn("IS in the extracted tree", capture.messages)
        self.assertTrue((root / provisional / "code" / "aes.c").is_file())
        self.assertTrue((root / "locked.zip").is_file())

    def test_a_rename_that_fails_leaves_the_content_under_a_declared_name(self):
        """The one path on which the provisional name becomes the definitive
        one -- and the reason it is a digest rather than a temporary directory.
        Not an amputation: the content is whole, only its name is not the one
        asked for."""
        root = self._tree()
        archive = self._zip_at(root / "pkg.zip")
        provisional = ux._provisional_extraction_name(archive, root)

        def refuse_rename(self, *args, **kwargs):
            raise OSError("rename refused by the file system")

        with mock.patch.object(Path, "rename", refuse_rename):
            _, capture = self._capture(ux.flatten_nested_archives, root)

        self.assertIn("could not be renamed", capture.messages)
        self.assertIn("IS in the extracted tree", capture.messages)
        self.assertTrue((root / provisional / "code" / "aes.c").is_file())
        self.assertFalse((root / "pkg.zip").exists())

    def test_a_failed_extraction_is_still_an_amputation_and_the_recap_says_so(self):
        """The two ledgers stay two. An archive that could not be OPENED is an
        amputation; one that could not be removed, or renamed, is not."""
        root = self._tree()
        broken = root / "broken.zip"
        broken.write_bytes(b"PK\x03\x04 truncated, not a zip at all")

        _, capture = self._capture(ux.flatten_nested_archives, root)

        self.assertIn("is NOT in the extracted tree", capture.messages)
        self.assertIn("were left unopened", capture.messages)
        self.assertTrue(broken.is_file())

    def test_an_archive_left_in_place_is_not_offered_again_at_every_level(self):
        """The ledger holds ARCHIVE paths, never the transient directories this
        scheme now multiplies. Without it a failing archive is re-discovered and
        re-announced once per level, up to ten times."""
        root = self._tree()
        broken = root / "broken.zip"
        broken.write_bytes(b"PK\x03\x04 truncated, not a zip at all")

        _, capture = self._capture(ux.flatten_nested_archives, root)

        failures = [record for record in capture.records
                    if "Extraction of" in record.getMessage()]
        self.assertEqual(1, len(failures))

    def test_a_reused_workspace_does_not_silently_discard_a_prior_flattening(self):
        """The route ONE LEVEL UP from the guard above: not a second run of
        `flatten_nested_archives` itself, but a second top-level extraction
        (`prepare_source`'s own `extract_archive` call) over a workspace where
        an earlier flattening pass already renamed a nested archive to its own
        verbatim name (`archive.name`, AC-1). A raw, not-yet-opened tar member
        of that name can then land on a directory -- exactly the shape of
        collision `_extract_tar_with_checks`'s merge logic silently discarded
        before this correction (measured in code review, story 14.2 of the
        upstream project, crypto-scan)."""
        root = self._tree()
        self._zip_at(root / "pkg.zip", members=(("code/aes.c", "int a;"),))
        self._capture(ux.flatten_nested_archives, root)
        self.assertTrue((root / "pkg.zip" / "code" / "aes.c").is_file(),
                        "the first flattening must have produced the "
                        "directory this test collides with, or it proves "
                        "nothing")

        # A second, unrelated top-level tar container carrying a raw member
        # literally named `pkg.zip` -- not the archive from the first run,
        # nothing that opens it is exercised here, only the collision on the
        # path `pkg.zip` inside `root`.
        outer = self.dir / "outer.tar"
        with tarfile.open(outer, "w") as t:
            payload = b"not the same pkg.zip, unopened raw bytes"
            info = tarfile.TarInfo("pkg.zip")
            info.size = len(payload)
            t.addfile(info, io.BytesIO(payload))

        _, capture = self._capture(ux.extract_archive, outer, root)

        self.assertIn("already held content as a directory", capture.messages)
        self.assertIn("pkg.zip", capture.messages)
        self.assertTrue((root / "pkg.zip").is_file(),
                        "the raw member DOES replace the stale directory -- "
                        "this is a declared replacement, not a refusal, and "
                        "the previously-flattened content is gone with it")

    def test_a_preexisting_empty_final_directory_is_declared_not_silently_replaced(self):
        """`Path.rename()` alone would replace an EMPTY directory silently on
        POSIX while raising on Windows for the identical precondition -- an
        explicit `final_dest.exists()` check makes both platforms declare the
        same way instead of one of them staying silent. Measured in code
        review, story 14.2 of the upstream project, crypto-scan."""
        root = self._tree()
        archive = self._zip_at(root / "pkg.zip")
        real_unlink = Path.unlink

        def unlink_then_race_an_empty_directory_in(self, *args, **kwargs):
            real_unlink(self, *args, **kwargs)
            if self == archive:
                # Simulates something else recreating an empty directory at
                # the archive's own path between the unlink above and the
                # rename below -- the only way `final_dest` can be occupied
                # there, since the archive itself held that path until now.
                self.mkdir()

        with mock.patch.object(Path, "unlink", unlink_then_race_an_empty_directory_in):
            _, capture = self._capture(ux.flatten_nested_archives, root)

        self.assertIn("could not be renamed", capture.messages)
        provisional = ux._provisional_extraction_name(archive, root)
        self.assertTrue((root / provisional / "code" / "aes.c").is_file())
        self.assertTrue((root / "pkg.zip").is_dir())
        self.assertEqual([], list((root / "pkg.zip").iterdir()),
                         "a silent native rename would have moved the "
                         "extracted content in here instead")

    def test_an_archive_already_gone_before_unlink_still_gets_renamed(self):
        """`archive.unlink()` raising `FileNotFoundError` -- external
        interference already removed it -- must not be treated like a real
        removal failure: nothing blocks completing the rename, and reporting
        "the archive is kept" would be false. Measured in code review, story
        14.2 of the upstream project, crypto-scan."""
        root = self._tree()
        archive = self._zip_at(root / "pkg.zip")
        real_unlink = Path.unlink

        def unlink_reports_already_gone(self, *args, **kwargs):
            # The file really is removed -- as external interference would
            # have left it -- but the call itself reports `FileNotFoundError`
            # rather than the ordinary success `archive.unlink()` expects.
            if self == archive:
                real_unlink(self, *args, **kwargs)
                raise FileNotFoundError(f"already removed: {self}")
            return real_unlink(self, *args, **kwargs)

        with mock.patch.object(Path, "unlink", unlink_reports_already_gone):
            _, capture = self._capture(ux.flatten_nested_archives, root)

        self.assertNotIn("could not be removed", capture.messages)
        self.assertTrue((root / "pkg.zip" / "code" / "aes.c").is_file())


# ---------------------------------------------------------------------------
# Level 0, story 14.8: the three modes `prepare_source` now offers, and the
# single point (`resolve_extraction_root`) that computes where each one lands
# -- reused by `unboxr.cli` rather than recomputed there (AC-1.4).
# ---------------------------------------------------------------------------
class TestLevelZeroThreeModes(_Bench):

    def test_resolve_extraction_root_is_the_single_point_for_all_three_modes(self):
        """AC-1.4. Touches no file system: a caller deciding where the tree
        will land must be able to ask before the archive, or even the
        destination, exists."""
        workspace = self.dir / "out"
        self.assertEqual(workspace / "toto.jar",
                         ux.resolve_extraction_root("toto.jar", workspace))
        self.assertEqual(workspace,
                         ux.resolve_extraction_root("toto.jar", workspace,
                                                    no_archive_dir=True))
        self.assertEqual(Path("toto.jar"),
                         ux.resolve_extraction_root("toto.jar", workspace,
                                                    replace=True))
        # `replace=True` ignores `workspace` entirely -- consistent with
        # `unboxr.cli` refusing DESTINATION alongside `--replace` (AC-3.2).
        self.assertEqual(Path("toto.jar"),
                         ux.resolve_extraction_root("toto.jar", None,
                                                    replace=True))

    def test_resolve_archive_name_does_not_touch_the_network_for_a_url(self):
        """The same rule `download_source` applies internally, repeated
        rather than reinvented, so a caller can learn the name BEFORE
        downloading anything."""
        self.assertEqual(
            "pkg.tar.gz",
            ux.resolve_archive_name("https://example.invalid/dir/pkg.tar.gz"))
        self.assertEqual(
            "downloaded_archive",
            ux.resolve_archive_name("https://example.invalid/"))
        self.assertEqual("toto.jar", ux.resolve_archive_name("toto.jar"))

    def test_the_default_mode_names_the_root_after_the_archive(self):
        """AC-1: the retired `extracted` is gone, the root now carries the
        archive's own name, verbatim."""
        archive = self._zip("pkg.zip")
        prepared = ux.prepare_source(str(archive), workspace=self.dir / "out")

        self.assertEqual(self.dir / "out" / "pkg.zip", prepared.tree)
        self.assertTrue((prepared.tree / "code" / "aes.c").is_file())

    def test_no_archive_dir_extracts_straight_into_the_workspace(self):
        """AC-4.1: no wrapper directory, the tree IS the workspace itself."""
        archive = self._zip("pkg.zip")
        workspace = self.dir / "out"
        prepared = ux.prepare_source(str(archive), workspace=workspace,
                                     no_archive_dir=True)

        self.assertEqual(workspace, prepared.tree)
        self.assertTrue((workspace / "code" / "aes.c").is_file())

    def test_replace_extracts_in_place_and_removes_the_archive(self):
        """AC-3.1: the archive becomes its own directory, on the same path --
        exactly what `unboxr` already does to a nested archive, reused here
        rather than reinvented (AC-5)."""
        archive = self._zip("pkg.zip")

        prepared = ux.prepare_source(str(archive), replace=True)

        self.assertEqual(archive, prepared.tree)
        self.assertTrue((archive / "code" / "aes.c").is_file())
        self.assertFalse(archive.is_file(),
                         "the archive must be gone: it was replaced by its "
                         "own extracted content")

    def test_replace_never_removes_the_archive_on_a_failed_extraction(self):
        """AC-3.6, and the mutation-critical half of it: the archive is
        removed ONLY after a successful extraction. Reproduced BEFORE the
        correction existed by reading the code path -- `extract_archive`
        raises before `local_path.unlink()` is ever reached -- and validated
        here by observing the archive survive a genuine failure."""
        broken = self.dir / "broken.zip"
        broken.write_bytes(b"PK\x03\x04 truncated, not a zip at all")

        with self.assertRaises(Exception):
            ux.prepare_source(str(broken), replace=True)

        self.assertTrue(broken.is_file(),
                        "a failed extraction must leave the archive in place")

    def test_replace_falls_back_to_the_provisional_name_when_the_rename_fails(self):
        """The SAME non-guarantee the nested case already carries (AC-5.4):
        the tree returned is the one ACTUALLY obtained, not the one that was
        intended, when the rename onto the archive's own vacated path fails."""
        archive = self._zip("pkg.zip")
        provisional = self.dir / ux._provisional_name_at_level_zero(archive)

        def refuse_rename(self, *args, **kwargs):
            raise OSError("rename refused by the file system")

        with mock.patch.object(Path, "rename", refuse_rename):
            prepared = ux.prepare_source(str(archive), replace=True)

        self.assertEqual(provisional, prepared.tree)
        self.assertTrue((provisional / "code" / "aes.c").is_file())
        self.assertFalse(archive.exists(),
                         "the archive was already removed before the rename "
                         "was attempted")

    def test_a_url_under_the_default_mode_consumes_the_downloaded_copy(self):
        """AC-5.2 (D-C): the destination the default mode targets IS, by
        construction, the exact path `download_source` just wrote the
        archive to -- so it is consumed the same way a nested archive is,
        and DESTINATION ends up holding only the tree."""
        workspace = self.dir / "out"

        def fake_download(source, dest_dir):
            return self._zip_at_dir(dest_dir, "pkg.zip")

        with mock.patch.object(ux, "download_source", fake_download):
            prepared = ux.prepare_source("https://example.invalid/pkg.zip",
                                         workspace=workspace)

        self.assertEqual(workspace / "pkg.zip", prepared.tree)
        self.assertTrue((prepared.tree / "code" / "aes.c").is_file())
        self.assertEqual(["pkg.zip"],
                         [p.name for p in workspace.iterdir()],
                         "the downloaded copy must not linger beside the tree")

    def test_a_url_under_no_archive_dir_also_consumes_the_downloaded_copy(self):
        """The same consumption, in the mode where there is no rename dance
        to fold it into: extracted directly into the workspace, then the
        download is removed so it is not re-discovered as a nested archive
        of itself."""
        workspace = self.dir / "out"

        def fake_download(source, dest_dir):
            return self._zip_at_dir(dest_dir, "pkg.zip")

        with mock.patch.object(ux, "download_source", fake_download):
            prepared = ux.prepare_source("https://example.invalid/pkg.zip",
                                         workspace=workspace, no_archive_dir=True)

        self.assertEqual(workspace, prepared.tree)
        self.assertTrue((workspace / "code" / "aes.c").is_file())
        self.assertFalse((workspace / "pkg.zip").exists())

    def _zip_at_dir(self, dest_dir: Path, name: str) -> Path:
        dest_dir.mkdir(parents=True, exist_ok=True)
        path = dest_dir / name
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("code/aes.c", "int a;")
        return path


if __name__ == "__main__":
    unittest.main(verbosity=2)
