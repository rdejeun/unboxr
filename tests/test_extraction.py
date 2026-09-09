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

        self.assertFalse((root / "manual_extracted").exists())
        self.assertTrue((root / "manual.docx").exists())
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
