"""The chain fills the report while it extracts, never by walking the tree.

WHY THIS FILE IS SEPARATE FROM `test_report.py`. That one holds what the report
IS -- its vocabulary, its filing rules, its capability profile -- with no
extraction anywhere near it. This one holds what the CHAIN PUTS IN IT, which
needs real archives, real failures and a real flattening loop.

THE ONE PROPERTY THAT CANNOT BE FAKED. A container is recorded AT THE POINT IT
IS OPENED, not by walking the finished tree afterwards. Flattening REMOVES a
nested archive once it has been extracted, and the directory that replaces it
carries the archive's own name verbatim: a container that was opened no longer
exists as a file. A test below asserts exactly that -- the record is there, the
file is not -- which no after-the-fact walk could ever produce.

100% offline, standard library only: no network, no 7-Zip binary, no versioned
fixture. The 7-Zip binary IS present on some machines and absent on others, so
every test that needs one state or the other MOCKS the probe rather than
reading the machine it happens to run on.
"""

from __future__ import annotations

import ast
import io
import shutil
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import unboxr.extraction as ux  # noqa: E402
from unboxr import report as rp  # noqa: E402

ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


class _Bench(unittest.TestCase):
    """Builds its own fixtures: no binary is versioned in this repository."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="test_chain_report_"))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    def _zip_at(self, path: Path, members=(("code/aes.c", "int a;"),)) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(path, "w") as archive:
            for arcname, content in members:
                archive.writestr(arcname, content)
        return path

    def _office_bytes(self) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("word/document.xml", "<w:document/>")
        return buffer.getvalue()

    def _tree(self) -> Path:
        root = self.dir / "tree"
        root.mkdir()
        return root

    def _codes(self, entries) -> set:
        return {entry.code for entry in entries}

    def _paths(self, entries, code: str) -> set:
        return {entry.path for entry in entries if entry.code == code}


# ---------------------------------------------------------------------------
# The report is a RETURNED value, on every path out
# ---------------------------------------------------------------------------
class TestTheReportIsReturned(_Bench):

    def test_the_three_existing_pieces_keep_exactly_their_meaning(self):
        """The arity changes; the semantics of what was already there must not.
        The tree, the distribution nature, and the BARE hexadecimal digest of
        the input."""
        archive = self._zip_at(self.dir / "pkg.whl")
        prepared = ux.prepare_source(str(archive), workspace=self.dir / "ws")

        self.assertEqual(self.dir / "ws" / "pkg.whl", prepared.tree)
        self.assertEqual("built", prepared.nature)
        self.assertEqual(64, len(prepared.digest))
        self.assertNotIn(":", prepared.digest)
        self.assertTrue((prepared.tree / "code" / "aes.c").is_file())

    def test_the_report_is_a_named_field_and_not_a_fourth_tuple_slot(self):
        """"A report whose field cannot be omitted" reads literally: a field
        has a name. Three positional pieces already read badly; a fourth, and
        the fifth a later story adds, would read worse."""
        archive = self._zip_at(self.dir / "pkg.zip")
        prepared = ux.prepare_source(str(archive), workspace=self.dir / "ws")

        self.assertIsInstance(prepared.report, rp.ExtractionReport)
        with self.assertRaises(TypeError):
            _tree, _nature, _digest = prepared

    def test_a_directory_source_returns_an_empty_report_and_never_none(self):
        """The early return extracts nothing, so the report is EMPTY -- and it
        is still there. An omission asserts: a missing report would read "not
        applicable" where the truth is "nothing was refused"."""
        source = self._tree()
        (source / "a.c").write_text("int a;", encoding="utf-8")

        prepared = ux.prepare_source(str(source))

        self.assertEqual("directory", prepared.nature)
        self.assertIsNone(prepared.digest)
        self.assertIsInstance(prepared.report, rp.ExtractionReport)
        self.assertEqual([], prepared.report.not_opened)
        self.assertEqual([], prepared.report.opened)
        self.assertEqual(0, prepared.report.amputation_count())

    def test_a_report_passed_in_survives_the_raise_that_ends_the_run(self):
        """THE reason the parameter exists alongside the return value. An
        office container given as the source is refused -- the most frequent
        amputation there is -- and THEN the run fails, with no value to return.
        A caller holding its own report still learns what was lost."""
        office = self.dir / "manual.docx"
        office.write_bytes(self._office_bytes())
        held = ux.new_report()

        with self.assertRaises(ValueError):
            ux.prepare_source(str(office), workspace=self.dir / "ws",
                              report=held)

        self.assertEqual(1, held.amputation_count())
        self.assertEqual({rp.OFFICE_CONTAINER_EXCLUDED},
                         self._codes(held.not_opened))
        self.assertEqual({"manual.docx"},
                         self._paths(held.not_opened,
                                     rp.OFFICE_CONTAINER_EXCLUDED))

    def test_a_top_level_extraction_failure_reaches_the_report_before_it_raises(self):
        """The first-level container is extracted OUTSIDE the flattening loop,
        where no `except` used to stand. Without one, the single most visible
        amputation of all -- the source itself -- reached no report."""
        broken = self.dir / "root.tar.zst"
        broken.write_bytes(ZSTD_MAGIC + b"undecodable")
        held = ux.new_report()

        with self.assertRaises(RuntimeError):
            ux.prepare_source(str(broken), workspace=self.dir / "ws",
                              report=held)

        self.assertEqual({rp.ZSTD_NOT_SUPPORTED}, self._codes(held.not_opened))
        self.assertEqual({"root.tar.zst"},
                         self._paths(held.not_opened, rp.ZSTD_NOT_SUPPORTED))

    def test_the_report_the_caller_passes_in_is_the_one_it_gets_back(self):
        archive = self._zip_at(self.dir / "pkg.zip")
        held = ux.new_report()
        prepared = ux.prepare_source(str(archive), workspace=self.dir / "ws",
                                     report=held)
        self.assertIs(held, prepared.report)


# ---------------------------------------------------------------------------
# Containers opened: recorded while they still exist
# ---------------------------------------------------------------------------
class TestContainersOpened(_Bench):

    def test_the_container_the_caller_handed_over_is_recorded_at_level_zero(self):
        """It is extracted outside the flattening loop. A recensement living
        only inside that loop would miss the one container the user named."""
        archive = self._zip_at(self.dir / "pkg.zip")
        prepared = ux.prepare_source(str(archive), workspace=self.dir / "ws")

        opened = prepared.report.opened
        self.assertEqual([rp.INPUT_CONTAINER_OPENED],
                         [entry.code for entry in opened])
        self.assertEqual("pkg.zip", opened[0].path)
        self.assertEqual(0, opened[0].level)

    def test_a_nested_container_is_recorded_although_it_no_longer_exists(self):
        """The property no walk of the finished tree could reproduce, and the
        whole reason the collection is instrumented INSIDE the chain: a nested
        archive is REMOVED once it is extracted, and the directory that takes
        its place carries its name verbatim."""
        root = self._tree()
        self._zip_at(root / "inner.jar")
        held = ux.new_report()

        ux.flatten_nested_archives(root, report=held)

        self.assertEqual({"inner.jar"},
                         self._paths(held.opened, rp.NESTED_CONTAINER_OPENED))
        self.assertFalse((root / "inner.jar").is_file(),
                         "if the archive were still a file, a walk of the tree "
                         "could have produced this record and the test would "
                         "prove nothing")
        self.assertTrue((root / "inner.jar").is_dir())

    def test_a_recorded_path_is_posix_relative_and_never_absolute(self):
        """Guarantee 3 of the determinism contract, applied to the report. A
        native separator here would reopen the first of the two inter-platform
        divergences this package keeps closed."""
        root = self._tree()
        self._zip_at(root / "vendor" / "sub" / "inner.zip")
        held = ux.new_report()

        ux.flatten_nested_archives(root, report=held)

        self.assertEqual({"vendor/sub/inner.zip"},
                         self._paths(held.opened, rp.NESTED_CONTAINER_OPENED))
        for entry in held.opened:
            with self.subTest(path=entry.path):
                self.assertNotIn("\\", entry.path)
                self.assertFalse(Path(entry.path).is_absolute())

    def test_the_level_a_container_was_met_at_is_recorded(self):
        root = self._tree()
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as archive:
            archive.writestr("deep/code.c", "int a;")
        self._zip_at(root / "outer.zip", members=(("inner.zip", inner.getvalue()),))
        held = ux.new_report()

        ux.flatten_nested_archives(root, report=held)

        levels = {entry.path: entry.level for entry in held.opened}
        self.assertEqual(1, levels["outer.zip"])
        self.assertEqual(2, levels["outer.zip/inner.zip"])


# ---------------------------------------------------------------------------
# Refused is not failed
# ---------------------------------------------------------------------------
class TestRefusedIsNotFailed(_Bench):

    def test_a_recognised_refusal_and_a_read_failure_are_two_states(self):
        """The contract enumerates them separately, and they say different
        things: "this tool does not open this format" against "this archive
        could not be read". Both used to arrive as a bare RuntimeError through
        one generic handler, under one code."""
        root = self._tree()
        (root / "refused.tar.zst").write_bytes(ZSTD_MAGIC + b"undecodable")
        (root / "broken.zip").write_bytes(b"PK\x03\x04 truncated, not a zip")
        held = ux.new_report()

        ux.flatten_nested_archives(root, report=held)

        self.assertEqual({"refused.tar.zst"},
                         self._paths(held.not_opened, rp.ZSTD_NOT_SUPPORTED))
        self.assertEqual({"broken.zip"},
                         self._paths(held.not_opened, rp.EXTRACTION_FAILED))

    def test_a_refusal_for_want_of_7zip_carries_its_own_code(self):
        """The binary is present on this machine and absent on others, so its
        absence is SIMULATED. A test that read the machine would assert one
        thing here and the opposite elsewhere."""
        root = self._tree()
        (root / "payload.7z").write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 16)
        held = ux.new_report()

        with mock.patch.object(ux, "find_7zip_binary", return_value=None):
            ux.flatten_nested_archives(root, report=held)

        self.assertEqual({"payload.7z"},
                         self._paths(held.not_opened,
                                     rp.SEVEN_ZIP_BINARY_MISSING))

    def test_the_refusal_exception_is_still_caught_by_except_runtime_error(self):
        """The code travels on the exception, and the exception does not change
        its contract: a subclass, so every `except RuntimeError` already written
        against this package keeps working."""
        self.assertTrue(issubclass(ux.UnsupportedFormatError, RuntimeError))
        archive = self.dir / "p.tar.zst"
        archive.write_bytes(ZSTD_MAGIC + b"undecodable")

        with self.assertRaises(RuntimeError) as caught:
            ux.extract_archive(archive, self.dir / "out")
        self.assertEqual(rp.ZSTD_NOT_SUPPORTED, caught.exception.code)

    def test_an_exception_carrying_no_code_falls_back_to_the_generic_failure(self):
        """Explicit, never guessed: a corrupt archive stays a FAILURE. Reading
        it as a refusal would say the tool does not open zip files."""
        root = self._tree()
        (root / "broken.zip").write_bytes(b"PK\x03\x04 truncated, not a zip")
        held = ux.new_report()

        ux.flatten_nested_archives(root, report=held)

        self.assertEqual({rp.EXTRACTION_FAILED}, self._codes(held.not_opened))

    def test_the_refusal_texts_keep_their_positive_only_oracle_reminder(self):
        """The code is added to the message, it does not replace it. What could
        not be opened cannot be reported on."""
        archive = self.dir / "p.tar.zst"
        archive.write_bytes(ZSTD_MAGIC + b"undecodable")
        with self.assertRaises(RuntimeError) as caught:
            ux.extract_archive(archive, self.dir / "out")
        self.assertIn("no conclusion can be drawn from the absence of a "
                      "finding", str(caught.exception))


# ---------------------------------------------------------------------------
# Depth, and the archives left behind
# ---------------------------------------------------------------------------
class TestDepthAndResidualArchives(_Bench):

    def _nested_three_deep(self) -> Path:
        root = self._tree()
        innermost = io.BytesIO()
        with zipfile.ZipFile(innermost, "w") as archive:
            archive.writestr("code/aes.c", "int a;")
        middle = io.BytesIO()
        with zipfile.ZipFile(middle, "w") as archive:
            archive.writestr("third.zip", innermost.getvalue())
        self._zip_at(root / "first.zip",
                     members=(("second.zip", middle.getvalue()),))
        return root

    def test_residual_archives_are_named_when_the_depth_limit_stops_flattening(self):
        """The net gain of this report over the logging message it sits beside.
        That message says archives "may remain unopened" -- a "perhaps", with
        neither list nor count. The archives still present at that instant are
        present BY DEFINITION; reading them there is "during the extraction"."""
        root = self._nested_three_deep()
        held = ux.new_report()

        ux.flatten_nested_archives(root, max_depth=1, report=held)

        self.assertEqual({"first.zip/second.zip"},
                         self._paths(held.not_opened, rp.MAXIMUM_DEPTH_REACHED))
        self.assertEqual(1, held.amputation_count())

    def test_the_other_exit_of_the_loop_names_its_residual_archives_too(self):
        """The "nothing left to find" exit already named them in the log. Each
        one is in the report as the failure it was, recorded when it happened,
        so nothing is left to a closing recap."""
        root = self._tree()
        (root / "broken.zip").write_bytes(b"PK\x03\x04 truncated, not a zip")
        held = ux.new_report()

        ux.flatten_nested_archives(root, report=held)

        self.assertEqual({"broken.zip"},
                         self._paths(held.not_opened, rp.EXTRACTION_FAILED))
        self.assertTrue((root / "broken.zip").is_file())

    def test_the_depth_reached_is_what_was_traversed_and_not_the_bound(self):
        """Two different numbers. Reporting only the bound would say nothing
        about what happened; reporting only the depth reached would hide how
        close to the limit a run came."""
        root = self._nested_three_deep()
        held = ux.new_report()

        ux.flatten_nested_archives(root, max_depth=7, report=held)

        self.assertEqual(7, held.depth_limit)
        self.assertEqual(3, held.depth_reached)

    def test_a_stopped_run_reports_the_bound_it_stopped_at(self):
        root = self._nested_three_deep()
        held = ux.new_report()

        ux.flatten_nested_archives(root, max_depth=1, report=held)

        self.assertEqual(1, held.depth_limit)
        self.assertEqual(1, held.depth_reached)

    def test_a_tree_with_nothing_to_flatten_reports_a_depth_of_zero(self):
        root = self._tree()
        (root / "a.c").write_text("int a;", encoding="utf-8")
        held = ux.new_report()

        ux.flatten_nested_archives(root, report=held)

        self.assertEqual(0, held.depth_reached)
        self.assertEqual(10, held.depth_limit)


# ---------------------------------------------------------------------------
# Containers set aside by policy -- the sixth element of the contract, and the
# most frequent case of all
# ---------------------------------------------------------------------------
class TestContainersSetAsideByPolicy(_Bench):

    def test_an_office_container_is_recorded_with_its_own_code(self):
        root = self._tree()
        (root / "report.docx").write_bytes(self._office_bytes())
        held = ux.new_report()

        ux.flatten_nested_archives(root, report=held)

        self.assertEqual({"report.docx"},
                         self._paths(held.not_opened,
                                     rp.OFFICE_CONTAINER_EXCLUDED))

    def test_one_entry_per_container_and_never_one_per_call(self):
        """`categorize_archive` is reached from four call sites, one of them
        inside the sorted comprehension re-evaluated at EVERY level. A report
        counting calls would announce dozens of amputations for one document.
        The tree below keeps the loop running for several levels, so the office
        container is looked at again and again."""
        root = self._tree()
        (root / "report.docx").write_bytes(self._office_bytes())
        innermost = io.BytesIO()
        with zipfile.ZipFile(innermost, "w") as archive:
            archive.writestr("code/aes.c", "int a;")
        middle = io.BytesIO()
        with zipfile.ZipFile(middle, "w") as archive:
            archive.writestr("third.zip", innermost.getvalue())
        self._zip_at(root / "first.zip",
                     members=(("second.zip", middle.getvalue()),))
        held = ux.new_report()

        ux.flatten_nested_archives(root, report=held)

        docx_entries = [entry for entry in held.not_opened
                        if entry.code == rp.OFFICE_CONTAINER_EXCLUDED]
        self.assertEqual(1, len(docx_entries))
        self.assertEqual(1, held.amputation_count())

    def test_the_count_of_excluded_extensions_is_read_and_never_written(self):
        """Thirty-eight today. The figure lives in the table; a literal here
        would be a second source of truth, and this project has paid for one of
        those twice already."""
        self.assertEqual(len(ux.NOT_EXTRACTED_EXTENSIONS),
                         len(set(ux.NOT_EXTRACTED_EXTENSIONS)))
        self.assertGreater(len(ux.NOT_EXTRACTED_EXTENSIONS), 0)


# ---------------------------------------------------------------------------
# What the corpus GAINS, and what stays in the tree
# ---------------------------------------------------------------------------
class TestWhatIsNotAnAmputation(_Bench):

    def test_the_corpus_widening_is_recorded_and_is_not_an_amputation(self):
        """A corpus that grows without a trace is no better than one that
        shrinks without a trace -- and it is still not a loss."""
        root = self._tree()
        source = self._zip_at(self.dir / "staging" / "pkg.zip")
        shutil.move(str(source), str(root / "opaque.data"))
        held = ux.new_report()

        ux.flatten_nested_archives(root, report=held)

        self.assertEqual({"opaque.data"},
                         self._paths(held.widened, rp.RECOGNISED_BY_CONTENT))
        self.assertEqual(0, held.amputation_count())

    def test_an_archive_extracted_but_not_removable_is_not_an_amputation(self):
        """Its content IS in the extracted tree, under the provisional name.
        Counting it as an amputation would assert a loss that did not happen --
        the exact reason the chain keeps two ledgers rather than one."""
        root = self._tree()
        self._zip_at(root / "locked.zip")
        held = ux.new_report()

        def refuse_unlink(self, *args, **kwargs):
            raise OSError("held by another process")

        with mock.patch.object(Path, "unlink", refuse_unlink):
            ux.flatten_nested_archives(root, report=held)

        self.assertEqual(0, held.amputation_count())
        self.assertEqual({"locked.zip"},
                         self._paths(held.still_in_tree,
                                     rp.ARCHIVE_KEPT_AFTER_SUCCESSFUL_EXTRACTION))
        self.assertEqual({"locked.zip"},
                         self._paths(held.opened, rp.NESTED_CONTAINER_OPENED))

    def test_a_provisional_directory_left_by_an_earlier_run_is_not_an_amputation(self):
        """The third case where the content IS in the tree: two extractions
        mixed under one provisional name. Nothing was lost from THIS run, and
        counting it as an amputation would assert a loss that did not happen --
        the same reason the chain keeps two ledgers rather than one."""
        root = self._tree()
        archive = self._zip_at(root / "pkg.zip")
        provisional = root / ux._provisional_extraction_name(archive, root)
        provisional.mkdir()
        (provisional / "left_by_an_earlier_run.txt").write_text(
            "x", encoding="utf-8")
        held = ux.new_report()

        ux.flatten_nested_archives(root, report=held)

        self.assertEqual(0, held.amputation_count())
        self.assertEqual({"pkg.zip"},
                         self._paths(held.still_in_tree,
                                     rp.PROVISIONAL_DIRECTORY_ALREADY_OCCUPIED))

    def test_an_extraction_that_could_not_be_renamed_is_not_an_amputation(self):
        root = self._tree()
        self._zip_at(root / "pkg.zip")
        held = ux.new_report()

        def refuse_rename(self, *args, **kwargs):
            raise OSError("rename refused")

        with mock.patch.object(Path, "rename", refuse_rename):
            ux.flatten_nested_archives(root, report=held)

        self.assertEqual(0, held.amputation_count())
        self.assertEqual({"pkg.zip"},
                         self._paths(held.still_in_tree,
                                     rp.EXTRACTION_KEPT_UNDER_PROVISIONAL_NAME))


# ---------------------------------------------------------------------------
# The capability profile
# ---------------------------------------------------------------------------
class TestTheCapabilityProfileOfThisMachine(_Bench):

    def test_the_profile_is_in_every_report_including_one_for_a_directory(self):
        """An omission asserts. A profile that only appeared when 7-Zip had
        been needed would read "not applicable" rather than "binary absent"."""
        source = self._tree()
        (source / "a.c").write_text("int a;", encoding="utf-8")

        prepared = ux.prepare_source(str(source))

        self._assert_profile_measures_this_machine(prepared.report.capability)

    def test_the_profile_is_there_when_no_delegated_format_was_ever_met(self):
        archive = self._zip_at(self.dir / "pkg.zip")
        prepared = ux.prepare_source(str(archive), workspace=self.dir / "ws")
        self._assert_profile_measures_this_machine(prepared.report.capability)

    def _assert_profile_measures_this_machine(self, profile):
        """Its PRESENCE is not enough: a profile filled with placeholder counts
        would be present and say nothing. What is asserted is that the counts
        are the table's own."""
        self.assertIsInstance(profile, rp.CapabilityProfile)
        self.assertEqual(len(ux.CATEGORY_BY_EXT), profile.recognised_extensions)
        self.assertEqual(
            sum(1 for category in ux.CATEGORY_BY_EXT.values()
                if category in ux.CATEGORIES_NEEDING_SEVEN_ZIP),
            profile.extensions_needing_seven_zip)

    def test_the_counts_of_the_profile_are_computed_from_the_table(self):
        """Sixty-eight recognised extensions and thirty-one needing 7-Zip on
        the day this was written. Neither figure is written here: this package
        counts them where they are read -- in this profile, and in the listing
        `unboxr --list-formats` prints -- rather than typing them out."""
        profile = ux.probe_capability_profile()
        self.assertEqual(len(ux.CATEGORY_BY_EXT), profile.recognised_extensions)
        self.assertEqual(
            sum(1 for category in ux.CATEGORY_BY_EXT.values()
                if category in ux.CATEGORIES_NEEDING_SEVEN_ZIP),
            profile.extensions_needing_seven_zip)

    def test_the_profile_states_the_binary_it_found_and_not_merely_that_it_did(self):
        """The PATH differs from one machine to the next, and it is what the
        divergence between two corpora hangs on. Simulated in both directions:
        this machine has a binary, another will not."""
        with mock.patch.object(ux, "find_7zip_binary",
                               return_value="/opt/7zip/7zz"):
            found = ux.probe_capability_profile()
        with mock.patch.object(ux, "find_7zip_binary", return_value=None):
            missing = ux.probe_capability_profile()

        self.assertEqual("/opt/7zip/7zz", found.seven_zip_binary)
        self.assertTrue(found.seven_zip_available)
        self.assertIsNone(missing.seven_zip_binary)
        self.assertFalse(missing.seven_zip_available)

    def test_the_probe_runs_once_per_report_and_not_once_per_archive(self):
        """The lazy probe at the point of use says nothing about a machine no
        delegated format was ever met on. This one runs up front; that is one
        `shutil.which` more per run, and it is the price of a declaration that
        is always there."""
        archive = self._zip_at(self.dir / "pkg.zip")
        with mock.patch.object(ux, "find_7zip_binary",
                               wraps=ux.find_7zip_binary) as probe:
            ux.prepare_source(str(archive), workspace=self.dir / "ws")
        self.assertEqual(1, probe.call_count)


# ---------------------------------------------------------------------------
# What this story deliberately did NOT change
# ---------------------------------------------------------------------------
class TestWhatThisInstrumentationDidNotChange(_Bench):

    @staticmethod
    def _logging_calls():
        source = (REPO_ROOT / "unboxr" / "extraction.py").read_text(encoding="utf-8")
        calls = []
        for node in ast.walk(ast.parse(source)):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "logger"):
                calls.append(node.func.attr)
        return calls

    def test_the_number_of_logging_sites_of_the_module_is_unchanged(self):
        """This story moves information into a DATA structure. It does not take
        it upon itself to double, or to remove, the messages already there --
        and a report that quietly changed how loud the chain is would be a
        second change hiding behind the first.

        Story 14.8 (crypto-scan, upstream) is the one exception on record: it
        gave level 0 its own provisional-name-then-rename dance, reused from
        `flatten_nested_archives` rather than reinvented, plus the removal of
        a URL's downloaded copy under `--no-archive-dir` -- five new sites,
        one informational and four warnings, all NAMED here rather than left
        for this test to silently absorb.

        Twenty-six sites, ten informational and sixteen warnings, asserted in
        this body rather than engraved in the name of the test."""
        calls = self._logging_calls()
        self.assertEqual(26, len(calls))
        self.assertEqual(10, calls.count("info"))
        self.assertEqual(16, calls.count("warning"))

    def test_recording_never_becomes_what_amputates_the_corpus(self):
        """A guard must never be the thing that shortens the corpus. If the
        report itself raised, the flattening would stop and every remaining
        archive would go unopened with no record at all -- which is the defect
        the occupancy check was moved out of its `try` to avoid."""
        root = self._tree()
        self._zip_at(root / "first.zip")
        self._zip_at(root / "second.zip")

        class _Hostile(rp.ExtractionReport):
            def record(self, *args, **kwargs):
                raise RuntimeError("a report that fights back")

        hostile = _Hostile(capability=ux.probe_capability_profile())
        ux.flatten_nested_archives(root, report=hostile)

        self.assertTrue((root / "first.zip" / "code" / "aes.c").is_file())
        self.assertTrue((root / "second.zip" / "code" / "aes.c").is_file())

    def test_flattening_still_works_with_no_report_at_all(self):
        """The parameter is optional. A caller that wants only the tree keeps
        the call it already had."""
        root = self._tree()
        self._zip_at(root / "inner.zip")
        self.assertIsNone(ux.flatten_nested_archives(root))
        self.assertTrue((root / "inner.zip" / "code" / "aes.c").is_file())


if __name__ == "__main__":
    unittest.main(verbosity=2)
