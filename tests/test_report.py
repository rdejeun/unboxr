"""The extraction report, held as a contract rather than as a convenience.

The library went silent when it became a library: an amputation of the corpus
was announced through the logging system, which a caller may never have
configured. This module puts it back in a RETURNED VALUE, where it cannot be
missed, and this file holds what that value must satisfy.

Three properties carry most of the weight:

  1. ONE table, and one only, turns a stable cause CODE into English prose. A
     second table written anywhere else would drift from the first, and the
     divergence would be invisible until a consumer read two different texts
     for one cause.
  2. The identity of an entry is the pair (code, path), NEVER the call.
     `categorize_archive` has four call sites, one of them inside a sorted
     comprehension re-evaluated at every level: counting calls would announce
     dozens of amputations for one office document.
  3. A report always carries a capability profile, even when nothing needed it.
     An omission asserts: a profile that only showed up when it had been used
     would read as "not applicable" rather than "binary absent".

100% offline, standard library only.
"""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from unboxr import report  # noqa: E402

PACKAGE_ROOT = REPO_ROOT / "unboxr"


class TestTheVocabularyOfCauses(unittest.TestCase):

    def test_every_code_has_exactly_one_english_text(self):
        for code, text in report.CAUSE_TEXTS.items():
            with self.subTest(code=code):
                self.assertTrue(text.strip(), "a code with no text is not a cause")
                self.assertEqual(text, text.strip())

    def test_a_code_is_an_identifier_and_not_a_sentence(self):
        """The six original keys were English prose. A reword changed them,
        while a downstream program translates the CODE: the key must be stable
        under rewording, which prose is not."""
        for code in report.CAUSE_TEXTS:
            with self.subTest(code=code):
                self.assertTrue(code.isidentifier())
                self.assertEqual(code, code.lower())
                self.assertNotIn(" ", code)

    def test_every_code_has_exactly_one_kind(self):
        self.assertEqual(set(report.CAUSE_TEXTS), set(report.CAUSE_KINDS))
        for code, kind in report.CAUSE_KINDS.items():
            with self.subTest(code=code):
                self.assertIn(kind, report.KINDS)

    def test_the_count_of_causes_is_asserted_here_and_not_in_a_test_name(self):
        """A figure engraved in a test name never goes red, it lies.
        Twenty-two causes: 6 amputations already named by the command, 8
        declared non-amputations (the eighth,
        `downloaded_copy_kept_alongside_the_tree`, added by story 14.8 of the
        upstream project, crypto-scan), the corpus widening, and the 4 an
        earlier story added -- two containers opened, two refusals for want
        of a capability. The last three arrived with 3.0: they say a listed path
        carries no digest and why, and they were the values of a
        `digestState` property until a document that reports only the
        abnormal stopped having a place for the fourth, "it was computed".
        """
        self.assertEqual(22, len(report.CAUSE_TEXTS))
        self.assertEqual(8, sum(1 for kind in report.CAUSE_KINDS.values()
                                if kind == report.NOT_OPENED))

    def test_the_original_prose_keys_are_kept_for_traceability(self):
        """The six names the command used are a record of the code review that
        produced them; renaming them to codes must not lose that trail."""
        self.assertEqual(6, len(report.ORIGINAL_AMPUTATION_NAMES))
        for code, prose in report.ORIGINAL_AMPUTATION_NAMES.items():
            with self.subTest(code=code):
                self.assertIn(code, report.CAUSE_TEXTS)
                self.assertEqual(report.NOT_OPENED, report.CAUSE_KINDS[code])
                self.assertIn(" ", prose, "the original key was English prose")

    def test_the_two_logging_tables_keep_their_cardinals(self):
        """Moved from the command, not rewritten: six amputations, eight
        declared non-amputations (story 14.8 of the upstream project,
        crypto-scan, added the eighth), one widening message."""
        self.assertEqual(6, len(report.AMPUTATION_MESSAGES))
        self.assertEqual(8, len(report.NOT_AN_AMPUTATION))
        self.assertTrue(report.CORPUS_WIDENING_MESSAGE)
        for code in report.AMPUTATION_MESSAGES:
            with self.subTest(code=code):
                self.assertEqual(report.NOT_OPENED, report.CAUSE_KINDS[code])
        for code in report.NOT_AN_AMPUTATION:
            with self.subTest(code=code):
                self.assertNotEqual(report.NOT_OPENED, report.CAUSE_KINDS[code])

    def test_no_second_table_gives_a_cause_its_text(self):
        """One table, inside unboxr, or the texts diverge by construction.
        Checked on the SOURCE of the other two modules: a copy made to spare an
        import is exactly the failure this forbids."""
        # `sbom.py` JOINED THE LIST AT 3.0: it is the module that projects the
        # codes onto a document, so it is the likeliest place for a second
        # table of texts to appear -- and the story that merged the digest
        # states into this vocabulary asked for the guard explicitly.
        for name in ("cli.py", "extraction.py", "sbom.py"):
            source = (PACKAGE_ROOT / name).read_text(encoding="utf-8")
            for code, text in report.CAUSE_TEXTS.items():
                with self.subTest(module=name, code=code):
                    self.assertNotIn(text, source)

    def test_no_upstream_message_prefix_enters_a_cause_text(self):
        for text in report.CAUSE_TEXTS.values():
            for prefix in ("[INFO]", "[AVERTISSEMENT]", "[ERREUR]", "[DEBUG]",
                           "[EXPLOITATION]"):
                with self.subTest(text=text, prefix=prefix):
                    self.assertNotIn(prefix, text)

    def test_the_report_module_does_not_import_the_command(self):
        """The dependency runs the other way: `cli` imports the tables. A cycle
        is the very reason they had landed in `cli.py`, where they did not
        belong."""
        tree = ast.parse((PACKAGE_ROOT / "report.py").read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                with self.subTest(module=node.module, level=node.level):
                    self.assertNotEqual("cli", (node.module or "").split(".")[-1])
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    with self.subTest(imported=alias.name):
                        self.assertNotIn("cli", alias.name.split("."))


class TestTheReportItself(unittest.TestCase):

    def _report(self) -> report.ExtractionReport:
        return report.ExtractionReport(
            capability=report.CapabilityProfile(
                seven_zip_binary=None, recognised_extensions=68,
                extensions_needing_seven_zip=31))

    def test_a_report_cannot_be_built_without_a_capability_profile(self):
        """An omission asserts. A profile that appeared only when it had been
        used would read as "not applicable" rather than "binary absent"."""
        with self.assertRaises(TypeError):
            report.ExtractionReport()

    def test_a_fresh_report_is_empty_and_explicit_about_it(self):
        fresh = self._report()
        self.assertEqual([], fresh.not_opened)
        self.assertEqual([], fresh.opened)
        self.assertEqual([], fresh.still_in_tree)
        self.assertEqual([], fresh.widened)
        self.assertEqual(0, fresh.depth_reached)
        self.assertIsNone(fresh.depth_limit)
        self.assertEqual(0, fresh.amputation_count())

    def test_the_identity_of_an_entry_is_the_pair_code_and_path(self):
        """`categorize_archive` has four call sites, one inside a comprehension
        re-evaluated at every level. Counting calls would announce dozens of
        amputations for a single office document."""
        held = self._report()
        for _ in range(12):
            held.record(report.OFFICE_CONTAINER_EXCLUDED, "doc/report.docx")
        self.assertEqual(1, held.amputation_count())
        self.assertEqual(1, len(held.not_opened))

    def test_two_different_paths_under_one_code_are_two_entries(self):
        held = self._report()
        held.record(report.OFFICE_CONTAINER_EXCLUDED, "a.docx")
        held.record(report.OFFICE_CONTAINER_EXCLUDED, "b.docx")
        self.assertEqual(2, held.amputation_count())

    def test_one_path_under_two_codes_stays_two_entries(self):
        """A container refused for a reason, then failing for another, is two
        facts. Collapsing them on the path alone would hide one."""
        held = self._report()
        held.record(report.EXTRACTION_FAILED, "x.zip")
        held.record(report.ZSTD_NOT_SUPPORTED, "x.zip")
        self.assertEqual(2, held.amputation_count())

    def test_a_record_is_routed_by_its_code_and_not_by_its_call_site(self):
        held = self._report()
        held.record(report.NESTED_CONTAINER_OPENED, "inner.zip", level=2)
        held.record(report.EXTRACTION_FAILED, "bad.zip", level=1)
        held.record(report.RECOGNISED_BY_CONTENT, "opaque.data")
        held.record(report.ARCHIVE_KEPT_AFTER_SUCCESSFUL_EXTRACTION, "held.zip")
        self.assertEqual(["inner.zip"], [entry.path for entry in held.opened])
        self.assertEqual(["bad.zip"], [entry.path for entry in held.not_opened])
        self.assertEqual(["opaque.data"], [entry.path for entry in held.widened])
        self.assertEqual(["held.zip"], [entry.path for entry in held.still_in_tree])

    def test_an_unknown_code_is_refused_rather_than_filed_somewhere(self):
        """A code with no declared kind has no place to go, and guessing one
        would put an amputation in a list nothing counts."""
        held = self._report()
        with self.assertRaises(KeyError):
            held.record("invented_code", "x.zip")

    def test_a_log_only_cause_records_nothing_and_says_so(self):
        """One cause names a logging message that has no container of its own:
        the closing recap, which restates entries already filed one by one.
        Counting it would inflate the total by one per run."""
        held = self._report()
        held.record(report.FLATTENING_FINISHED_WITH_UNOPENED_ARCHIVES, "")
        self.assertEqual(0, held.amputation_count())
        self.assertEqual([], held.opened)
        self.assertEqual([], held.still_in_tree)

    def test_recording_survives_a_caller_that_passes_the_wrong_shape(self):
        """A record that raised would abort the flattening and leave every
        remaining archive unopened with no trace at all -- the guard becoming
        what amputates the corpus. Only an UNDECLARED code is refused, and that
        is a programming error caught on the first run, not a runtime state."""
        held = self._report()
        held.record(report.EXTRACTION_FAILED, "x.zip", level=None, detail=None)
        held.record(report.EXTRACTION_FAILED, None, level="two")
        self.assertEqual(2, held.amputation_count())

    def test_the_text_of_an_entry_comes_from_the_single_table(self):
        held = self._report()
        held.record(report.ZSTD_NOT_SUPPORTED, "p.tar.zst")
        entry = held.not_opened[0]
        self.assertEqual(report.CAUSE_TEXTS[report.ZSTD_NOT_SUPPORTED],
                         report.text_for(entry.code))

    def test_an_unknown_code_degrades_and_is_never_confused_with_nothing(self):
        """A consumer on the other side of a language boundary must be able to
        tell "a code I do not know" from "nothing to report". `text_for` says
        so rather than returning an empty string."""
        degraded = report.text_for("a_code_from_a_later_version")
        self.assertTrue(degraded)
        self.assertIn("a_code_from_a_later_version", degraded)
        self.assertIn("unknown", degraded.lower())


class TestTheCapabilityProfile(unittest.TestCase):

    def test_the_profile_states_what_was_measured_not_what_is_supposed(self):
        present = report.CapabilityProfile(
            seven_zip_binary="/usr/bin/7zz", recognised_extensions=68,
            extensions_needing_seven_zip=31)
        absent = report.CapabilityProfile(
            seven_zip_binary=None, recognised_extensions=68,
            extensions_needing_seven_zip=31)
        self.assertTrue(present.seven_zip_available)
        self.assertFalse(absent.seven_zip_available)

    def test_the_profile_declares_a_divergence_and_closes_nothing(self):
        """Same posture as every other declaration in this package: state what
        was measured, never promise the gap is closed."""
        source = (PACKAGE_ROOT / "report.py").read_text(encoding="utf-8")
        self.assertIn("No guarantee on the corpus when the 7-Zip binary is "
                      "absent", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
