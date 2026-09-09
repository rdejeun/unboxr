"""The `unboxr` command line: a deliberate floor, and the one thing it owns.

The command is the ONLY part of the package that configures logging. It is also
the only part that can restore, today, a guarantee the library gives up by going
silent: an amputation of the corpus must be announced. It does that with a
COUNTER on the six NAMED amputations -- not by counting warnings, since one
warning of the module (the machine-dependent naming fallback) is not an
amputation at all.

`--quiet` therefore cannot mean "warnings only": the most frequent amputation,
an office container being refused, is announced at the informational level.

100% offline: no network, no 7-Zip binary, no versioned fixture.
"""

from __future__ import annotations

import ast
import contextlib
import io
import logging
import re
import shutil
import sys
import tempfile
import tomllib
import unittest
import zipfile
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from unboxr import __version__, cli  # noqa: E402


@contextlib.contextmanager
def _isolated_logger():
    """The command installs a handler on the package logger, as a command may.

    A library must not, and does not. Tests restore the logger so that one case
    does not leak its handler into the next.
    """
    logger = logging.getLogger("unboxr")
    handlers = list(logger.handlers)
    filters = list(logger.filters)
    level = logger.level
    try:
        yield logger
    finally:
        logger.handlers = handlers
        logger.filters = filters
        logger.setLevel(level)


class _CommandBench(unittest.TestCase):

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="test_cli_"))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    def _zip(self, name: str, members) -> Path:
        path = self.dir / name
        with zipfile.ZipFile(path, "w") as z:
            for arcname, content in members:
                z.writestr(arcname, content)
        return path

    def _run(self, argv):
        """Runs the command, returns (code, stdout, stderr)."""
        out, err = io.StringIO(), io.StringIO()
        with _isolated_logger():
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                try:
                    code = cli.main(argv)
                except SystemExit as exit_code:      # argparse
                    code = exit_code.code
        return code, out.getvalue(), err.getvalue()


class TestEntryPointAndSurface(_CommandBench):

    def test_the_console_entry_point_is_declared(self):
        pyproject = tomllib.loads(
            (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual({"unboxr": "unboxr.cli:main"},
                         pyproject["project"]["scripts"])

    def test_version_prints_the_single_source_of_truth(self):
        code, out, err = self._run(["--version"])
        self.assertEqual(0, code)
        self.assertIn(__version__, out + err)

    def test_help_lists_the_minimal_surface_and_nothing_more(self):
        code, out, _ = self._run(["--help"])
        self.assertEqual(0, code)
        for option in ("--verbose", "--quiet", "--version", "--help"):
            with self.subTest(option=option):
                self.assertIn(option, out)

    def test_the_command_has_no_self_check_gate(self):
        """No `--controle`, no `--strict`: those belong to the project this code
        came from, and unboxr has no gate of any kind."""
        _, out, _ = self._run(["--help"])
        for absent in ("--controle", "--strict", "--check"):
            with self.subTest(absent=absent):
                self.assertNotIn(absent, out)
        # What the help DOES say, and must keep saying.
        self.assertIn("renders no verdict", out)

    def test_verbose_and_quiet_are_mutually_exclusive(self):
        archive = self._zip("p.zip", [("a.txt", "a")])
        code, _, _ = self._run([str(archive), str(self.dir / "d"), "-v", "-q"])
        self.assertEqual(2, code, "a usage error returns 2")

    def test_a_missing_argument_is_a_usage_error(self):
        code, _, _ = self._run(["only-one-argument"])
        self.assertEqual(2, code)

    def test_the_floor_is_declared_in_the_module_docstring(self):
        """Declared, so that later work adds to a stated floor rather than
        discovering one."""
        # Whitespace-normalised: the docstring is wrapped prose, and a
        # sentence can straddle a line break.
        flat = re.sub(r"\s+", " ", cli.__doc__.lower())
        self.assertIn("floor", flat)
        self.assertIn("do not design their options here", flat)


class TestExtractionThroughTheCommand(_CommandBench):

    def test_a_successful_run_returns_zero_and_prints_the_tree(self):
        archive = self._zip("p.zip", [("pkg/a.txt", "a")])
        destination = self.dir / "out"
        code, out, _ = self._run([str(archive), str(destination)])
        self.assertEqual(0, code)
        tree = Path(out.strip())
        self.assertEqual(destination / "extracted", tree)
        self.assertTrue((tree / "pkg" / "a.txt").is_file())

    def test_an_extraction_failure_returns_one(self):
        broken = self.dir / "broken.tar.zst"
        broken.write_bytes(b"\x28\xb5\x2f\xfd" + b"\x00" * 8)
        code, out, err = self._run([str(broken), str(self.dir / "out")])
        self.assertEqual(1, code)
        self.assertEqual("", out.strip(), "no tree is printed when there is none")
        self.assertIn("Zstandard", err)

    def test_a_missing_source_returns_one(self):
        code, _, err = self._run([str(self.dir / "absent.zip"), str(self.dir / "out")])
        self.assertEqual(1, code)
        self.assertIn("FileNotFoundError", err)

    def test_a_non_empty_destination_is_refused_rather_than_overwritten(self):
        archive = self._zip("p.zip", [("a.txt", "a")])
        destination = self.dir / "busy"
        destination.mkdir()
        (destination / "precious.txt").write_text("keep me", encoding="utf-8")

        code, _, err = self._run([str(archive), str(destination)])
        self.assertEqual(2, code)
        self.assertIn("not empty", err)
        self.assertEqual("keep me",
                         (destination / "precious.txt").read_text(encoding="utf-8"))

    def test_a_destination_that_is_a_file_is_refused(self):
        archive = self._zip("p.zip", [("a.txt", "a")])
        occupied = self.dir / "a_file"
        occupied.write_text("x", encoding="utf-8")
        code, _, err = self._run([str(archive), str(occupied)])
        self.assertEqual(2, code)
        self.assertIn("not a directory", err)

    def test_a_url_is_accepted_and_handed_over_untouched(self):
        """A URL is the only input that reaches the network, so the test stops
        at the boundary: it checks the string is passed through, never that a
        download happens."""
        seen = {}

        def fake_prepare(source, workspace=None):
            seen["source"] = source
            seen["workspace"] = workspace
            (workspace / "extracted").mkdir(parents=True)
            return workspace / "extracted", "undetermined", "0" * 64

        with mock.patch.object(cli, "prepare_source", fake_prepare):
            code, _, _ = self._run(["https://example.invalid/pkg.tar.gz",
                                    str(self.dir / "out")])
        self.assertEqual(0, code)
        self.assertEqual("https://example.invalid/pkg.tar.gz", seen["source"])
        self.assertEqual(self.dir / "out", seen["workspace"])

    def test_the_command_never_leaves_a_temporary_tree_behind(self):
        """The destination is a parameter precisely so the command does not
        create a workspace it never removes -- one abandoned tree per run."""
        archive = self._zip("p.zip", [("a.txt", "a")])
        with mock.patch("tempfile.mkdtemp",
                        side_effect=AssertionError("the command must not mkdtemp")):
            code, _, _ = self._run([str(archive), str(self.dir / "out")])
        self.assertEqual(0, code)


class TestAmputationsAreNeverHidden(_CommandBench):

    def _archive_with_an_office_container(self) -> Path:
        """Flattening this one refuses an office container: the most frequent
        amputation of all, and the one announced at the informational level."""
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as z:
            z.writestr("word/document.xml", "<w:document/>")
        return self._zip("package.zip", [("src/a.txt", "a"),
                                         ("doc/report.docx", inner.getvalue())])

    @staticmethod
    def _emitted_format_strings(level: str | None = None) -> set:
        source = (REPO_ROOT / "unboxr" / "extraction.py").read_text(encoding="utf-8")
        emitted = set()
        for node in ast.walk(ast.parse(source)):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "logger" and node.args
                    and (level is None or node.func.attr == level)):
                first = node.args[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    emitted.add(first.value)
        return emitted

    def test_every_warning_is_either_an_amputation_or_declared_not_to_be(self):
        """The class of defect, not just one instance of it.

        The test below checks that each NAMED amputation is still emitted. It
        does not, and did not, check the other direction: a warning ADDED to
        the module was counted by nothing and named by nothing. That is how
        the partial-move amputation went uncounted on the day it was written
        (code review, 9 September 2026). The two lists must now be exhaustive
        over the warnings of the module.
        """
        warnings = self._emitted_format_strings("warning")
        classified = set(cli.AMPUTATION_MESSAGES.values()) | cli.NOT_AN_AMPUTATION
        self.assertEqual(
            set(), warnings - classified,
            "a warning of unboxr.extraction is in neither AMPUTATION_MESSAGES "
            "nor NOT_AN_AMPUTATION. Decide which it is: if it says a container "
            "was not opened, it is an amputation and the counter must see it.")
        self.assertEqual(
            set(), cli.NOT_AN_AMPUTATION - warnings,
            "NOT_AN_AMPUTATION names a message the module no longer emits")

    def test_the_six_amputations_are_named_and_really_emitted_by_the_module(self):
        """The counter matches on the exact format strings of the module. This
        walks the AST of `extraction.py` and fails if any of them is no longer
        emitted there -- so a reworded message cannot silently stop counting."""
        emitted = self._emitted_format_strings()

        self.assertEqual(6, len(cli.AMPUTATION_MESSAGES))
        for name, message in cli.AMPUTATION_MESSAGES.items():
            with self.subTest(amputation=name):
                self.assertIn(message, emitted)
        self.assertIn(cli.CORPUS_WIDENING_MESSAGE, emitted,
                      "the corpus WIDENING message is named the same way, and "
                      "deliberately left out of the counter")

    def test_the_corpus_widening_message_is_not_counted_as_an_amputation(self):
        self.assertNotIn(cli.CORPUS_WIDENING_MESSAGE,
                         cli.AMPUTATION_MESSAGES.values())

    def test_the_naming_fallback_warning_is_not_counted_as_an_amputation(self):
        """It is a warning, and it is not an amputation: nothing was left
        unopened. Counting warnings instead of naming amputations would have
        made the oracle reminder fire on it."""
        source = (REPO_ROOT / "unboxr" / "extraction.py").read_text(encoding="utf-8")
        self.assertIn("fallback naming derived", source)
        for message in cli.AMPUTATION_MESSAGES.values():
            self.assertNotIn("fallback naming", message)

    def test_an_amputation_triggers_the_positive_only_oracle_reminder(self):
        archive = self._archive_with_an_office_container()
        code, _, err = self._run([str(archive), str(self.dir / "out")])
        self.assertEqual(0, code)
        self.assertIn("were not opened during this run", err)
        self.assertIn("absence of a finding is never evidence of absence", err)

    def test_a_clean_run_does_not_show_the_reminder(self):
        """It reports what happened; it is not a disclaimer stapled to every
        run."""
        archive = self._zip("clean.zip", [("src/a.txt", "a")])
        code, _, err = self._run([str(archive), str(self.dir / "out")])
        self.assertEqual(0, code)
        self.assertNotIn("were not opened during this run", err)

    def test_quiet_still_shows_the_informational_amputation(self):
        """The point of the whole design: `--quiet` does not drop below what
        declares an amputation."""
        archive = self._archive_with_an_office_container()
        code, _, err = self._run([str(archive), str(self.dir / "out"), "--quiet"])
        self.assertEqual(0, code)
        self.assertIn("report.docx", err)
        self.assertIn("office container", err)
        self.assertIn("were not opened during this run", err)

    def test_quiet_does_drop_the_ordinary_informational_records(self):
        """Otherwise `--quiet` would mean nothing at all."""
        archive = self._zip("clean.zip", [("src/a.txt", "a")])
        _, _, verbose_err = self._run([str(archive), str(self.dir / "loud")])
        _, _, quiet_err = self._run([str(archive), str(self.dir / "hushed"), "-q"])
        self.assertIn("Extracting archive", verbose_err)
        self.assertNotIn("Extracting archive", quiet_err)

    def test_the_default_level_is_informational_so_a_user_sees_everything(self):
        archive = self._archive_with_an_office_container()
        _, _, err = self._run([str(archive), str(self.dir / "out")])
        self.assertIn("SHA-256 digest of the input", err)
        self.assertIn("report.docx", err)


class TestTheLibraryStaysSilent(_CommandBench):
    """The command configures logging. The library must not, ever."""

    def test_the_library_writes_to_neither_stdout_nor_stderr(self):
        """THE TRAP IS STDERR. Without a `NullHandler`, logging's handler of
        last resort writes warnings there, so a test watching only stdout would
        pass for the wrong reason."""
        import unboxr.extraction as ux

        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as z:
            z.writestr("word/document.xml", "<w:document/>")
        archive = self._zip("p.zip", [("src/a.txt", "a"),
                                      ("doc/report.docx", inner.getvalue()),
                                      ("bad/payload.tar.zst", b"\x28\xb5\x2f\xfd\x00")])

        out, err = io.StringIO(), io.StringIO()
        with _isolated_logger():
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                tree, nature, digest = ux.prepare_source(
                    str(archive), workspace=self.dir / "silent")
        self.assertTrue((tree / "src" / "a.txt").is_file())
        self.assertEqual("", out.getvalue())
        self.assertEqual("", err.getvalue())

    def test_the_package_installs_a_null_handler_and_nothing_else(self):
        logger = logging.getLogger("unboxr")
        self.assertTrue(any(isinstance(h, logging.NullHandler)
                            for h in logger.handlers))

    def test_the_library_never_calls_basic_config(self):
        """`basicConfig` in imported code overwrites the caller's own logging
        setup -- the most common way to get this pattern wrong, and invisible in
        a unit test that does not look for it."""
        for name in ("__init__.py", "extraction.py"):
            with self.subTest(module=name):
                source = (REPO_ROOT / "unboxr" / name).read_text(encoding="utf-8")
                self.assertNotIn("basicConfig", source)
                self.assertNotIn("StreamHandler", source)

    def test_only_the_command_module_configures_logging(self):
        source = (REPO_ROOT / "unboxr" / "cli.py").read_text(encoding="utf-8")
        self.assertIn("StreamHandler", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
