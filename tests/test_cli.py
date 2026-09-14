"""The `unboxr` command line: a deliberate floor, and the one thing it owns.

The command is the ONLY part of the package that configures logging. It used to
be the only part that could restore, at all, a guarantee the library gives up by
going silent -- and it did that by READING ITS OWN LOGGING RECORDS, matching
each one against the exact format strings the library emits. The library now
RETURNS a report, and the command counts containers off it: one container, one
entry, however many call sites and however many nesting levels looked at it.

`--quiet` still cannot mean "warnings only": the most frequent amputation, an
office container being refused, is announced at the informational level. That
filter is the one that survives, and it reads the format strings from
`unboxr.report`, the table's one home, never from a copy.

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
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from unboxr import __version__, cli, report  # noqa: E402
from unboxr.report import PreparedSource  # noqa: E402


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
        """"And nothing more" was in the name and in nothing else: the body
        was four `assertIn`, so ADDING an option left it green. Measured on
        12 September 2026, and the third instance of that defect found in this
        repository. The assertion is now on the COMPLETE set."""
        code, out, _ = self._run(["--help"])
        self.assertEqual(0, code)
        listed = set(re.findall(r"(?<![\w-])--[a-z][a-z-]*", out))
        # `--sbom` writes the extraction document; `--linked-bom` says which
        # other BOM that document belongs to, and has no meaning without it.
        # `--replace` and `--no-archive-dir` are the two other extraction
        # modes story 14.8 added. The surface is asserted as a COMPLETE set
        # precisely so that one more cannot slip in unnoticed.
        self.assertEqual({"--verbose", "--quiet", "--sbom", "--linked-bom",
                          "--replace", "--no-archive-dir",
                          "--version", "--help"}, listed)
        short = set(re.findall(r"(?<![\w-])-[a-z](?![\w-])", out))
        self.assertEqual({"-v", "-q", "-h"}, short)

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

    def test_a_missing_destination_is_a_usage_error_unless_replace_is_given(self):
        """`destination` became OPTIONAL the day `--replace` needed an
        invocation that has no object for it (story 14.8, AC-3.2): what
        "missing" means no longer follows from the positional alone, it
        follows from the combination with `--replace`. Still a usage error,
        still code 2 -- the definition of "missing" changed, not the fact
        that omitting it is refused."""
        code, _, err = self._run(["only-one-argument"])
        self.assertEqual(2, code)
        self.assertIn("destination", err)

    def test_an_archive_alone_is_a_valid_invocation_only_under_replace(self):
        archive = self._zip("p.zip", [("a.txt", "a")])
        code, out, _ = self._run(["--replace", str(archive)])
        self.assertEqual(0, code)
        self.assertEqual(archive, Path(out.strip()))

    def test_the_floor_is_declared_and_says_what_was_added_to_it(self):
        """Declared, so that later work adds to a STATED floor rather than
        discovering one.

        The docstring used to forbid, literally, what the report story then
        did: "do not design their options here". The command was always meant
        to be enriched by that story and again by the document one; what it
        must keep saying is which floor it is now standing on, and what is
        still not its job.

        AND THE CLAIM THAT HAD TO GO. "It writes no document" was true until
        the document story, and this assertion is what made its removal
        impossible to forget -- the whole point of holding published prose in
        a test. It is replaced here by the claim that is now true, which is
        narrower: a document is written ON REQUEST, and never otherwise.

        AND THE SECOND ONE, FOR A REASON WORTH WRITING DOWN. The heading was
        asserted and its CONTENTS never were, so the paragraph under it could
        say the exact opposite of what the command does while this test stayed
        green. It said that linking that document to another was later work
        and not designed here -- which is precisely what the linking work then
        did. A heading held without its contents is more dangerous than prose
        held by nothing, because it is believed to be held. A fragment of what
        the paragraph now says is asserted below, and the sentence that became
        false is asserted GONE.
        """
        # Whitespace-normalised: the docstring is wrapped prose, and a
        # sentence can straddle a line break.
        flat = re.sub(r"\s+", " ", cli.__doc__.lower())
        self.assertIn("floor", flat)
        self.assertIn("summarises what could not be opened", flat)
        self.assertNotIn("writes no document", flat)
        self.assertIn("on request -- and only on request", flat)
        self.assertIn("what is still not this floor", flat)
        self.assertNotIn("do not design their options here", flat)
        self.assertNotIn("linking that document to another, and every option",
                         flat)
        self.assertIn("no self-check gate, no strict mode", flat)
        # A fragment of what REPLACED the false claim, not merely of what
        # survived around it -- the previous two assertions above pin
        # unchanged prose and would stay green even if this sentence were
        # deleted outright. Precedent: 14.4 added
        # "on request -- and only on request" for the same reason.
        self.assertIn("does not fetch, open or resolve", flat)


class TestExtractionThroughTheCommand(_CommandBench):

    def test_a_successful_run_returns_zero_and_prints_the_tree(self):
        archive = self._zip("p.zip", [("pkg/a.txt", "a")])
        destination = self.dir / "out"
        code, out, _ = self._run([str(archive), str(destination)])
        self.assertEqual(0, code)
        tree = Path(out.strip())
        self.assertEqual(destination / "p.zip", tree)
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

    def test_a_non_empty_destination_is_refused_under_no_archive_dir(self):
        """AC-4.2 keeps the OLDER rule under `--no-archive-dir`, where the
        extracted tree IS DESTINATION: it must be empty or absent."""
        archive = self._zip("p.zip", [("a.txt", "a")])
        destination = self.dir / "busy"
        destination.mkdir()
        (destination / "precious.txt").write_text("keep me", encoding="utf-8")

        code, _, err = self._run([str(archive), str(destination),
                                  "--no-archive-dir"])
        self.assertEqual(2, code)
        self.assertIn("not empty", err)
        self.assertEqual("keep me",
                         (destination / "precious.txt").read_text(encoding="utf-8"))

    def test_a_non_empty_destination_is_accepted_in_the_default_mode(self):
        """AC-2.4: the new contract claims a NAME inside DESTINATION, not the
        whole directory -- `unboxr toto.jar /tmp` is now a valid invocation
        even when DESTINATION holds other things, as long as it does not
        already hold a path named after the archive."""
        archive = self._zip("p.zip", [("a.txt", "a")])
        destination = self.dir / "busy"
        destination.mkdir()
        (destination / "precious.txt").write_text("keep me", encoding="utf-8")

        code, out, _ = self._run([str(archive), str(destination)])
        self.assertEqual(0, code)
        self.assertEqual(destination / "p.zip", Path(out.strip()))
        self.assertEqual("keep me",
                         (destination / "precious.txt").read_text(encoding="utf-8"))

    def test_an_already_occupied_target_is_refused_in_the_default_mode(self):
        """AC-2.1/AC-2.2: the refusal is on the SPECIFIC target already
        existing, never on DESTINATION being merely non-empty."""
        archive = self._zip("p.zip", [("a.txt", "a")])
        destination = self.dir / "out"
        (destination / "p.zip").mkdir(parents=True)

        code, _, err = self._run([str(archive), str(destination)])
        self.assertEqual(2, code)
        self.assertIn(str(destination / "p.zip"), err)
        self.assertIn("already exists", err)

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

        def fake_prepare(source, workspace=None, report=None, replace=False,
                         no_archive_dir=False):
            seen["source"] = source
            seen["workspace"] = workspace
            seen["report"] = report
            # REPRODUCES the real name computation (`resolve_archive_name`),
            # rather than the retired literal "extracted": a fake that
            # invented its own name would stop exercising what `cli.main`
            # actually prints on `stdout`.
            name = Path(urlparse(source).path).name or "downloaded_archive"
            tree = workspace / name
            tree.mkdir(parents=True)
            # `PreparedSource` imported by name, not read off the module: the
            # parameter above is called `report` because the real signature
            # calls it that, and it shadows the module inside this function.
            return PreparedSource(
                tree=tree, nature="undetermined",
                digest="0" * 64, report=report)

        with mock.patch.object(cli, "prepare_source", fake_prepare):
            code, _, _ = self._run(["https://example.invalid/pkg.tar.gz",
                                    str(self.dir / "out")])
        self.assertEqual(0, code)
        self.assertEqual("https://example.invalid/pkg.tar.gz", seen["source"])
        self.assertEqual(self.dir / "out", seen["workspace"])
        self.assertIsNotNone(seen["report"], "the command creates the report "
                                             "and hands it over, so that a "
                                             "failure still declares")

    def test_the_command_never_leaves_a_temporary_tree_behind(self):
        """The destination is a parameter precisely so the command does not
        create a workspace it never removes -- one abandoned tree per run."""
        archive = self._zip("p.zip", [("a.txt", "a")])
        with mock.patch("tempfile.mkdtemp",
                        side_effect=AssertionError("the command must not mkdtemp")):
            code, _, _ = self._run([str(archive), str(self.dir / "out")])
        self.assertEqual(0, code)


class TestTheThreeExtractionModes(_CommandBench):
    """Story 14.8: the default, `--replace` and `--no-archive-dir` modes, and
    the refusals AC-2/AC-3/AC-4/AC-5 attach to them."""

    def test_replace_extracts_in_place_and_removes_the_archive(self):
        """AC-3.1, end to end through the command line."""
        archive = self._zip("p.zip", [("a.txt", "a")])
        code, out, _ = self._run(["--replace", str(archive)])
        self.assertEqual(0, code)
        self.assertEqual(archive, Path(out.strip()))
        self.assertTrue((archive / "a.txt").is_file())
        self.assertFalse(archive.is_file())

    def test_replace_refuses_a_destination(self):
        """AC-3.2: a usage error, not a silently ignored argument."""
        archive = self._zip("p.zip", [("a.txt", "a")])
        code, _, err = self._run(["--replace", str(archive), str(self.dir / "out")])
        self.assertEqual(2, code)
        self.assertIn("DESTINATION is not accepted with --replace", err)
        self.assertTrue(archive.is_file(), "nothing may be touched before the refusal")

    def test_replace_refuses_a_url(self):
        """AC-3.3: there is no local file to replace."""
        code, _, err = self._run(["--replace", "https://example.invalid/p.zip"])
        self.assertEqual(2, code)
        self.assertIn("--replace is refused on a URL", err)

    def test_replace_refuses_a_directory_source(self):
        """AC-3.4 / D-D: `prepare_source` extracts nothing on this branch --
        there is no archive for `--replace` to consume."""
        source = self.dir / "given"
        source.mkdir()
        (source / "a.txt").write_text("a", encoding="utf-8")
        code, _, err = self._run(["--replace", str(source)])
        self.assertEqual(2, code)
        self.assertIn("already a directory", err)
        self.assertTrue((source / "a.txt").is_file(), "nothing may be touched")

    def test_no_archive_dir_refuses_a_directory_source(self):
        """AC-4.5 / D-D, the same refusal for the other mode."""
        source = self.dir / "given"
        source.mkdir()
        code, _, err = self._run([str(source), str(self.dir / "out"),
                                  "--no-archive-dir"])
        self.assertEqual(2, code)
        self.assertIn("already a directory", err)

    def test_replace_and_no_archive_dir_are_refused_together(self):
        """AC-3.5, enforced by `build_parser`'s own mutually exclusive group."""
        archive = self._zip("p.zip", [("a.txt", "a")])
        code, _, _ = self._run(["--replace", "--no-archive-dir", str(archive)])
        self.assertEqual(2, code, "a usage error returns 2")

    def test_a_local_archive_colliding_with_its_own_destination_is_refused(self):
        """AC-2.3 / AC-5.3: DESTINATION is the archive's own parent directory,
        so the default target IS the archive itself. The archive is a local
        file the caller did not ask to consume, so this is AC-2's existence
        refusal, not the provisional-name dance -- and the message names
        `--replace` as the only way out."""
        archive = self._zip("p.zip", [("a.txt", "a")])
        code, _, err = self._run([str(archive), str(self.dir)])
        self.assertEqual(2, code)
        self.assertIn("is the archive itself", err)
        self.assertIn("--replace", err)
        self.assertTrue(archive.is_file(), "nothing may be touched")

    def test_replace_resolves_the_collision_the_default_mode_refuses(self):
        """The other half of the same scenario: `--replace` is exactly the
        way out AC-2.3 names."""
        archive = self._zip("p.zip", [("a.txt", "a")])
        code, out, _ = self._run(["--replace", str(archive)])
        self.assertEqual(0, code)
        self.assertEqual(archive, Path(out.strip()))

    def test_replace_refuses_an_sbom_path_inside_the_tree_it_will_become(self):
        """AC-8.5, the third mode: under `--replace` the tree IS the
        archive's own path, so `--sbom` pointing inside it is refused the
        same way, with nothing extracted and the archive left untouched."""
        archive = self._zip("p.zip", [("a.txt", "a")])
        code, _, err = self._run(["--replace", str(archive),
                                  "--sbom", str(archive / "sbom.json")])
        self.assertEqual(2, code)
        self.assertIn("inside the tree it inventories", err)
        self.assertTrue(archive.is_file(), "nothing may be touched before the refusal")

    def test_no_archive_dir_writes_no_sbom_anywhere_under_destination(self):
        """AC-4.3: under this mode the tree IS DESTINATION, so no path under
        it is left "beside" the tree the way `DESTINATION/sbom.json` is in
        the default mode."""
        archive = self._zip("p.zip", [("a.txt", "a")])
        destination = self.dir / "out"
        code, _, err = self._run([
            str(archive), str(destination), "--no-archive-dir",
            "--sbom", str(destination / "sbom.json")])
        self.assertEqual(2, code)
        self.assertIn("inside the tree it inventories", err)


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
        classified = (set(report.AMPUTATION_MESSAGES.values())
                      | set(report.NOT_AN_AMPUTATION.values()))
        self.assertEqual(
            set(), warnings - classified,
            "a warning of unboxr.extraction is in neither AMPUTATION_MESSAGES "
            "nor NOT_AN_AMPUTATION. Decide which it is: if it says a container "
            "was not opened, it is an amputation and the report must see it.")
        self.assertEqual(
            set(), set(report.NOT_AN_AMPUTATION.values()) - warnings,
            "NOT_AN_AMPUTATION names a message the module no longer emits")
        # The arithmetic the two tables have to keep adding up to. Thirteen
        # warnings: five amputations at warning level -- the sixth, the office
        # container, is an `info` -- and eight declared non-amputations. The
        # eighth was added by story 14.8 (crypto-scan, upstream):
        # `downloaded_copy_kept_alongside_the_tree`, filed when a URL's
        # download cannot be removed under `--no-archive-dir`.
        self.assertEqual(13, len(warnings))
        self.assertEqual(
            5, len(set(report.AMPUTATION_MESSAGES.values()) & warnings))
        self.assertEqual(8, len(report.NOT_AN_AMPUTATION))

    def test_the_six_amputations_are_named_and_really_emitted_by_the_module(self):
        """The counter matches on the exact format strings of the module. This
        walks the AST of `extraction.py` and fails if any of them is no longer
        emitted there -- so a reworded message cannot silently stop counting."""
        emitted = self._emitted_format_strings()

        self.assertEqual(6, len(report.AMPUTATION_MESSAGES))
        for code, message in report.AMPUTATION_MESSAGES.items():
            with self.subTest(amputation=code):
                self.assertIn(message, emitted)
        self.assertIn(report.CORPUS_WIDENING_MESSAGE, emitted,
                      "the corpus WIDENING message is named the same way, and "
                      "deliberately left out of the amputation count")

    def test_the_corpus_widening_message_is_not_counted_as_an_amputation(self):
        self.assertNotIn(report.CORPUS_WIDENING_MESSAGE,
                         report.AMPUTATION_MESSAGES.values())
        self.assertNotEqual(report.NOT_OPENED,
                            report.CAUSE_KINDS[report.RECOGNISED_BY_CONTENT])

    def test_the_provisional_naming_warning_is_not_counted_as_an_amputation(self):
        """It is a warning, and it is not an amputation: nothing was left
        unopened. Counting warnings instead of naming amputations would have
        made the oracle reminder fire on it."""
        source = (REPO_ROOT / "unboxr" / "extraction.py").read_text(encoding="utf-8")
        self.assertIn("provisional name derived", source)
        for message in report.AMPUTATION_MESSAGES.values():
            self.assertNotIn("provisional name", message)

    def test_a_rename_that_fails_is_declared_and_is_not_an_amputation(self):
        """The one path on which the provisional name becomes the definitive
        one. The content is whole and on disk, so counting it as an amputation
        would claim a loss that did not happen -- but staying silent would
        leave a consumer looking for a directory that is not there."""
        message = ("%s: the extracted content could not be renamed to %s (%s): "
                   "it stays under its provisional name %s. Its content IS in "
                   "the extracted tree, under that name.")
        self.assertIn(message, report.NOT_AN_AMPUTATION.values())
        self.assertIn(message, self._emitted_format_strings("warning"))
        self.assertNotIn(message, report.AMPUTATION_MESSAGES.values())

    def test_an_amputation_triggers_the_positive_only_oracle_reminder(self):
        archive = self._archive_with_an_office_container()
        code, _, err = self._run([str(archive), str(self.dir / "out")])
        self.assertEqual(0, code)
        self.assertIn("were not opened during this run", err)
        self.assertIn("absence of a finding is never evidence of absence", err)

    def test_the_failure_path_still_declares_what_was_lost_before_it(self):
        """The one guarantee the counter on logging records did deliver, and
        the reason a report is passed IN as well as returned. An office
        container is refused -- the most frequent amputation there is -- and
        THEN the run fails with nothing to return. Removing the counter without
        putting this in its place would have been a regression dressed up as a
        simplification."""
        office = self.dir / "manual.docx"
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as z:
            z.writestr("word/document.xml", "<w:document/>")
        office.write_bytes(inner.getvalue())

        code, out, err = self._run([str(office), str(self.dir / "out")])

        self.assertEqual(1, code)
        self.assertEqual("", out.strip())
        self.assertIn("office container", err)
        self.assertIn("were not opened during this run", err)

    def test_the_count_shown_is_containers_and_no_longer_logging_records(self):
        """One office container, met at four call sites and at every nesting
        level, used to be counted several times over. The reminder now names
        ONE."""
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as z:
            z.writestr("word/document.xml", "<w:document/>")
        deepest = io.BytesIO()
        with zipfile.ZipFile(deepest, "w") as z:
            z.writestr("code/aes.c", "int a;")
        middle = io.BytesIO()
        with zipfile.ZipFile(middle, "w") as z:
            z.writestr("third.zip", deepest.getvalue())
        archive = self._zip("package.zip", [("doc/report.docx", inner.getvalue()),
                                            ("second.zip", middle.getvalue())])

        code, _, err = self._run([str(archive), str(self.dir / "out")])

        self.assertEqual(0, code)
        self.assertIn("1 container(s) were not opened during this run", err)

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
                prepared = ux.prepare_source(
                    str(archive), workspace=self.dir / "silent")
        self.assertTrue((prepared.tree / "src" / "a.txt").is_file())
        self.assertEqual("", out.getvalue())
        self.assertEqual("", err.getvalue())

    def test_the_package_installs_a_null_handler_and_nothing_else(self):
        logger = logging.getLogger("unboxr")
        self.assertTrue(any(isinstance(h, logging.NullHandler)
                            for h in logger.handlers))

    def test_the_library_never_calls_basic_config(self):
        """`basicConfig` in imported code overwrites the caller's own logging
        setup -- the most common way to get this pattern wrong, and invisible in
        a unit test that does not look for it.

        The list of modules is DERIVED from the package, not written out. It
        named two files until 12 September 2026, so a third module would have
        crossed this guard without ever being looked at."""
        library = [path for path in sorted((REPO_ROOT / "unboxr").glob("*.py"))
                   if path.name != "cli.py"]
        self.assertGreater(len(library), 2, "a guard over two files while the "
                                            "package has more proves less than "
                                            "it claims")
        for path in library:
            with self.subTest(module=path.name):
                source = path.read_text(encoding="utf-8")
                self.assertNotIn("basicConfig", source)
                self.assertNotIn("StreamHandler", source)

    def test_only_the_command_module_configures_logging(self):
        """"Only" was in the name and in nothing else: the body asserted the
        PRESENCE of a `StreamHandler` in `cli.py` and stopped there, proving
        nothing about the rest of the package. Both halves are now asserted."""
        configuring = {path.name
                       for path in sorted((REPO_ROOT / "unboxr").glob("*.py"))
                       if "StreamHandler" in path.read_text(encoding="utf-8")}
        self.assertEqual({"cli.py"}, configuring)


if __name__ == "__main__":
    unittest.main(verbosity=2)
