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
import functools
import io
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import tomllib
import unittest
import zipfile
from pathlib import Path
from unittest import mock
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
# This directory too, EXPLICITLY, so that the import below does not depend on
# which runner picked the file up: `pytest` prepends it, `unittest discover -t
# tests` prepends it, and anything else may not.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from unboxr import __version__, cli, extraction, report  # noqa: E402
from unboxr.report import PreparedSource  # noqa: E402
# THE VOCABULARY GUARD IS IMPORTED, NEVER RETYPED. `test_boundaries` holds both
# families -- the tokens banned from the SOURCE and the claim words banned from
# what a caller READS -- plus the helper that tells this package's own
# disclaimer from a claim. A second list written here is what code review found
# on 15 September 2026: two guards sharing no entry, neither naming the other.
from test_boundaries import (  # noqa: E402
    VERDICT_CLAIM_TOKENS,
    verdict_claims_in,
)


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
        # modes. `--list-formats` prints what this machine
        # opens and extracts nothing; `--json` shapes that listing and has
        # no meaning without it. The surface is asserted as a COMPLETE set
        # precisely so that one more cannot slip in unnoticed -- this test
        # went red on the two added here, which is what it is for.
        self.assertEqual({"--verbose", "--quiet", "--sbom", "--linked-bom",
                          "--replace", "--no-archive-dir",
                          "--list-formats", "--json",
                          "--version", "--help"}, listed)
        short = set(re.findall(r"(?<![\w-])-[a-z](?![\w-])", out))
        self.assertEqual({"-v", "-q", "-h"}, short)

    def test_the_command_has_no_self_check_gate(self):
        """No `--controle`, no `--strict`: this command has no self-check gate
        of any kind."""
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
        invocation that has no object for it: what
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

        The command is meant to grow; what it must keep saying is which floor
        it is standing on, and what is still not its job.

        AND THE CLAIM IS NARROW: a document is written ON REQUEST, and never
        otherwise. Holding published prose in a test is what keeps that
        sentence true.

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
        """The OLDER rule is kept under `--no-archive-dir`, where the
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
        """The default contract claims a NAME inside DESTINATION, not the
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
        """The refusal is on the SPECIFIC target already
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
                         no_archive_dir=False, progress=None):
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
    """The default, `--replace` and `--no-archive-dir` modes, and the
    refusals attached to each of them."""

    def test_replace_extracts_in_place_and_removes_the_archive(self):
        """The in-place mode, end to end through the command line."""
        archive = self._zip("p.zip", [("a.txt", "a")])
        code, out, _ = self._run(["--replace", str(archive)])
        self.assertEqual(0, code)
        self.assertEqual(archive, Path(out.strip()))
        self.assertTrue((archive / "a.txt").is_file())
        self.assertFalse(archive.is_file())

    def test_replace_refuses_a_destination(self):
        """A usage error, not a silently ignored argument."""
        archive = self._zip("p.zip", [("a.txt", "a")])
        code, _, err = self._run(["--replace", str(archive), str(self.dir / "out")])
        self.assertEqual(2, code)
        self.assertIn("DESTINATION is not accepted with --replace", err)
        self.assertTrue(archive.is_file(), "nothing may be touched before the refusal")

    def test_replace_refuses_a_url(self):
        """There is no local file to replace."""
        code, _, err = self._run(["--replace", "https://example.invalid/p.zip"])
        self.assertEqual(2, code)
        self.assertIn("--replace is refused on a URL", err)

    def test_replace_refuses_a_directory_source(self):
        """`prepare_source` extracts nothing on this branch --
        there is no archive for `--replace` to consume."""
        source = self.dir / "given"
        source.mkdir()
        (source / "a.txt").write_text("a", encoding="utf-8")
        code, _, err = self._run(["--replace", str(source)])
        self.assertEqual(2, code)
        self.assertIn("already a directory", err)
        self.assertTrue((source / "a.txt").is_file(), "nothing may be touched")

    def test_no_archive_dir_refuses_a_directory_source(self):
        """The same refusal for the other mode."""
        source = self.dir / "given"
        source.mkdir()
        code, _, err = self._run([str(source), str(self.dir / "out"),
                                  "--no-archive-dir"])
        self.assertEqual(2, code)
        self.assertIn("already a directory", err)

    def test_replace_and_no_archive_dir_are_refused_together(self):
        """Enforced by `build_parser`'s own mutually exclusive group."""
        archive = self._zip("p.zip", [("a.txt", "a")])
        code, _, _ = self._run(["--replace", "--no-archive-dir", str(archive)])
        self.assertEqual(2, code, "a usage error returns 2")

    def test_a_local_archive_colliding_with_its_own_destination_is_refused(self):
        """DESTINATION is the archive's own parent directory,
        so the default target IS the archive itself. The archive is a local
        file the caller did not ask to consume, so this is the existence
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
        way out the refusal names."""
        archive = self._zip("p.zip", [("a.txt", "a")])
        code, out, _ = self._run(["--replace", str(archive)])
        self.assertEqual(0, code)
        self.assertEqual(archive, Path(out.strip()))

    def test_replace_refuses_an_sbom_path_inside_the_tree_it_will_become(self):
        """The third mode: under `--replace` the tree IS the
        archive's own path, so `--sbom` pointing inside it is refused the
        same way, with nothing extracted and the archive left untouched."""
        archive = self._zip("p.zip", [("a.txt", "a")])
        code, _, err = self._run(["--replace", str(archive),
                                  "--sbom", str(archive / "sbom.json")])
        self.assertEqual(2, code)
        self.assertIn("inside the tree it inventories", err)
        self.assertTrue(archive.is_file(), "nothing may be touched before the refusal")

    def test_no_archive_dir_writes_no_sbom_anywhere_under_destination(self):
        """Under this mode the tree IS DESTINATION, so no path under
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
        # eighth is
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

    def _archive_with_unreadable_containers(self) -> Path:
        """A corrupt zip and a truncated xz, nested: both are recognised by
        their extension and neither can be read."""
        import lzma
        xz = lzma.compress(b"payload" * 1000, format=lzma.FORMAT_XZ)
        return self._zip("package.zip", [
            ("src/a.txt", "a"),
            ("tests/data/corrupt.zip", b"PK\x03\x04" + b"\x00" * 40),
            ("tests/data/truncated.xz", xz[:len(xz) // 2]),
        ])

    def test_the_summary_line_names_why_a_container_could_not_be_read(self):
        """The generic text says THAT a container was not read, never WHY.

        The native cause is carried by the report entry's `detail`, and it was
        dropped by the closing summary: a user saw "a container was recognised
        but could not be read" for a corrupt test fixture and for a genuine
        defect alike, with the cause only in a live warning scrolled far above
        -- or nowhere at all under the failure path. Reported against
        zip and xz, 19 October 2026.
        """
        archive = self._archive_with_unreadable_containers()
        for argv_tail in ([], ["--quiet"]):
            with self.subTest(argv_tail=argv_tail):
                out = self.dir / ("out" + "".join(argv_tail))
                code, _, err = self._run([str(archive), str(out), *argv_tail])
                self.assertEqual(0, code)
                lines = [line for line in err.splitlines()
                         if "Not opened -- " in line]
                self.assertEqual(2, len(lines), err)
                by_path = {("zip" if "corrupt.zip" in line else "xz"): line
                           for line in lines}
                self.assertIn("[File is not a zip file]", by_path["zip"])
                self.assertIn("[Compressed file ended before the end-of-stream "
                              "marker was reached]", by_path["xz"])

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


class TestListingWhatThisMachineCanOpen(_CommandBench):
    """`--list-formats`: what this installation does with every extension.

    THE POINT OF THE OPTION IS THE FOUR STATES, and most of what is asserted
    below is about the two that a shorter listing would lose. A machine
    without a 7-Zip binary must still be shown the delegated extensions --
    dropping them would say unboxr does not recognise them, which is a
    different claim and a false one -- and the Zstandard extensions must be
    somewhere other than "opened" or "install something", since no
    installation of anything opens them.

    EVERY EXPECTED FIGURE HERE IS COMPUTED FROM THE TABLES, never typed. A
    test that engraved 68 would be the second source of truth the feature
    exists to avoid, and it would go green on a table it no longer matches.

    100% offline, as the rest of this file: the only contact with the machine
    is the `shutil.which` sweep inside `find_7zip_binary`, and the two tests
    that care about its answer substitute it rather than depending on whether
    the machine running the suite happens to have 7-Zip installed.
    """

    # Derived, once, from the tables themselves -- the same projection the
    # command renders, computed here by an independent route so that the two
    # can disagree. Reading `project_format_support` back would assert that a
    # function equals itself.
    #
    # AND THE LARGEST STATE IS DERIVED THE SAME WAY AS THE OTHERS, which it
    # was not until code review on 15 September 2026. It read
    # `set(CATEGORY_BY_EXT) - set(DELEGATED) - set(REFUSED)` -- a verbatim
    # restatement, in the test, of the very `else:` the code used to take. The
    # "independent route" collapsed onto the code for the one state holding
    # half the table, which is why a category sorted into none of the three
    # lists went green here. It now reads its OWN positive list, so the two
    # can disagree for this state as they always could for the other three.
    DELEGATED = sorted(extension
                       for extension, category in extraction.CATEGORY_BY_EXT.items()
                       if category in extraction.CATEGORIES_NEEDING_SEVEN_ZIP)
    REFUSED = sorted(extension
                     for extension, category in extraction.CATEGORY_BY_EXT.items()
                     if category in extraction.CATEGORIES_REFUSED)
    NOT_OPENED = sorted(extraction.NOT_EXTRACTED_EXTENSIONS)
    STANDARD_LIBRARY = sorted(
        extension
        for extension, category in extraction.CATEGORY_BY_EXT.items()
        if category in extraction.CATEGORIES_OPENED_BY_THE_STANDARD_LIBRARY)

    @staticmethod
    def _tokens(out):
        """The listing wraps at a fixed width, so an extension can sit at the
        end of a line or the start of one. Splitting on whitespace asks the
        question that matters -- is this extension in the listing at all --
        without depending on where the wrap happened to fall."""
        return set(out.split())

    @staticmethod
    def _flat(out):
        """The listing with every run of whitespace collapsed to one space.

        WHY EVERY ASSERTION ON PROSE GOES THROUGH THIS. The summary paragraph
        is one `textwrap.fill(width=78)`, so where a sentence breaks depends
        on the LENGTH OF THE NUMBERS IN FRONT OF IT. Measured on 15 September
        2026: of 120 prefix offsets, 68 split an asserted phrase across a
        newline -- so `assertIn("64 of them openable on this machine", out)`
        was passing on the digits this machine happens to produce, and would
        have gone red on a machine with a different count, for a reason having
        nothing to do with what it is testing. A wrapped paragraph has no
        contiguous substrings to assert on; this gives it some.

        The precedent is in this file already: `cli.__doc__` has been asserted
        whitespace-normalised since 14.4, for the same reason.
        """
        return re.sub(r"\s+", " ", out)

    def test_the_listing_needs_no_archive_and_returns_zero(self):
        """Row 3 of the matrix: listing what this machine opens has nothing to
        do with owning an archive, which is why `archive` became an optional
        positional rather than something to fake."""
        code, out, err = self._run(["--list-formats"])
        self.assertEqual(0, code)
        self.assertNotEqual("", out.strip(), "the listing goes to stdout")
        self.assertEqual("", err.strip(),
                         "nothing about a listing belongs on stderr, and "
                         "nothing here goes through logging at all")

    def test_the_binary_that_was_found_is_named_in_the_listing(self):
        """Row 1: the presence is MEASURED, and what was measured is printed.
        A listing that said "7-Zip available" without saying WHICH one leaves
        a caller with two binaries on the PATH unable to tell which answer
        they are reading."""
        with mock.patch.object(extraction, "find_7zip_binary",
                               return_value="/opt/bin/7zz"):
            code, out, _ = self._run(["--list-formats"])
        self.assertEqual(0, code)
        self.assertIn("/opt/bin/7zz", out)
        self.assertIn("AVAILABLE on this machine", out)
        self.assertNotIn("NOT AVAILABLE", out)

    def test_a_machine_without_the_binary_still_lists_every_delegated_extension(self):
        """Row 2, and the acceptance criterion the whole feature turns on.

        The delegated extensions are RECOGNISED whatever this machine has
        installed; only their openability here is in question. Removing them
        from the listing would answer a question nobody asked ("does unboxr
        know `.rar`?") with a false "no". They stay, and the answer that does
        change is written next to them.
        """
        with mock.patch.object(extraction, "find_7zip_binary", return_value=None):
            code, out, _ = self._run(["--list-formats"])
        self.assertEqual(0, code)
        self.assertIn("No 7-Zip binary found on this machine", out)
        self.assertIn("NOT AVAILABLE on this machine", out)
        printed = self._tokens(out)
        for extension in self.DELEGATED:
            with self.subTest(extension=extension):
                self.assertIn(extension, printed)
        self.assertIn(f"-- {len(self.DELEGATED)} extension(s)", out)

    def test_a_machine_without_the_binary_counts_them_out_of_what_it_opens(self):
        """The same absence, in the one number a reader will act on. Listing
        them and counting them as openable would be the same false claim made
        arithmetically."""
        with mock.patch.object(extraction, "find_7zip_binary", return_value=None):
            _, out, _ = self._run(["--list-formats"])
            _, raw, _ = self._run(["--list-formats", "--json"])
        openable = len(self.STANDARD_LIBRARY)
        self.assertIn(f"{openable} of them openable on this machine",
                      self._flat(out))
        self.assertEqual(openable,
                         json.loads(raw)["extensions_openable_here"])

    def test_the_four_states_hold_every_extension_of_the_two_tables_once(self):
        """The acceptance criterion in its arithmetic form: the states are a
        PARTITION of `CATEGORY_BY_EXT` plus `NOT_EXTRACTED_EXTENSIONS`, so no
        extension is silently in two of them and none is in none. A listing
        that lost an extension between the tables and the screen would be an
        omission, and an omission asserts."""
        _, raw, _ = self._run(["--list-formats", "--json"])
        states = json.loads(raw)["states"]

        seen = []
        for state in states.values():
            seen.extend(state["extensions"])
        expected = set(extraction.CATEGORY_BY_EXT) | set(
            extraction.NOT_EXTRACTED_EXTENSIONS)
        self.assertEqual(sorted(expected), sorted(seen),
                         "every extension of the two tables, exactly once")
        self.assertEqual(len(extraction.CATEGORY_BY_EXT)
                         + len(extraction.NOT_EXTRACTED_EXTENSIONS), len(seen))
        self.assertEqual(
            {"opened_by_the_standard_library": self.STANDARD_LIBRARY,
             "delegated_to_seven_zip": self.DELEGATED,
             "recognised_and_refused": self.REFUSED,
             "recognised_and_not_opened": self.NOT_OPENED},
            {name: state["extensions"] for name, state in states.items()})

    def test_the_zstandard_extensions_are_in_a_state_of_their_own(self):
        """Neither opened nor waiting for an installation. A two-column
        listing would have to put them in one of those, and both are false:
        the standard library has no reader for them here and 7-Zip does not
        handle the format either."""
        _, raw, _ = self._run(["--list-formats", "--json"])
        states = json.loads(raw)["states"]
        refused = states["recognised_and_refused"]
        self.assertEqual(self.REFUSED, refused["extensions"])
        self.assertFalse(refused["openable_here"])
        self.assertFalse(refused["depends_on_this_machine"],
                         "no machine opens these: the answer is the same "
                         "everywhere, and saying otherwise would send a "
                         "reader off to install something")
        self.assertTrue(states["delegated_to_seven_zip"]["depends_on_this_machine"],
                        "exactly one state depends on the machine")

    def test_every_printed_total_is_the_length_of_a_table(self):
        """The guard against a number that drifts. Each figure the listing
        prints is compared with the table it claims to count -- not with a
        figure recorded from an earlier run, which is how a stale number
        survives a change to the tables."""
        _, out, _ = self._run(["--list-formats"])
        flat = self._flat(out)
        self.assertIn(f"{len(extraction.CATEGORY_BY_EXT)} recognised extensions",
                      flat)
        self.assertIn(f"{len(extraction.NOT_EXTRACTED_EXTENSIONS)} more are "
                      f"recognised as containers", flat)
        self.assertIn(f"{len(extraction.CATEGORY_BY_EXT) + len(extraction.NOT_EXTRACTED_EXTENSIONS)} "
                      f"listed here", flat)
        for extensions in (self.STANDARD_LIBRARY, self.DELEGATED,
                           self.REFUSED, self.NOT_OPENED):
            with self.subTest(count=len(extensions)):
                # The heading is the one line of the listing that is NOT
                # wrapped prose -- it is appended whole -- so it is asserted
                # on the raw output on purpose.
                self.assertIn(f"-- {len(extensions)} extension(s)", out)

    def test_a_total_follows_the_table_rather_than_being_written_down(self):
        """And this is the one that would catch a literal.

        The test above compares what is printed with `len(TABLE)`, which stays
        green for a hard-coded 68 as long as the table happens to hold 68
        entries -- it only bites on the day someone adds an extension, which
        is exactly when nobody is running it for this reason. So the tables
        are given one more entry HERE, and the listing has to follow: a figure
        typed into the source cannot.

        BOTH TABLES, AND THAT IS THE FIX CODE REVIEW ASKED FOR ON 15 SEPTEMBER
        2026. This case used to perturb `CATEGORY_BY_EXT` alone, so THREE of
        the five printed totals could be hard-coded with the suite still fully
        green -- verified by mutation: `"not_extracted_extensions": 38`,
        `"listed_extensions": 106` and the fourth state's own `"count"` all
        passed as literals. `NOT_EXTRACTED_EXTENSIONS` is a `frozenset`, which
        `mock.patch.dict` cannot extend at all; `mock.patch.object` replaces
        the name outright, and the projection reads the global at call time,
        so it follows.
        """
        widened = frozenset(extraction.NOT_EXTRACTED_EXTENSIONS
                            | {".notacontainer"})
        with mock.patch.dict(extraction.CATEGORY_BY_EXT,
                             {".notanextension": "zip"}), \
                mock.patch.object(extraction, "NOT_EXTRACTED_EXTENSIONS",
                                  widened):
            recognised = len(extraction.CATEGORY_BY_EXT)
            not_extracted = len(extraction.NOT_EXTRACTED_EXTENSIONS)
            _, out, _ = self._run(["--list-formats"])
            _, raw, _ = self._run(["--list-formats", "--json"])
        flat = self._flat(out)
        document = json.loads(raw)

        self.assertIn(f"{recognised} recognised extensions", flat)
        self.assertNotIn(f"{recognised - 1} recognised extensions", flat)
        self.assertIn(".notanextension", self._tokens(out))

        # The second table, in the three figures that used to be free to be
        # literals: its own total, the grand total that includes it, and the
        # per-state count of the state it alone feeds.
        self.assertIn(f"{not_extracted} more are recognised as containers",
                      flat)
        self.assertNotIn(f"{not_extracted - 1} more are recognised as "
                         f"containers", flat)
        self.assertIn(f"{recognised + not_extracted} listed here", flat)
        self.assertIn(f"-- {not_extracted} extension(s)", out)
        self.assertIn(".notacontainer", self._tokens(out))

        self.assertEqual(recognised, document["recognised_extensions"])
        self.assertEqual(not_extracted, document["not_extracted_extensions"])
        self.assertEqual(recognised + not_extracted,
                         document["listed_extensions"])
        self.assertEqual(not_extracted,
                         document["states"]["recognised_and_not_opened"]["count"])

    def test_the_json_listing_is_read_back_and_agrees_with_the_text(self):
        """Row 4: the same four states and the same totals, in a shape a
        consumer can read. One projection, two renderings -- the JSON cannot
        carry a number the text contradicts, and this says so rather than
        leaving it to be inferred from the code."""
        _, text_out, _ = self._run(["--list-formats"])
        code, raw, err = self._run(["--list-formats", "--json"])
        self.assertEqual(0, code)
        self.assertEqual("", err.strip())

        document = json.loads(raw)
        self.assertEqual(__version__, document["unboxr"])
        self.assertEqual(cli.FORMAT_SUPPORT_DOCUMENT_KIND, document["kind"])
        self.assertEqual(list(extraction.FORMAT_SUPPORT_STATES),
                         list(document["states"]))
        flat = self._flat(text_out)
        self.assertIn(f"{document['recognised_extensions']} recognised "
                      f"extensions", flat)
        self.assertIn(f"{document['listed_extensions']} listed here", flat)
        self.assertIn(f"{document['extensions_openable_here']} of them "
                      f"openable", flat)
        for name, state in document["states"].items():
            with self.subTest(state=name):
                self.assertEqual(sorted(state["extensions"]),
                                 state["extensions"], "sorted, so two runs "
                                                      "can be compared")
                self.assertEqual(len(state["extensions"]), state["count"])

    def test_json_without_the_listing_is_refused_with_its_cause(self):
        """Row 5: `--json` shapes a listing, and there is no other
        machine-readable output to shape. Accepting it on an extraction would
        promise a JSON that is never printed."""
        archive = self._zip("p.zip", [("a.txt", "a")])
        destination = self.dir / "out"
        code, out, err = self._run([str(archive), str(destination), "--json"])
        self.assertEqual(2, code)
        self.assertIn("--json", err)
        self.assertIn("--list-formats", err)
        self.assertEqual("", out.strip())
        self.assertFalse(destination.exists(),
                         "nothing is created before a usage refusal")

    def test_the_listing_together_with_an_extraction_is_refused(self):
        """Row 6, and the reason it is a refusal rather than a courtesy.

        `unboxr a.zip dest --list-formats` would print a listing, extract
        nothing, and exit 0. The caller would read a successful-looking run as
        an extraction that happened -- an option ignored in silence makes
        someone believe in work that was never done.
        """
        archive = self._zip("p.zip", [("a.txt", "a")])
        destination = self.dir / "out"
        code, out, err = self._run([str(archive), str(destination),
                                    "--list-formats"])
        self.assertEqual(2, code)
        self.assertIn("--list-formats", err)
        self.assertIn("ARCHIVE", err)
        self.assertIn("DESTINATION", err)
        self.assertEqual("", out.strip(), "no listing is printed either")
        self.assertFalse(destination.exists(), "and nothing was extracted")

    def test_the_listing_is_refused_with_options_it_would_have_ignored(self):
        """The same refusal, for the options that describe a document rather
        than a tree. `--sbom` names a file this mode does not write and
        `--linked-bom` a link it does not record; accepting either would be
        the same silence coming in by another door.

        THE LINK IS REFUSED HERE EVEN WHEN ITS URN IS PERFECTLY WELL FORMED,
        which is what pins the ORDER: these two refusals run before
        `check_linked_bom`, so a caller who is not extracting anything is told
        the listing takes no such option rather than being sent to add the
        `--sbom` that would never have been written either."""
        document = self.dir / "doc.json"
        for extra in (["--sbom", str(document)],
                      ["--linked-bom",
                       "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1"],
                      ["--replace"],
                      ["--no-archive-dir"]):
            with self.subTest(extra=extra[0]):
                code, out, err = self._run(["--list-formats"] + extra)
                self.assertEqual(2, code)
                self.assertIn(extra[0], err)
                self.assertEqual("", out.strip())
                self.assertFalse(document.exists())

    def test_an_invocation_with_nothing_at_all_still_asks_for_the_archive(self):
        """Row 7: `archive` became an optional positional, so argparse stopped
        writing this sentence -- and the refusal it used to produce must not
        have gone with it. Same code, same word, and the condition that made
        the positional optional appended to it."""
        code, out, err = self._run([])
        self.assertEqual(2, code)
        # ON THE SENTENCE, NOT ON THE WORD. `assertIn("archive", err)` passes
        # on the usage line argparse prints above every refusal -- which names
        # the positional, and `--list-formats` too, whatever the actual cause
        # was. Measured by mutation: with the refusal removed, the run fell
        # through to the DESTINATION refusal and this test stayed green.
        self.assertIn("required: archive", err)
        self.assertIn("omit it only together with --list-formats", err)
        self.assertEqual("", out.strip())

    def test_the_listing_is_sorted_and_two_calls_in_one_interpreter_agree(self):
        """RENAMED TO WHAT IT ACTUALLY CHECKS, and given the assertion that
        makes it check anything at all.

        It was called "two runs on one machine print exactly the same thing"
        and it called `main` twice INSIDE ONE INTERPRETER, where the iteration
        order of a `dict` and of a `frozenset` is constant by construction:
        deleting `sorted(...)` from the projection left it green -- verified
        by mutation on 15 September 2026. Two calls in one process can only
        catch a listing that varies with something OTHER than hash seeding,
        which is a real property and is what this case now claims.

        The order itself is asserted DIRECTLY, on the extensions, which is
        what "deterministic" means here and is the thing the removed `sorted`
        would break. What no single interpreter can answer -- does the order
        survive a different hash seed -- is the case below, in a subprocess.
        """
        _, first, _ = self._run(["--list-formats"])
        _, second, _ = self._run(["--list-formats"])
        self.assertEqual(first, second)
        _, first_json, _ = self._run(["--list-formats", "--json"])
        _, second_json, _ = self._run(["--list-formats", "--json"])
        self.assertEqual(first_json, second_json)
        for name, state in json.loads(first_json)["states"].items():
            with self.subTest(state=name):
                self.assertEqual(sorted(state["extensions"]),
                                 state["extensions"])

    def test_the_listing_survives_a_different_interpreter_hash_seed(self):
        """The determinism claim, asked of the only thing that can answer it.

        `NOT_EXTRACTED_EXTENSIONS` is a `frozenset` of strings, so its
        iteration order is a property of the interpreter's HASH SEED -- fixed
        for the life of a process, and different between two processes started
        with different seeds. Nothing inside one interpreter can see that, so
        the guard runs the command in two subprocesses with `PYTHONHASHSEED`
        set to two different values and compares the bytes.

        WHAT EACH OF THE TWO CASES BUYS, since removing `sorted(...)` from the
        projection now turns BOTH of them red and neither alone would say why.
        The one above checks the ORDER, which is a claim about one run; this
        one checks that the order does not depend on the interpreter that
        produced it, which is the only claim a caller comparing two machines'
        listings can use. Before 15 September 2026 there was one case, it
        called `main` twice in this process, and deleting `sorted(...)` left it
        green -- it asserted neither.

        Offline like the rest of the file: `--list-formats` opens no archive
        and touches no network.
        """
        outputs = []
        for seed in ("0", "1", "12345"):
            environment = dict(os.environ,
                               PYTHONHASHSEED=seed,
                               PYTHONPATH=str(REPO_ROOT))
            result = subprocess.run(
                [sys.executable, "-m", "unboxr.cli", "--list-formats",
                 "--json"],
                cwd=str(REPO_ROOT), env=environment, capture_output=True,
                text=True, encoding="utf-8", timeout=120)
            self.assertEqual(0, result.returncode, result.stderr)
            outputs.append(result.stdout)
        self.assertEqual(1, len(set(outputs)),
                         "three hash seeds, three identical listings")

    def test_the_listing_mints_no_verdict_of_any_kind(self):
        """`tests/test_boundaries.py` holds this guard for the SOURCE of the
        package. What it cannot see is a sentence assembled at run time out of
        the tables, which is what a caller of this option actually reads -- so
        the rendered text and the rendered JSON are checked here, on the
        output itself.

        The words are the ones that would turn a capability listing into a
        judgement about what an archive CONTAINS. This option answers "can
        this installation open a file with this name", and nothing else.

        THE LIST IS NOT WRITTEN HERE: it comes from `tests/test_boundaries.py`,
        so that one file holds the vocabulary decision.

        AND THE GUARD CAN NOW TELL A DISCLAIMER FROM A CLAIM.
        `assertNotIn("verdict", out.lower())` fires on this package's own
        sentence, "unboxr renders no verdict on what it extracts", which
        `--help` already prints; a guard that goes red on the disclaimer it
        protects is a guard someone deletes. `verdict_claims_in` strikes the
        disclaimers out first and is itself tested, on both halves, in
        `tests/test_boundaries.py`.
        """
        _, out, _ = self._run(["--list-formats"])
        _, raw, _ = self._run(["--list-formats", "--json"])
        for rendered in (out, raw):
            self.assertEqual([], verdict_claims_in(rendered))
        self.assertIn("verdict", VERDICT_CLAIM_TOKENS,
                      "the word this option is most at risk of using is in "
                      "the list it is checked against")

    def test_the_printed_breakdown_adds_up_to_the_total_in_front_of_it(self):
        """The one sentence of the listing a reader checks by adding.

        "68 recognised extensions: 33 by the standard library, 31 delegated to
        7-Zip, 4 recognised and refused." That breakdown was a hand-written
        3-tuple until 15 September 2026, under a comment claiming every table
        here is iterated through `FORMAT_SUPPORT_STATES` so that a state can
        go missing from none of them. Measured: a FIFTH state made the
        sentence print an addition that does not add up, in public, while the
        suite stayed green.

        So the addition is asserted, on the PRINTED figures, parsed back out
        of the sentence itself -- not on the projection, which is where the
        numbers being added come from.
        """
        _, out, _ = self._run(["--list-formats"])
        flat = self._flat(out)
        match = re.search(r"(\d+) recognised extensions: (.+?)\. \d+ more are",
                          flat)
        self.assertIsNotNone(match, flat)
        total = int(match.group(1))
        parts = [int(number) for number in re.findall(r"(\d+) ",
                                                      match.group(2) + " ")]
        self.assertEqual(total, sum(parts),
                         f"the breakdown {parts} must add up to {total}")
        # And it names every state EXCEPT the one fed by the other table --
        # which is the whole reason the fourth is not in the sum.
        self.assertEqual(len(extraction.FORMAT_SUPPORT_STATES) - 1, len(parts))

    def test_a_state_with_nothing_in_it_says_so(self):
        """A heading, a four-line note about extensions, and then a blank
        line where the extensions would be: that is what an emptied state
        printed until 15 September 2026, and a reader has no way to tell it
        from a rendering that lost them.

        The state STAYS in the listing -- dropping the heading would be the
        omission the four states exist to prevent -- and the note that
        describes extensions it does not have is not printed over nothing.
        """
        without_zstd = {extension: category
                        for extension, category
                        in extraction.CATEGORY_BY_EXT.items()
                        if category not in extraction.CATEGORIES_REFUSED}
        with mock.patch.object(extraction, "CATEGORY_BY_EXT", without_zstd):
            _, out, _ = self._run(["--list-formats"])
            _, raw, _ = self._run(["--list-formats", "--json"])
        self.assertIn("Recognised and refused -- 0 extension(s)", out,
                      "the state is still there, and still counted")
        self.assertIn(cli.EMPTY_STATE_LINE, out)
        self.assertNotIn("No machine opens these", out,
                         "the note describes extensions this state does not "
                         "have")
        self.assertEqual(
            [], json.loads(raw)["states"]["recognised_and_refused"]["extensions"])

    def test_the_new_option_makes_two_abbreviations_of_linked_bom_ambiguous(self):
        """PINNED, because it is a real regression and a declared fact is
        better than a surprise.

        `--l` and `--li` are prefixes of both `--linked-bom` and
        `--list-formats`, so argparse refuses them with "ambiguous option" and
        exits 2. Both options keep their names, and `allow_abbrev` stays on,
        because turning it off would break EVERY abbreviation of every option
        rather than these two.

        AND THE BOUNDARY IS PINNED WITH IT, so that this documents exactly two
        lost spellings and not a family: `--lin` and everything longer still
        reach `--linked-bom`, because `--list-formats` stops sharing the
        prefix at the third letter.
        """
        urn = "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1"
        for ambiguous in ("--l", "--li"):
            with self.subTest(lost=ambiguous):
                code, out, err = self._run([ambiguous, urn])
                self.assertEqual(2, code)
                self.assertIn("ambiguous option", err)
                self.assertIn("--linked-bom", err)
                self.assertIn("--list-formats", err)
                self.assertEqual("", out.strip())
        # And the two prefixes are the WHOLE of it: the moment the spellings
        # diverge, the abbreviation reaches `--linked-bom` as it always did,
        # and is answered by the refusal that has nothing to do with prefixes.
        for unaffected in ("--lin", "--link", "--linked", "--linked-bom"):
            with self.subTest(kept=unaffected):
                code, _, err = self._run([unaffected, urn, "a.zip", "d"])
                self.assertEqual(2, code)
                self.assertNotIn("ambiguous", err)
                self.assertIn("--sbom", err, "it reached check_linked_bom, "
                                             "which is what it used to do")

    def test_an_unprintable_seven_zip_path_degrades_instead_of_killing_the_run(self):
        """The one command whose job is to REPORT the binary must be able to
        print it.

        Reproduced on Windows on 15 September 2026: `stdout` redirected under
        `cp1252`, a 7-Zip path holding CJK characters, and `--list-formats`
        died with a raw `UnicodeEncodeError` traceback, return code 1, ZERO
        bytes of listing. The path is taken off the machine; a machine is free
        to hold one its own console codec cannot carry.

        The degradation is VISIBLE -- backslash escapes, not a question mark
        -- so two different paths stay two different strings, and the rest of
        the listing is printed in full.
        """
        awkward = "C:\\\u30c4\u30fc\u30eb\\7z.exe"
        stream = io.TextIOWrapper(io.BytesIO(), encoding="cp1252",
                                  errors="strict", newline="")
        with mock.patch.object(extraction, "find_7zip_binary",
                               return_value=awkward):
            with _isolated_logger():
                with contextlib.redirect_stdout(stream):
                    code = cli.main(["--list-formats"])
                stream.flush()
        printed = stream.buffer.getvalue().decode("cp1252")
        self.assertEqual(0, code)
        self.assertIn("7-Zip binary found:", printed)
        self.assertIn("\\u30c4", printed, "escaped, and still readable")
        self.assertIn("extension(s)", printed, "the whole listing is printed")
        self.assertIn(".zip", printed)

    def test_the_json_listing_carries_no_byte_a_codec_can_refuse(self):
        """The machine-readable rendering survives the same stream, and it
        does so by DEPENDING on `json.dumps` defaulting to
        `ensure_ascii=True` rather than by any property of the data. Stated
        here so that the day someone passes `ensure_ascii=False` for prettier
        output, this case says what it costs."""
        awkward = "C:\\\u30c4\u30fc\u30eb\\7z.exe"
        with mock.patch.object(extraction, "find_7zip_binary",
                               return_value=awkward):
            _, raw, _ = self._run(["--list-formats", "--json"])
        self.assertEqual(raw, raw.encode("ascii").decode("ascii"))
        self.assertEqual(awkward, json.loads(raw)["seven_zip_binary"])


class TestTheProjectionClassifiesByPositiveLists(unittest.TestCase):
    """A category nobody sorted is an ANOMALY, never "opened everywhere".

    THE DEFECT THIS CLASS CLOSES, measured in code review on 15 September
    2026. `project_format_support` filed every category belonging to neither
    `CATEGORIES_NEEDING_SEVEN_ZIP` nor `CATEGORIES_REFUSED` under "opened by
    the standard library" through a bare `else:` -- and the note printed under
    that heading says "opened here and on every machine". Adding
    `".lz4": "lz4_unsupported"` to `CATEGORY_BY_EXT` WITH a correct dispatch
    branch raising `UnsupportedFormatError`, and forgetting
    `CATEGORIES_REFUSED`, left the entire suite green and made the listing
    promise a caller that `.lz4` opens everywhere, while the extraction
    raised.

    The favourable state was the fall-through default. It is now read from its
    own positive list like the other two, and what belongs to none of them
    stops the projection by name.
    """

    def test_a_category_in_no_named_list_is_a_named_anomaly(self):
        """The mutation that used to pass, as a test. A format implemented
        correctly everywhere ELSE -- recognised, dispatched, refused out loud
        -- and simply not sorted into a state."""
        with mock.patch.dict(extraction.CATEGORY_BY_EXT,
                             {".lz4": "lz4_unsupported"}):
            with self.assertRaises(extraction.UnclassifiedCategoryError) as raised:
                extraction.project_format_support()
        message = str(raised.exception)
        self.assertIn("lz4_unsupported", message,
                      "the message names the category nobody sorted")
        self.assertIn(".lz4", message)

    def test_the_command_fails_loudly_rather_than_printing_a_false_listing(self):
        """And it reaches the command: the anomaly is not swallowed on the
        way to the screen. A listing that cannot be trusted is not printed."""
        with mock.patch.dict(extraction.CATEGORY_BY_EXT,
                             {".lz4": "lz4_unsupported"}):
            with self.assertRaises(extraction.UnclassifiedCategoryError):
                cli.main(["--list-formats"])

    def test_every_category_of_the_table_is_in_exactly_one_named_list(self):
        """The standing invariant, asserted against the tables rather than
        against a run: the three lists PARTITION the categories in use.

        Both directions matter. A category in the table and in no list is the
        defect above. A category in a list and in no table is dead wood that
        makes the next reader believe an extension exists.
        """
        named = {
            "seven_zip": set(extraction.CATEGORIES_NEEDING_SEVEN_ZIP),
            "refused": set(extraction.CATEGORIES_REFUSED),
            "standard_library": set(
                extraction.CATEGORIES_OPENED_BY_THE_STANDARD_LIBRARY),
        }
        union = set().union(*named.values())
        self.assertEqual(set(extraction.CATEGORY_BY_EXT.values()), union)
        self.assertEqual(sum(len(names) for names in named.values()),
                         len(union), "the three lists do not overlap")

    def test_two_tables_that_stop_being_disjoint_are_an_anomaly_too(self):
        """The other way the four states stop being a partition, and the one
        no total can see: an extension in BOTH tables lands in two states, and
        its state's count and the sum over the states move by one each. The
        arithmetic still agrees -- on a wrong number.

        The comment that used to sit on `listed_extensions` claimed the sum
        was the check ("if the partition above ever stopped being one, this
        total would move"). It is not, and this is.
        """
        overlapping = frozenset(extraction.NOT_EXTRACTED_EXTENSIONS | {".zip"})
        with mock.patch.object(extraction, "NOT_EXTRACTED_EXTENSIONS",
                               overlapping):
            with self.assertRaises(extraction.UnclassifiedCategoryError) as raised:
                extraction.project_format_support()
        self.assertIn(".zip", str(raised.exception))



# ---------------------------------------------------------------------------
# The progress line: one line rewritten in place, for a person at a terminal
# ---------------------------------------------------------------------------
class _FakeTerminal(io.StringIO):
    """A stream that says it is a terminal, with the codec a terminal has.

    `io.StringIO` answers `isatty()` with False and carries no encoding, which
    is exactly why every other test in this file sees no progress line.
    """

    def __init__(self, encoding: str = "utf-8"):
        super().__init__()
        self._encoding = encoding

    @property
    def encoding(self):
        return self._encoding

    def isatty(self):
        if self.closed:
            raise ValueError("I/O operation on closed file")
        return True


class _LineRefusingTerminal(_FakeTerminal):
    """A terminal that fails every write starting with a carriage return --
    the progress line's -- and lets everything else, records included, through.
    """

    def write(self, text):
        if text.startswith("\r"):
            raise OSError("the console went away")
        return super().write(text)


class _FailsAfterFirstDraw(_FakeTerminal):
    """A terminal that accepts the first draw of the line, then fails every
    later one: the first draw stays on the screen, and nothing can erase it."""

    def __init__(self):
        super().__init__()
        self.draws = 0

    def write(self, text):
        if text.startswith("\r"):
            self.draws += 1
            if self.draws > 1:
                raise OSError("the console went away")
        return super().write(text)


class _FlushFailsOnce(_FakeTerminal):
    """A terminal whose first flush fails -- after the text has landed."""

    def __init__(self):
        super().__init__()
        self.failed = False

    def flush(self):
        if not self.failed:
            self.failed = True
            raise OSError("the console went away")
        return super().flush()


def _screen(text: str) -> list[str]:
    """What a terminal shows once `text` has been written to it.

    A carriage return moves the cursor to the start of the line WITHOUT
    erasing it, so a shorter text written over a longer one leaves the end of
    the longer one visible. Asserting on the raw stream would miss exactly
    that; replaying it here does not.
    """
    lines, current, column = [], [], 0
    for char in text:
        if char == "\r":
            column = 0
        elif char == "\n":
            lines.append("".join(current).rstrip())
            current, column = [], 0
        else:
            if column < len(current):
                current[column] = char
            else:
                current.append(char)
            column += 1
    lines.append("".join(current).rstrip())
    return lines


def _line_writes(text: str) -> list[str]:
    """Every write of the progress line: what follows a carriage return up to
    the next one, when no newline intervenes (a record always ends with one)."""
    return [segment for segment in text.split("\r")[1:] if "\n" not in segment]


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def _nested_zip(path: Path) -> Path:
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as archive:
        archive.writestr("src/a.c", "int a;")
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("vendor/a-very-long-directory-name/lib.zip",
                         inner.getvalue())
        archive.writestr("readme.txt", "r")
    return path


class TestTheProgressLineRendering(unittest.TestCase):
    """The line drawn from one event: width, truncation, glyphs, clock."""

    def _line(self, stream=None, *, width=40, glyphs=None, clock=None):
        stream = _FakeTerminal() if stream is None else stream
        return stream, cli._StatusLine(
            stream, glyphs=glyphs or cli._ASCII_GLYPHS,
            width=lambda: width, clock=clock or _Clock())

    def test_a_nested_archive_shows_level_bar_count_path_and_clock(self):
        event = extraction.ProgressEvent(phase="nested", level=2, index=3, total=7,
                                         path="lib/a.tar.gz", seven_zip=True)
        text = cli._render_status(event, 12.4, 0, 80, cli._ASCII_GLYPHS)
        self.assertEqual("| level 2 [###---------] 3/7  lib/a.tar.gz (7-Zip)  00:12",
                         text)

    def test_the_bar_counts_the_archives_done_never_the_one_in_hand(self):
        first = extraction.ProgressEvent(phase="nested", level=1, index=1, total=4)
        last = extraction.ProgressEvent(phase="nested", level=1, index=4, total=4)
        self.assertIn("[------------]", cli._render_status(
            first, 0, 0, 80, cli._ASCII_GLYPHS))
        self.assertIn("[#########---]", cli._render_status(
            last, 0, 0, 80, cli._ASCII_GLYPHS))

    def test_each_opaque_phase_has_its_words_and_no_bar(self):
        for event, words in (
                (extraction.ProgressEvent(phase="download", path="https://h/p.zip"),
                 "downloading https://h/p.zip"),
                (extraction.ProgressEvent(phase="digest"),
                 "hashing input"),
                (extraction.ProgressEvent(phase="input", path="p.zip"),
                 "extracting p.zip"),
                (extraction.ProgressEvent(phase="scan", level=3),
                 "level 3: looking for nested archives")):
            with self.subTest(phase=event.phase):
                text = cli._render_status(event, 0, 0, 80, cli._ASCII_GLYPHS)
                self.assertIn(words, text)
                self.assertNotIn("[", text)

    def test_the_clock_reads_minutes_then_hours(self):
        self.assertEqual("00:00", cli._elapsed_text(0))
        self.assertEqual("01:15", cli._elapsed_text(75.9))
        self.assertEqual("1:02:05", cli._elapsed_text(3725))

    def test_the_line_never_reaches_the_last_column(self):
        """A line that wraps can no longer be rewritten by a carriage return:
        every rewrite would then add a line instead of replacing one."""
        long_path = "/".join(["directory"] * 12) + "/archive.tar.gz"
        wide_path = "\u4e2d\u6587" * 20 + ".zip"
        for width in (8, 20, 40, 80, 200):
            for path in (long_path, wide_path):
                for glyphs in (cli._ASCII_GLYPHS, cli._UNICODE_GLYPHS):
                    stream, line = self._line(width=width, glyphs=glyphs)
                    line.update(extraction.ProgressEvent(
                        phase="nested", level=12, index=999, total=1000, path=path,
                        seven_zip=True))
                    for event in ("input", "download", "scan", "digest"):
                        line.update(extraction.ProgressEvent(phase=event, path=path))
                    line.stop()
                    for written in _line_writes(stream.getvalue()):
                        with self.subTest(width=width, path=path[:12]):
                            self.assertLessEqual(cli._columns(written),
                                                 width - 1)

    def test_a_long_path_is_cut_from_the_left(self):
        """The end of a path names the archive; the start only says where."""
        event = extraction.ProgressEvent(
            phase="nested", level=1, index=1, total=1,
            path="vendor/a-very-long-directory-name/lib.zip")
        wide = cli._render_status(event, 0, 0, 64, cli._ASCII_GLYPHS)
        self.assertEqual("| level 1 [------------] 1/1  ...-directory-name/lib.zip  00:00",
                         wide)
        self.assertEqual(63, len(wide))
        # Narrower, the bar halves before the path goes entirely.
        self.assertEqual("| level 1 [------] 1/1  ...b.zip  00:00",
                         cli._render_status(event, 0, 0, 40, cli._ASCII_GLYPHS))

    def test_the_clock_is_the_last_thing_to_go(self):
        event = extraction.ProgressEvent(phase="scan", level=1)
        self.assertEqual("| level 1: looking for ne...  00:00",
                         cli._render_status(event, 0, 0, 36, cli._ASCII_GLYPHS))

    def test_on_a_tiny_terminal_the_marker_goes_before_the_clock(self):
        """And the clock is shown whole or not at all: "12:3" reads as a time."""
        event = extraction.ProgressEvent(phase="nested", level=1, index=1,
                                         total=1, path="p.7z", seven_zip=True)
        whole_tail = " (7-Zip)  12:34"
        for width in range(2, 17):
            with self.subTest(width=width):
                text = cli._render_status(event, 754, 0, width,
                                          cli._ASCII_GLYPHS)
                self.assertLessEqual(len(text), width - 1)
                if width - 1 < len(whole_tail):
                    self.assertNotIn("(7-Zip", text)
                if ":" in text:
                    self.assertTrue(text.endswith("12:34"), text)
        # Where marker and clock just fit, the words have already gone.
        self.assertEqual(whole_tail, cli._render_status(
            event, 754, 0, 16, cli._ASCII_GLYPHS))
        self.assertTrue(cli._render_status(
            event, 754, 0, 12, cli._ASCII_GLYPHS).endswith("  12:34"))
        self.assertIn("(7-Zip)", cli._render_status(
            event, 754, 0, 40, cli._ASCII_GLYPHS))

    def test_an_ambiguous_width_character_counts_as_two_columns(self):
        """Conservative on purpose: a line one column short costs nothing, a
        line that wraps cannot be rewritten."""
        ellipsis, block = chr(0x2026), chr(0x2588)
        self.assertEqual(2, cli._columns(ellipsis))
        self.assertEqual(2, cli._columns(block))
        self.assertEqual(1, cli._columns("a"))

    def test_a_path_cannot_break_the_line(self):
        event = extraction.ProgressEvent(phase="input", path="a\nb\tc.zip")
        text = cli._render_status(event, 0, 0, 80, cli._ASCII_GLYPHS)
        self.assertNotIn("\n", text)
        self.assertNotIn("\t", text)
        self.assertIn("a\\nb\\tc.zip", text)

    def test_a_path_the_codec_cannot_carry_is_escaped(self):
        event = extraction.ProgressEvent(phase="input", path="\u4e2d.zip")
        text = cli._render_status(event, 0, 0, 80, cli._ASCII_GLYPHS, "cp1252")
        self.assertIn("\\u4e2d.zip", text)

    def test_stopping_leaves_the_line_blank_and_the_cursor_at_its_start(self):
        stream, line = self._line()
        line.update(extraction.ProgressEvent(phase="scan", level=1))
        line.stop()
        self.assertTrue(stream.getvalue().endswith("\r" + " " * 39 + "\r"))
        self.assertEqual([""], _screen(stream.getvalue()))

    def test_nothing_is_drawn_before_the_first_event(self):
        stream, line = self._line()
        line.tick()
        line.stop()
        self.assertEqual("", stream.getvalue())

    def test_the_ticker_turns_the_spinner_and_the_clock(self):
        clock = _Clock()
        stream, line = self._line(clock=clock)
        line.update(extraction.ProgressEvent(phase="scan", level=1))
        clock.now += 61
        line.tick()
        line.stop()
        draws = _line_writes(stream.getvalue())
        self.assertTrue(draws[0].startswith("| level 1"))
        self.assertTrue(draws[1].startswith("/ level 1"))
        self.assertIn("01:01", draws[1])

    def test_the_ticker_thread_ends_with_the_line(self):
        stream, line = self._line()
        line.start_ticker(interval=0.001)
        line.update(extraction.ProgressEvent(phase="scan", level=1))
        line.stop()
        self.assertFalse(line._ticker.is_alive())
        self.assertEqual([""], _screen(stream.getvalue()))

    def test_a_failing_stream_switches_the_line_off_and_nothing_else(self):
        stream, line = self._line(stream=_LineRefusingTerminal())
        line.update(extraction.ProgressEvent(phase="scan", level=1))
        self.assertTrue(line.broken)
        line.update(extraction.ProgressEvent(phase="scan", level=2))
        line.stop()
        # The failed write may have put part of the line on the screen, so
        # it is closed with a newline, once. Nothing else is written.
        self.assertEqual("\n", stream.getvalue())

    def _record_after(self, stream, line):
        handler = cli._ProgressAwareHandler(stream=stream)
        handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        handler.status_line = line
        handler.emit(logging.makeLogRecord(
            {"msg": "next", "levelname": "INFO", "levelno": logging.INFO}))
        return handler

    def test_a_record_never_lands_glued_to_a_line_that_went_broken(self):
        stream, line = self._line(stream=_FailsAfterFirstDraw())
        line.update(extraction.ProgressEvent(phase="scan", level=1))
        line.update(extraction.ProgressEvent(phase="scan", level=2))
        self.assertTrue(line.broken)
        self._record_after(stream, line)
        screen = _screen(stream.getvalue())
        self.assertTrue(screen[0].startswith("| level 1"), screen)
        self.assertEqual(["INFO: next", ""], screen[1:])
        # Closed once: stopping adds nothing more.
        line.stop()
        self.assertEqual(3, len(_screen(stream.getvalue())))

    def test_a_draw_whose_flush_failed_still_counts_as_drawn(self):
        stream, line = self._line(stream=_FlushFailsOnce())
        line.update(extraction.ProgressEvent(phase="scan", level=1))
        self.assertTrue(line.broken)
        self._record_after(stream, line)
        screen = _screen(stream.getvalue())
        self.assertTrue(screen[0].startswith("| level 1"), screen)
        self.assertEqual(["INFO: next", ""], screen[1:])

    def test_a_rendering_fault_switches_the_line_off_and_raises_nothing(self):
        def no_width():
            raise RuntimeError("no width today")

        stream = _FakeTerminal()
        line = cli._StatusLine(stream, glyphs=cli._ASCII_GLYPHS,
                               width=no_width, clock=_Clock())
        line.update(extraction.ProgressEvent(phase="scan", level=1))
        line.tick()
        line.stop()
        self.assertTrue(line.broken)
        self.assertEqual("", stream.getvalue())

    def test_stopping_does_not_wait_for_ever_on_a_held_lock(self):
        """A ticker stuck in a write on a stalled terminal holds the lock."""
        stream, line = self._line()
        line.update(extraction.ProgressEvent(phase="scan", level=1))
        line.stop_timeout = 0.05
        held, release = threading.Event(), threading.Event()

        def hold():
            with line.lock:
                held.set()
                release.wait()

        holder = threading.Thread(target=hold, daemon=True)
        holder.start()
        held.wait()
        try:
            line.stop()
        finally:
            release.set()
            holder.join()
        self.assertTrue(line.broken)

    def test_a_record_lands_on_a_line_of_its_own(self):
        stream, line = self._line()
        handler = cli._ProgressAwareHandler(stream=stream)
        handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        handler.status_line = line
        line.update(extraction.ProgressEvent(
            phase="nested", level=1, index=1, total=2, path="a-rather-long-name.zip"))
        handler.emit(logging.makeLogRecord(
            {"msg": "short", "levelname": "INFO", "levelno": logging.INFO}))
        self.assertTrue(_screen(stream.getvalue())[-1].startswith("| level 1"))
        line.stop()
        self.assertEqual(["INFO: short", ""], _screen(stream.getvalue()))

    def test_with_no_line_the_handler_is_a_stream_handler(self):
        plain, aware = io.StringIO(), io.StringIO()
        record = logging.makeLogRecord(
            {"msg": "same", "levelname": "INFO", "levelno": logging.INFO})
        logging.StreamHandler(plain).emit(record)
        cli._ProgressAwareHandler(aware).emit(record)
        self.assertEqual(plain.getvalue(), aware.getvalue())


class TestWhenTheProgressLineIsShown(unittest.TestCase):
    """A terminal, no `--quiet`, a `TERM` that is not "dumb" -- and no option."""

    def test_only_a_terminal_gets_the_line(self):
        self.assertTrue(cli._status_line_wanted(_FakeTerminal(), False, {}))
        self.assertFalse(cli._status_line_wanted(io.StringIO(), False, {}))

    def test_quiet_and_a_dumb_terminal_switch_it_off(self):
        self.assertFalse(cli._status_line_wanted(_FakeTerminal(), True, {}))
        self.assertFalse(cli._status_line_wanted(
            _FakeTerminal(), False, {"TERM": "dumb"}))

    def test_a_closed_stream_is_not_a_terminal(self):
        stream = _FakeTerminal()
        stream.close()
        self.assertFalse(cli._status_line_wanted(stream, False, {}))

    def test_unicode_glyphs_only_where_they_can_be_drawn(self):
        utf8, cp1252 = _FakeTerminal("utf-8"), _FakeTerminal("cp1252")
        self.assertIs(cli._UNICODE_GLYPHS, cli._glyphs_for(utf8, {}, "posix"))
        self.assertIs(cli._ASCII_GLYPHS, cli._glyphs_for(cp1252, {}, "posix"))
        # The legacy Windows console draws braille as boxes whatever the
        # stream's codec says; Windows Terminal announces itself.
        self.assertIs(cli._ASCII_GLYPHS, cli._glyphs_for(utf8, {}, "nt"))
        self.assertIs(cli._UNICODE_GLYPHS, cli._glyphs_for(
            utf8, {"WT_SESSION": "1"}, "nt"))
        self.assertIs(cli._ASCII_GLYPHS, cli._glyphs_for(
            cp1252, {"WT_SESSION": "1"}, "nt"))

    def test_the_linux_virtual_console_gets_ascii(self):
        """Its font has neither braille nor block glyphs, whatever the codec."""
        utf8 = _FakeTerminal("utf-8")
        self.assertIs(cli._ASCII_GLYPHS, cli._glyphs_for(
            utf8, {"TERM": "linux"}, "posix"))
        self.assertIs(cli._UNICODE_GLYPHS, cli._glyphs_for(
            utf8, {"TERM": "xterm-256color"}, "posix"))

    def test_the_command_gains_no_option_for_it(self):
        listed = set(re.findall(r"(?<![\w-])--[a-z][a-z-]*",
                                cli.build_parser().format_help()))
        self.assertNotIn("--progress", listed)
        self.assertNotIn("--no-progress", listed)


class TestTheProgressLineThroughTheCommand(_CommandBench):
    """The whole command, its stderr a terminal of 40 columns.

    NOTHING HERE READS THE MACHINE. The environment, the platform, the width
    and the clock are handed to the line through its injection points, and
    the ticker thread is not started: every draw comes from an event, so the
    output is the same on every run.
    """

    WIDTH = 40

    def _run_on(self, stderr, argv, **hooks):
        settings = dict(environ={}, os_name="posix",
                        width=lambda: self.WIDTH, clock=_Clock(),
                        ticker=False)
        settings.update(hooks)
        line_for_this_run = functools.partial(cli._progress_line, **settings)
        out = io.StringIO()
        with _isolated_logger(), \
                mock.patch.object(cli, "_progress_line", line_for_this_run):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(stderr):
                try:
                    code = cli.main(argv)
                except SystemExit as exit_code:
                    code = exit_code.code
        return code, out.getvalue(), stderr.getvalue()

    def test_a_nested_run_draws_the_line_and_leaves_only_records(self):
        archive = _nested_zip(self.dir / "p.zip")
        code, out, err = self._run_on(_FakeTerminal(),
                                      [str(archive), str(self.dir / "out")])
        self.assertEqual(0, code)
        self.assertEqual(f"{self.dir / 'out' / 'p.zip'}\n", out)

        draws = _line_writes(err)
        self.assertTrue(any("level 1 [" in draw for draw in draws), draws)
        for draw in draws:
            self.assertLessEqual(cli._columns(draw), self.WIDTH - 1)
        # What stays on the screen is the log, line for line, and a blank
        # line under it: the progress line left nothing behind.
        screen = _screen(err)
        self.assertEqual("", screen[-1])
        for shown in screen[:-1]:
            with self.subTest(shown=shown):
                self.assertRegex(shown, r"^(INFO|WARNING|ERROR|DEBUG): ")

    def test_the_line_is_gone_before_the_error_is_written(self):
        def failing_prepare(source, workspace=None, report=None, replace=False,
                            no_archive_dir=False, progress=None):
            progress(extraction.ProgressEvent(phase="input", path="p.zip"))
            raise ValueError("boom")

        archive = self._zip("p.zip", [("a.txt", "a")])
        with mock.patch.object(cli, "prepare_source", failing_prepare):
            code, _, err = self._run_on(_FakeTerminal(),
                                        [str(archive), str(self.dir / "out")])
        self.assertEqual(1, code)
        self.assertIn("\r" + " " * (self.WIDTH - 1) + "\rERROR: ValueError: boom",
                      err)
        self.assertIn("ERROR: ValueError: boom", _screen(err))

    def test_an_interrupted_run_leaves_the_line_blank(self):
        def interrupted_prepare(source, workspace=None, report=None,
                                replace=False, no_archive_dir=False,
                                progress=None):
            progress(extraction.ProgressEvent(phase="scan", level=1))
            raise KeyboardInterrupt

        archive = self._zip("p.zip", [("a.txt", "a")])
        stderr = _FakeTerminal()
        with mock.patch.object(cli, "prepare_source", interrupted_prepare):
            with self.assertRaises(KeyboardInterrupt):
                self._run_on(stderr, [str(archive), str(self.dir / "out")])
        self.assertTrue(_line_writes(stderr.getvalue()))
        self.assertEqual("", _screen(stderr.getvalue())[-1])

    def test_quiet_draws_nothing(self):
        archive = _nested_zip(self.dir / "p.zip")
        code, _, err = self._run_on(_FakeTerminal(),
                                    ["-q", str(archive), str(self.dir / "out")])
        self.assertEqual(0, code)
        self.assertNotIn("\r", err)

    def test_a_dumb_terminal_draws_nothing(self):
        archive = _nested_zip(self.dir / "p.zip")
        code, _, err = self._run_on(_FakeTerminal(),
                                    [str(archive), str(self.dir / "out")],
                                    environ={"TERM": "dumb"})
        self.assertEqual(0, code)
        self.assertNotIn("\r", err)

    def test_a_rendering_fault_leaves_the_run_successful(self):
        def no_width():
            raise RuntimeError("no width today")

        archive = _nested_zip(self.dir / "p.zip")
        code, out, err = self._run_on(_FakeTerminal(),
                                      [str(archive), str(self.dir / "out")],
                                      width=no_width)
        self.assertEqual(0, code)
        self.assertEqual(f"{self.dir / 'out' / 'p.zip'}\n", out)
        self.assertNotIn("\r", err)
        self.assertIn("Containers opened: 2.", err)

    def test_the_glyphs_follow_the_platform(self):
        """A legacy Windows console gets ASCII; elsewhere, Unicode."""
        archive = _nested_zip(self.dir / "p.zip")
        _, _, legacy = self._run_on(_FakeTerminal(),
                                    [str(archive), str(self.dir / "one")],
                                    os_name="nt")
        _, _, modern = self._run_on(_FakeTerminal(),
                                    [str(archive), str(self.dir / "two")])
        self.assertTrue(legacy.isascii())
        self.assertFalse(modern.isascii())

    def test_a_stderr_that_is_not_a_terminal_is_what_it_was(self):
        """The line is the only thing that differs between a terminal and a
        pipe: replayed, the terminal's screen holds the pipe's bytes."""
        archive = _nested_zip(self.dir / "p.zip")
        code, _, piped = self._run_on(io.StringIO(),
                                      [str(archive), str(self.dir / "one")])
        self.assertEqual(0, code)
        self.assertNotIn("\r", piped)
        code, _, shown = self._run_on(_FakeTerminal(),
                                      [str(archive), str(self.dir / "two")])
        self.assertEqual(0, code)
        self.assertEqual(piped.replace(str(self.dir / "one"),
                                       str(self.dir / "two")).split("\n"),
                         _screen(shown))

    def test_a_console_that_fails_loses_the_line_and_keeps_the_run(self):
        archive = _nested_zip(self.dir / "p.zip")
        code, out, err = self._run_on(_LineRefusingTerminal(),
                                      [str(archive), str(self.dir / "out")])
        self.assertEqual(0, code)
        self.assertTrue(out.strip())
        self.assertNotIn("\r", err)
        self.assertIn("Containers opened: 2.", err)


if __name__ == "__main__":
    unittest.main(verbosity=2)
