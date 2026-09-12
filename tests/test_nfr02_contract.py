"""The determinism contract, tested as a contract and not as prose.

`unboxr.extraction` writes down four guarantees and seven non-guarantees. This
file holds the first three guarantees by PROPERTY -- a test that only grepped
the docstring would go green on a module that had stopped honouring it -- and
holds the non-guarantees by presence, because a silently deleted non-guarantee
reads as a promise. The fourth guarantee, the corpus report, is held by property
in `test_report.py` and `test_report_of_the_chain.py`, where the archives are.

Guarantee 1 needs care. A real directory tree is NOT enough: the file systems in
common use already enumerate entries in near-sorted order, so a test built on
one would be green without proving anything. The enumeration is therefore
SIMULATED in reverse order, and what is asserted is the order of EFFECTIVE
PROCESSING.

Guarantee 2 needs two interpreters. `hash()` is salted by `PYTHONHASHSEED`,
which is fixed for the life of a process: a single-process test cannot tell a
`hashlib` digest from a `hash()` one. Two child processes with different seeds
can.

100% offline, standard library only.
"""

from __future__ import annotations

import hashlib
import io
import logging
import os
import re
import shutil
import subprocess
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

PROVISIONAL_NAME_SHAPE = re.compile(r"^archive_[0-9a-f]{16}$")

# The seven things the contract explicitly does NOT guarantee. Each entry is a
# fragment that must appear in the written contract. They are held here because
# a non-guarantee that quietly disappears from the documentation turns into an
# implied promise -- the exact opposite of what it was written for.
#
# The COUNT is asserted in the test below, not merely written in its name: a
# figure engraved in a test name never goes red, it just becomes a lie.
DECLARED_NON_GUARANTEES = (
    "No symbolic-link containment",
    "__pycache__",
    "No guarantee on any document",
    "when the 7-Zip binary is absent",
    "the tar security filter was made mandatory",
    "provisional extraction name stays provisional",
    # Added 12 September 2026 with the corpus report: the report names
    # containers, it says nothing about what is inside them, and an absent entry
    # is not evidence of anything.
    "AN ABSENT ENTRY ESTABLISHES NOTHING",
)


class _Quiet:
    """Swallows package records: these tests assert behaviour, not logging."""

    def __enter__(self):
        self.logger = logging.getLogger("unboxr")
        self.handler = logging.NullHandler()
        self.logger.addHandler(self.handler)
        self.previous = self.logger.level
        self.logger.setLevel(logging.CRITICAL)
        return self

    def __exit__(self, *exc_info):
        self.logger.removeHandler(self.handler)
        self.logger.setLevel(self.previous)
        return False


class _Bench(unittest.TestCase):

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="test_contract_"))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    def _zip(self, path: Path, members=(("code/a.c", "int a;"),)) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(path, "w") as z:
            for arcname, content in members:
                z.writestr(arcname, content)
        return path

    def _tar(self, path: Path, members=(("src/a.c", "int a;"),)) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(path, "w") as t:
            for arcname, content in members:
                payload = content.encode("utf-8")
                info = tarfile.TarInfo(arcname)
                info.size = len(payload)
                t.addfile(info, io.BytesIO(payload))
        return path


# ---------------------------------------------------------------------------
# Guarantee 1 -- traversal order
# ---------------------------------------------------------------------------
class TestTraversalOrder(_Bench):

    def _reverse_enumeration(self):
        """Simulates a file system enumerating in reverse order.

        Without this, the test is green on any implementation, sorted or not.
        """
        real_rglob = Path.rglob

        def reversed_rglob(self, pattern, **kwargs):
            found = list(real_rglob(self, pattern, **kwargs))
            found.sort(key=lambda p: p.as_posix(), reverse=True)
            return iter(found)

        return mock.patch.object(Path, "rglob", reversed_rglob)

    def test_flattening_processes_archives_in_posix_relative_path_order(self):
        root = self.dir / "tree"
        for name in ("m_third.zip", "a_first.zip", "z_last.zip"):
            self._zip(root / "vendor" / name)
        self._zip(root / "aaa_shallow.zip")

        processed = []
        real_extract = ux.extract_archive

        def spy(archive, dest):
            processed.append(Path(archive).relative_to(root).as_posix())
            return real_extract(archive, dest)

        with self._reverse_enumeration(), mock.patch.object(ux, "extract_archive", spy):
            with _Quiet():
                ux.flatten_nested_archives(root)

        first_level = processed[:4]
        self.assertEqual(sorted(first_level), first_level,
                         "the reversed enumeration leaked into the processing "
                         "order; the sort is not doing its job")

    def test_the_tar_chosen_in_a_7z_envelope_is_the_first_in_sorted_order(self):
        """The choice decides THE WHOLE EXTRACTED CORPUS, so it may not depend
        on the enumeration order."""
        envelope = self.dir / "package.tar.7z"
        envelope.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 16)
        dest = self.dir / "out"

        def fake_7zip(archive_path, target, binary):
            target.mkdir(parents=True, exist_ok=True)
            for name in ("z_last.tar", "a_first.tar", "m_middle.tar"):
                self._tar(target / "nested" / name,
                          members=((f"from_{name}.c", "int a;"),))

        with self._reverse_enumeration(), \
                mock.patch.object(ux, "find_7zip_binary", lambda: "7z"), \
                mock.patch.object(ux, "extract_with_7zip", fake_7zip), \
                _Quiet():
            ux.extract_tar_7z(envelope, dest)

        produced = [p.name for p in dest.rglob("*") if p.is_file()]
        self.assertEqual(["from_a_first.tar.c"], produced,
                         "the tar retained must be the first in sorted order")


# ---------------------------------------------------------------------------
# Guarantee 2 -- extraction directory names
# ---------------------------------------------------------------------------
CHILD_PROGRAM = """
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import unboxr.extraction as ux
print(ux._provisional_extraction_name(Path(sys.argv[2]) / sys.argv[3],
                                      Path(sys.argv[2])))
"""


class TestExtractionNames(_Bench):

    def _name_in_child(self, seed: str, root: str, relative: str) -> str:
        environment = dict(os.environ, PYTHONHASHSEED=seed)
        result = subprocess.run(
            [sys.executable, "-c", CHILD_PROGRAM, str(REPO_ROOT), root, relative],
            capture_output=True, text=True, env=environment, timeout=120)
        self.assertEqual(0, result.returncode, result.stderr)
        return result.stdout.strip()

    def test_the_name_is_identical_under_two_different_hash_seeds(self):
        """Two SEPARATE interpreters, with DIFFERENT `PYTHONHASHSEED` values.

        This is the only shape of test that can tell `hashlib` from `hash()`:
        the salt is drawn once per interpreter, so within a single process both
        are equally stable.
        """
        root = str(self.dir)
        relative = "vendor/deep/.tar.gz"
        first = self._name_in_child("0", root, relative)
        second = self._name_in_child("1", root, relative)
        self.assertEqual(first, second)
        self.assertRegex(first, PROVISIONAL_NAME_SHAPE)

    def test_the_name_is_the_digest_of_the_posix_relative_path(self):
        """Stated as a formula so that a change of input -- an absolute path, a
        rank, a level -- cannot slip through."""
        relative = "vendor/deep/.tar.gz"
        expected = hashlib.sha256(relative.encode("utf-8")).hexdigest()[:16]
        self.assertEqual(f"archive_{expected}",
                         ux._provisional_extraction_name(self.dir / relative, self.dir))

    def test_the_name_does_not_vary_with_the_nesting_level(self):
        """The defect a positional `(level, position)` counter had: one
        directory per level walked, for a single archive."""
        archive = self.dir / "a" / "b" / "c" / ".zip"
        names = {ux._provisional_extraction_name(archive, self.dir) for _ in range(5)}
        self.assertEqual(1, len(names))

    def test_the_name_does_not_depend_on_the_other_archives_in_the_tree(self):
        """The defect a GLOBAL rank had: adding an unrelated archive elsewhere
        renumbered the directory and moved every path of its subtree."""
        root = self.dir / "tree"
        target = self._zip(root / "vendor" / ".zip")
        before = ux._provisional_extraction_name(target, root)

        self._zip(root / "another.zip")
        self._zip(root / "aaa" / "earlier.zip")
        after = ux._provisional_extraction_name(target, root)
        self.assertEqual(before, after)

    def test_end_to_end_the_directory_left_behind_carries_the_final_name(self):
        """DECLARED LOSS OF COVERAGE, and it is not an oversight.

        This test used to observe the PROVISIONAL name on disk, in the finished
        tree. It cannot any more, and it must not: the contract now says that
        name is normally transitory, so a test asserting it survives a run would
        contradict the very thing being promised. What is observable at the end
        of a run is the FINAL name -- here, an archive named literally `.zip`
        yields a directory named `.zip`, and no digest appears anywhere.

        The three determinism properties of the provisional name are therefore
        held by UNIT tests only (the four above), never end to end. Nothing
        else in the suite reaches it on disk.
        """
        root = self.dir / "tree"
        target = self._zip(root / "vendor" / ".zip")
        provisional = ux._provisional_extraction_name(target, root)
        with _Quiet():
            ux.flatten_nested_archives(root)

        self.assertTrue((root / "vendor" / ".zip").is_dir())
        self.assertTrue((root / "vendor" / ".zip" / "code" / "a.c").is_file())
        self.assertFalse((root / "vendor" / provisional).exists())
        self.assertFalse((root / "vendor" / f"{provisional}_extracted").exists())

    def test_an_archive_outside_the_root_announces_the_absolute_path_it_used(self):
        """A machine-dependent name is a declared stopgap, never a silent one."""
        outside = self.dir / "elsewhere" / "x.zip"
        self._zip(outside)
        with self.assertLogs("unboxr", level="WARNING") as captured:
            name = ux._provisional_extraction_name(outside, self.dir / "tree")
        self.assertRegex(name, PROVISIONAL_NAME_SHAPE)
        self.assertIn("depends on", captured.records[0].getMessage())


# ---------------------------------------------------------------------------
# Guarantee 3 -- POSIX paths
# ---------------------------------------------------------------------------
class TestPosixPaths(_Bench):

    def test_the_produced_name_uses_a_character_set_valid_on_both_systems(self):
        """Digits, `a-f` and `_` only: none of `< > : " / \\ | ? *`, which
        Windows forbids in a path component."""
        forbidden = set('<>:"/\\|?*')
        for relative in ("a/.zip", "b/c/.tar.gz", "UPPER/Mixed Case/.7z",
                         "accented-nom-francais/.tgz", "spaces and (parens)/.zip"):
            with self.subTest(relative=relative):
                name = ux._provisional_extraction_name(self.dir / relative, self.dir)
                self.assertRegex(name, PROVISIONAL_NAME_SHAPE)
                self.assertEqual(set(), set(name) & forbidden)

    def test_the_name_is_invariant_to_the_temporary_directory(self):
        """An absolute path would tie the name to the machine; a POSIX relative
        path does not."""
        first_root = Path(tempfile.mkdtemp(prefix="root_one_"))
        second_root = Path(tempfile.mkdtemp(prefix="root_two_"))
        self.addCleanup(shutil.rmtree, first_root, ignore_errors=True)
        self.addCleanup(shutil.rmtree, second_root, ignore_errors=True)

        relative = "vendor/pkg/.tar.gz"
        self.assertEqual(
            ux._provisional_extraction_name(first_root / relative, first_root),
            ux._provisional_extraction_name(second_root / relative, second_root))

    def test_the_sort_key_is_a_posix_string_not_a_raw_path(self):
        """A sort on a raw `Path` is not portable: `PureWindowsPath` compares on
        a case-folded form and `PurePosixPath` does not, so the same tree would
        be walked in two different orders on two systems."""
        import inspect
        for function in (ux.flatten_nested_archives, ux.extract_tar_7z):
            with self.subTest(function=function.__name__):
                source = inspect.getsource(function)
                self.assertIn("as_posix()", source)
                self.assertIn("sorted(", source)


# ---------------------------------------------------------------------------
# What the contract does NOT guarantee, and the reminder it does carry
# ---------------------------------------------------------------------------
def _flatten(text: str) -> str:
    return re.sub(r"\s+", " ", text)


class TestTheWrittenContract(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Both texts are wrapped prose: a fragment can straddle a line break, so
        # the comparison runs on whitespace-normalised copies. Asserting on the
        # raw text would fail on a reflow that changed nothing.
        cls.docstring = _flatten(ux.__doc__ or "")
        cls.readme = _flatten((REPO_ROOT / "README.md").read_text(encoding="utf-8"))

    def test_the_seven_non_guarantees_are_written_in_the_module(self):
        self.assertEqual(7, len(DECLARED_NON_GUARANTEES),
                         "the count is part of what this file asserts: update "
                         "the name of this test and the docstring above with it")
        for fragment in DECLARED_NON_GUARANTEES:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.docstring)

    def test_the_non_guarantee_on_the_provisional_name_does_not_overpromise(self):
        """It said "never a stable observable state", which was false on the
        rename-failure path -- the one path where that name is what the
        consumer is left with. A non-guarantee that lies is worse than none."""
        for text in (self.docstring, self.readme):
            self.assertIn("provisional extraction name stays provisional", text)
            self.assertIn("rename fails", text)

    def test_the_contract_is_written_in_the_readme_too(self):
        for heading in ("Traversal order", "Extraction directory names",
                        "POSIX paths", "corpus report", "does not guarantee"):
            with self.subTest(heading=heading):
                self.assertIn(heading, self.readme)

    def test_what_the_report_guarantees_is_written_in_both_texts(self):
        """The guarantee, and its limit, in the two places the contract lives.
        A guarantee written in only one of them is a guarantee that drifts:
        the module and the README are compared here for exactly that reason.

        Case-folded: the module docstring shouts the limit in capitals and the
        README italicises it, which is a difference of typography and not of
        contract."""
        for claim in ("every amputation of the corpus",
                      "the report is returned on every way out",
                      "an absent entry establishes nothing"):
            with self.subTest(claim=claim):
                self.assertIn(claim, self.docstring.lower())
                self.assertIn(claim, self.readme.lower())

    def test_the_two_directory_names_are_told_apart_in_both_texts(self):
        """Headings alone said nothing about what guarantee 2 promises, and it
        now promises two different things about two different names. Both texts
        have to distinguish them, or the published one drifts from the module."""
        for claim in ("that archive's own name, in full and verbatim",
                      "SHA-256 digest of the archive's POSIX relative path",
                      "it can stop being provisional"):
            with self.subTest(claim=claim):
                self.assertIn(claim, self.docstring)
                self.assertIn(claim, self.readme)

    def test_the_only_fabricated_name_is_declared_in_both_texts(self):
        """Declaring beats keeping quiet: this is the one name the package
        makes up, and the one place a "cleaner" name would break extraction."""
        for claim in ("`_decompressed` suffix", "no natural name exists",
                      "required to match no recognised extension"):
            with self.subTest(claim=claim):
                self.assertIn(claim, self.docstring)
                self.assertIn(claim, self.readme)

    def test_the_positive_only_oracle_reminder_is_due_in_both(self):
        """The absolute rule that exempts a module without a verdict from the
        scope warnings does NOT exempt it from this reminder."""
        reminder = "absence of a finding is never evidence of absence"
        self.assertIn(reminder, self.docstring)
        self.assertIn(reminder, self.readme)

    def test_the_contract_names_no_upstream_requirement_number(self):
        """The guarantees are unboxr's own; they are not stated by reference to
        a requirement of a project its users have never heard of.

        `D8` and `D22` are decision numbers of that same upstream backlog: the
        naming rules they settled are stated here as rules, never by number."""
        for token in ("NFR-02", "NFR-07", "NFR-13", "AC-1", "AC-2", "AC-5",
                      "D8", "D22"):
            with self.subTest(token=token):
                self.assertNotIn(token, self.docstring)
                self.assertNotIn(token, self.readme)


if __name__ == "__main__":
    unittest.main(verbosity=2)
