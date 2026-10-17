"""unboxr renders no verdict on what it extracts.

Two families of guard hold that boundary:

  - the DEPENDENCY guard, by AST and never by `grep`: the roots of every
    `import` in `unboxr/`, minus the standard library and this package itself,
    must be the EMPTY SET;
  - the VOCABULARY guard: words that would turn what a caller reads into a
    judgement about what an archive contains.

SCOPE. Both guards cover the `unboxr/` PACKAGE, not the repository.

This file also holds the packaging invariants, which are boundaries of the same
kind: what this package must never start depending on.
"""

from __future__ import annotations

import ast
import sys
import tomllib
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_ROOT = REPO_ROOT / "unboxr"
sys.path.insert(0, str(REPO_ROOT))

import unboxr  # noqa: E402
import unboxr.cli  # noqa: E402
import unboxr.extraction  # noqa: E402
import unboxr.report  # noqa: E402

# Modules of this package: not dependencies. Removing them from the residue
# relaxes NOTHING -- the ratchet is on THIRD-PARTY roots, and it stays at zero.
INTERNAL_ROOTS = {"unboxr"}

# THE VOCABULARY FAMILY. These tokens are ordinary English that the source is
# entirely free to use -- `_ensure_safe_extraction_path`, "the security
# filter", "a trusted root" -- and that must not appear in what a CALLER READS at run time,
# where a listing of what this installation can open would turn into a
# judgement about what an archive contains.
#
VERDICT_CLAIM_TOKENS = ("verdict", "compliant", "approved", "certified",
                        "trusted", "safe", "secure")

# AND A DISCLAIMER IS NOT A CLAIM. A bare `assertNotIn("verdict", output)` goes
# red on this package's own central sentence -- "unboxr renders no verdict on
# what it extracts" -- which `--help` prints on every run. A guard that fires
# on the disclaimer it exists to protect is a guard somebody switches off, and
# it can tell nobody the difference between a package saying it judges nothing
# and a package saying it judged something. These phrases are struck out of the
# text before the search, so what remains is claims only.
VERDICT_DISCLAIMER_PHRASES = (
    "renders no verdict",
    "mints no verdict",
    "no verdict of any kind",
)


def verdict_claims_in(text: str) -> list[str]:
    """The claim tokens a rendered output makes, disclaimers struck out first.

    Returns a sorted list, so a failure names WHICH word was found rather than
    only that one was. Case-insensitive: the output is prose, and "Certified"
    claims exactly what "certified" claims.
    """
    lowered = text.lower()
    for phrase in VERDICT_DISCLAIMER_PHRASES:
        lowered = lowered.replace(phrase, " ")
    return sorted({token for token in VERDICT_CLAIM_TOKENS
                   if token in lowered})


def _package_files() -> list[Path]:
    return sorted(PACKAGE_ROOT.glob("*.py"))


def _imported_package_modules() -> list:
    """Every module of the package, IMPORTED, derived from the files on disk.

    A hard-coded tuple of names was what this helper replaced on 12 September
    2026: it named three modules, and a fourth would have crossed the guard
    below without ever being looked at. A list written by hand goes stale at
    the next module; one derived from `_package_files()` cannot.
    """
    import importlib

    modules = []
    for path in _package_files():
        name = "unboxr" if path.name == "__init__.py" else f"unboxr.{path.stem}"
        modules.append(importlib.import_module(name))
    return modules


def _import_roots(tree: ast.Module) -> set[str]:
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots


class TestDependencyBoundary(unittest.TestCase):

    def test_the_package_has_python_modules_to_guard(self):
        """A guard over an empty set proves nothing.

        A ratchet like this one exists to make a new module DECLARED, not to
        make it impossible. `report.py` is a module of its own because
        `cli.py` imports `extraction`, so `extraction` cannot import `cli`:
        the tables both read live in a third module.

        The set asserted here is the one `_package_files()` returns, and every
        other guard in this file iterates that same helper: adding a module to
        the package therefore brings it under all of them at once, and this
        assertion is what says so out loud.
        """
        names = {path.name for path in _package_files()}
        # Deriving the set from the disk brings every module under every guard
        # in this file: the forbidden tokens, the third-party import ban and
        # the pure-ASCII rule apply to a new module without a line written.
        self.assertEqual({"__init__.py", "cli.py", "extraction.py", "report.py",
                          "sbom.py"},
                         names)

    def test_no_third_party_import_anywhere_in_the_package(self):
        """By AST, never by `grep`: a textual search reads commented-out code,
        strings and docstrings, and misses `import a.b.c as d`."""
        for path in _package_files():
            with self.subTest(module=path.name):
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
                residue = _import_roots(tree) - set(sys.stdlib_module_names) - INTERNAL_ROOTS
                self.assertEqual(set(), residue,
                                 f"unexpected third-party dependency: {residue}")

    def test_the_scope_of_this_guard_is_the_package_not_the_repository(self):
        """DECLARED, not implied: the guards read the package directory and
        nothing else in the repository."""
        for path in _package_files():
            self.assertEqual(PACKAGE_ROOT, path.parent)


class TestVocabularyBoundary(unittest.TestCase):

    def test_a_disclaimer_is_not_read_as_a_claim(self):
        """The guard must tell "we judge nothing" from "we judged this".

        `unboxr renders no verdict on what it extracts` is the package's own
        sentence and `--help` prints it. A guard that went red on it would be
        switched off, and a guard switched off catches the real claim too.
        """
        self.assertEqual([], verdict_claims_in(unboxr.cli.build_parser().epilog))
        self.assertEqual([], verdict_claims_in(
            "unboxr renders no verdict on what it extracts."))

    def test_a_real_claim_is_still_caught(self):
        """And the other half of the same guard: struck-out disclaimers must
        not become a way to smuggle a claim past it. Without this case, a
        helper that returned the empty list unconditionally would pass the
        test above."""
        self.assertEqual(["verdict"], verdict_claims_in(
            "unboxr renders no verdict; this archive has a verdict."))
        self.assertEqual(["certified", "safe"], verdict_claims_in(
            "This tree is certified safe."))

    def test_the_package_borrows_no_foreign_message_prefix(self):
        """A published package uses its ecosystem's standard logging. The
        bracketed prefixes belong to another tool's convention, and levels
        replace them here."""
        for path in _package_files():
            source = path.read_text(encoding="utf-8")
            for prefix in ("[INFO]", "[AVERTISSEMENT]", "[ERREUR]", "[DEBUG]",
                           "[EXPLOITATION]"):
                with self.subTest(module=path.name, prefix=prefix):
                    self.assertNotIn(prefix, source)

    def test_the_package_source_is_pure_ascii(self):
        """Not a style rule: a non-ASCII byte in a source file read without an
        explicit encoding is a decoding error on a machine whose default
        codepage is not UTF-8, and a published package is read on machines we
        do not choose."""
        for path in _package_files():
            with self.subTest(module=path.name):
                raw = path.read_bytes()
                self.assertEqual(raw, raw.decode("utf-8").encode("ascii", "strict"))


class TestPackagingBoundary(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.pyproject = tomllib.loads(
            (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    def test_there_are_no_runtime_dependencies(self):
        self.assertEqual([], self.pyproject["project"]["dependencies"])
        self.assertNotIn("optional-dependencies", self.pyproject["project"])

    def test_the_python_floor_is_declared_and_is_3_12(self):
        """3.12 is what makes `extractall(filter=...)` guaranteed, which is what
        removes every conditional code path from the extraction chain."""
        self.assertEqual(">=3.12", self.pyproject["project"]["requires-python"])
        self.assertIn("Python 3.12 or later",
                      (REPO_ROOT / "README.md").read_text(encoding="utf-8"))

    def test_no_capability_probe_was_written_for_the_tar_filter(self):
        """The floor makes the filter unconditional. A probe would be dead code
        suggesting a doubt that no longer exists."""
        source = (PACKAGE_ROOT / "extraction.py").read_text(encoding="utf-8")
        for probe in ("version_info >= (3, 12", "hasattr(tarfile, \"data_filter\")",
                      "hasattr(tarfile, 'data_filter')"):
            with self.subTest(probe=probe):
                self.assertNotIn(probe, source)

    def test_the_licence_is_declared_once_and_as_an_expression(self):
        """PEP 639 superseded the `License ::` classifiers, and setuptools 77
        onwards REFUSES a project that carries both. Declaring the licence twice
        is not redundancy here: it makes `pip install .` -- the very command the
        README puts first -- fail outright on a current toolchain.

        This guard exists because that is exactly what happened: five closed
        stories shipped a package that could not be installed, none of them
        having ever run the installation they document.
        """
        project = self.pyproject["project"]
        self.assertEqual("MIT", project["license"])
        self.assertEqual(["LICENSE.md"], project["license-files"])
        for classifier in project["classifiers"]:
            with self.subTest(classifier=classifier):
                self.assertFalse(classifier.startswith("License ::"))

    def test_the_version_has_a_single_source_of_truth(self):
        """`pyproject.toml` reads the package; the reverse is forbidden, because
        reading installed metadata fails from a clone that was never installed."""
        self.assertIn("version", self.pyproject["project"]["dynamic"])
        self.assertEqual({"attr": "unboxr.__version__"},
                         self.pyproject["tool"]["setuptools"]["dynamic"]["version"])
        # ENGRAVED ON PURPOSE: the one guard in this file that the version
        # -- not the package surface -- makes go red. Bump it together with
        # `unboxr.__version__`.
        self.assertEqual("0.2.1", unboxr.__version__)
        source = (PACKAGE_ROOT / "__init__.py").read_text(encoding="utf-8")
        self.assertNotIn("importlib.metadata", source)

    def test_the_progress_event_is_exported_by_both_gestures(self):
        """Exporting a public name is two gestures: the
        import block AND `__all__`. A name in one and missing from the other
        passes every other test."""
        self.assertIn("ProgressEvent", unboxr.__all__)
        self.assertIs(unboxr.extraction.ProgressEvent, unboxr.ProgressEvent)

    def test_the_test_suite_uses_unittest_and_nothing_else(self):
        self.assertEqual([], list(REPO_ROOT.glob("**/conftest.py")))
        for path in sorted((REPO_ROOT / "tests").glob("*.py")):
            with self.subTest(module=path.name):
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
                self.assertNotIn("pytest", _import_roots(tree))

    def test_no_test_of_this_suite_is_skipped(self):
        """A skipped test that turns a suite green for nothing is the failure
        mode this repository refuses. The suite must run everywhere, or fail.

        By AST, not by substring: this very file names the skip mechanisms in
        order to forbid them, and a textual guard would flag itself. Reaching
        for `grep` where an AST is needed is the mistake this project has
        already paid for once.
        """
        skip_calls = {"skipTest", "SkipTest"}
        skip_decorators = {"skip", "skipIf", "skipUnless"}
        for path in sorted((REPO_ROOT / "tests").glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    for decorator in node.decorator_list:
                        target = decorator.func if isinstance(decorator, ast.Call) else decorator
                        name = getattr(target, "attr", getattr(target, "id", ""))
                        with self.subTest(module=path.name, function=node.name):
                            self.assertNotIn(name, skip_decorators)
                elif isinstance(node, ast.Call):
                    name = getattr(node.func, "attr", getattr(node.func, "id", ""))
                    with self.subTest(module=path.name, call=name):
                        self.assertNotIn(name, skip_calls)

    def test_the_licence_carries_no_scope_clause(self):
        """A licence clause naming directories that do not exist would be worse
        than none."""
        licence = (REPO_ROOT / "LICENSE.md").read_text(encoding="utf-8")
        self.assertIn("MIT License", licence)
        self.assertIn("Copyright (c) 2026 RοdοƖphе Dеȷеᴜnеѕ", licence)
        for absent in ("wheelhouse", "NOTICE.md", "src/", "packaging/"):
            with self.subTest(absent=absent):
                self.assertNotIn(absent, licence)

    def test_the_gitignore_does_not_keep_build_and_dist(self):
        """Build output must never be committed."""
        ignored = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").split()
        self.assertIn("build/", ignored)
        self.assertIn("dist/", ignored)

    def test_the_offline_install_trap_is_written_down(self):
        """Without this line, unboxr cannot be installed on an air-gapped
        machine at all: `pip install .` reaches for the index."""
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("--no-build-isolation", readme)
        self.assertIn("build isolation", readme)


if __name__ == "__main__":
    unittest.main(verbosity=2)
