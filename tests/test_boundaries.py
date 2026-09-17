"""unboxr does not know what it was carved out of, and proves it.

This package was extracted from a tool that renders regulatory verdicts. None of
that came along. Two families of guard hold that boundary:

  - the DEPENDENCY guard, by AST and never by `grep`: the roots of every
    `import` in `unboxr/`, minus the standard library and this package itself,
    must be the EMPTY SET;
  - the VOCABULARY guard: a closed list of tokens that would betray the
    provenance, none of which may appear in the package source.

SCOPE. Both guards cover the `unboxr/` PACKAGE, not the repository.
`transport/` necessarily names the upstream project -- comparing against it is
its entire purpose -- and is DECLARED out of scope here. `tests/` is out of
scope for the same reason: this very file names the forbidden tokens in order to
forbid them.

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

# Symbols of the upstream project that must not have followed the code here.
FORBIDDEN_UPSTREAM_MODULES = (
    "catalogue_crypto",
    "avertissements_portee",
    "arbitrages",
    "constantes_crypto",
    "phase1_scanner_crypto",
)

# Tokens that would betray the provenance, or worse, suggest this package takes
# part in a qualification it knows nothing about.
#
# THIS LIST IS DELIBERATELY NARROW, and two obvious-looking candidates are
# EXCLUDED because in English they produce false positives on ordinary prose:
#
#   - `published`: an everyday English word. "the published interface", "a
#     published package" are legitimate sentences in a README and in a
#     docstring, and have nothing to do with the regulatory meaning the term
#     carries upstream;
#   - `qualifi`: matches `qualified`, `qualifier` and `qualifies`, all of which
#     are ordinary English. Banning the prefix would forbid writing "a fully
#     qualified path".
#
# What is banned instead are tokens that carry the regulatory meaning and
# nothing else. A false negative here is cheap; a guard that cries wolf on
# ordinary prose gets disabled, which is not.
FORBIDDEN_TOKENS = (
    "non-standard cryptography",
    "ECCN",
    "772.1",
    "742.15",
    "cryptographic-asset",
    "revue_humaine",
    "CBOM",
    "phase1",
    "phase2",
)

VERDICT_MARKERS = (
    "garantir_affichage_console",
    "import arbitrages",
    "declarer(",
)

# THE SECOND VOCABULARY FAMILY, and the reason this file holds two.
#
# `FORBIDDEN_TOKENS` above is checked against the SOURCE of the package, where
# every occurrence is a fault whatever the sentence around it. The tokens below
# are the opposite kind of word: ordinary English that the source is entirely
# free to use -- `_ensure_safe_extraction_path`, "the security filter", "a
# trusted root" -- and that must not appear in what a CALLER READS at run time,
# where a listing of what this installation can open would turn into a
# judgement about what an archive contains.
#
# TWO LISTS, ONE HOME, AND THEY ARE DISJOINT ON PURPOSE. Until code review on
# 15 September 2026 the runtime half lived as a literal tuple inside
# `tests/test_cli.py`: the two guards shared no entry, neither referenced the
# other, and nothing said whether that was a decision or an oversight.
# `tests/test_cli.py` now imports these names from here and checks the rendered
# output against BOTH families, so a token added to either is a token both
# surfaces are held to.
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

        `report.py` was added on 12 September 2026, DELIBERATELY and with this
        ratchet going red to say so. The extraction report needed a module of
        its own: `cli.py` imports `extraction`, so `extraction` cannot import
        `cli`, which is precisely why the amputation tables had ended up in the
        command where they did not belong. A third module is what lets both
        read them. A ratchet like this one exists to make an addition DECLARED,
        not to make it impossible.

        The set asserted here is the one `_package_files()` returns, and every
        other guard in this file iterates that same helper: adding a module to
        the package therefore brings it under all of them at once, and this
        assertion is what says so out loud.
        """
        names = {path.name for path in _package_files()}
        # `sbom.py` joined the package with the extraction document. It was
        # brought under every guard in this file by that one addition, which is
        # the whole point of deriving the set from the disk: the forbidden
        # tokens, the third-party import ban, the pure-ASCII rule and the
        # absence of any provisional-arbitration dependency all apply to it
        # without a line being written for it.
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

    def test_no_upstream_module_is_imported(self):
        for path in _package_files():
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            roots = _import_roots(tree)
            for module in FORBIDDEN_UPSTREAM_MODULES:
                with self.subTest(module=path.name, forbidden=module):
                    self.assertNotIn(module, roots)

    def test_the_scope_of_this_guard_is_the_package_not_the_repository(self):
        """DECLARED, not implied. `transport/` names the upstream project on
        purpose; it is not covered here, and must not be."""
        transport = REPO_ROOT / "transport" / "test_equivalence.py"
        self.assertTrue(transport.is_file())
        self.assertNotIn(transport, _package_files())
        self.assertIn("phase1_scanner_crypto", transport.read_text(encoding="utf-8"))


class TestVocabularyBoundary(unittest.TestCase):

    def test_no_forbidden_qualification_token_in_the_package(self):
        for path in _package_files():
            source = path.read_text(encoding="utf-8")
            for token in FORBIDDEN_TOKENS:
                with self.subTest(module=path.name, token=token):
                    self.assertNotIn(token, source)

    def test_no_forbidden_token_in_the_readme_either(self):
        """The README is the first thing a stranger reads."""
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        for token in FORBIDDEN_TOKENS:
            with self.subTest(token=token):
                self.assertNotIn(token, readme)

    def test_the_package_declares_no_provisional_arbitration_dependency(self):
        """Two forms, because they fail for different reasons: the attribute
        catches a constant defined and re-exported, the token catches one
        written and never read."""
        for module in _imported_package_modules():
            with self.subTest(module=module.__name__):
                self.assertFalse(hasattr(module, "DEPEND_ARBITRAGE"))
        for path in _package_files():
            with self.subTest(module=path.name):
                self.assertNotIn("DEPEND_ARBITRAGE", path.read_text(encoding="utf-8"))

    def test_the_package_mints_no_verdict(self):
        for path in _package_files():
            source = path.read_text(encoding="utf-8")
            for marker in VERDICT_MARKERS:
                with self.subTest(module=path.name, marker=marker):
                    self.assertNotIn(marker, source)

    def test_the_two_vocabulary_families_are_disjoint_and_stay_so(self):
        """A DECISION, written as an assertion rather than left as a
        coincidence. The two lists guard different surfaces and must not
        overlap: a word banned from the SOURCE has no business being merely
        watched at run time, and a word that is ordinary English in a
        docstring must not be banned from the source by the back door. Code
        review, 15 September 2026, found the runtime half living in another
        file with no entry in common and no reference either way -- which is
        this same property, holding by accident."""
        self.assertEqual(set(), set(FORBIDDEN_TOKENS) & set(VERDICT_CLAIM_TOKENS))
        self.assertNotEqual((), VERDICT_CLAIM_TOKENS)

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

    def test_the_package_borrows_no_upstream_message_prefix(self):
        """A published package uses its ecosystem's standard logging. The
        bracketed prefixes belong to the project this code came from, and levels
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
        # ENGRAVED ON PURPOSE, and the one guard in this file that the
        # version -- not the package surface -- makes go red. 2.0.0 is story
        # 14.8: the level-0 extraction root stopped being the fixed name
        # `extracted` and started carrying the archive's own name, exactly
        # as the determinism contract already promised for a nested one --
        # EVERY caller of `prepare_source`, and every invocation of the
        # command line, gets a tree at a different path than before, with
        # nothing to opt into. That is a change of SHAPE to the default
        # behaviour, not an addition, so a major version -- even though two
        # new options (`--replace`, `--no-archive-dir`) ship alongside it.
        # 2.0.1 is six correctness fixes from the adversarial code review of
        # 2.0.0 (15 September 2026): no public signature and no observable
        # shape changed on a correct run, so a PATCH version.
        # 2.1.0 is story 14.9: the document became readable -- keys in the
        # order `bom-1.7.schema.json` declares them instead of alphabetically,
        # every `property` and every `hash` folded onto one line, and the
        # calculated timestamp stopped at the second it measures. Nothing the
        # document SAYS changed, and no public signature moved, so it is not a
        # major; but the BYTES a caller stores did, which is more than a patch.
        # 2.1.1 is ten fixes from the adversarial review of 2.1.0: three of
        # behaviour (tuples ordered like any other container, circular
        # documents raising ValueError again, the BOM link written in schema
        # order) and seven of diagnostics and prose. No public signature
        # moved and no document this package builds comes out differently, so
        # a PATCH version.
        # 2.2.0 is `--list-formats`: the command projects the extension tables
        # onto the four states it sorts every recognised extension into, and
        # `--json` renders the same projection for a machine. A MINOR version:
        # no public signature moved, no document changed a byte, and nothing
        # that was extracted before is extracted differently.
        # THREE THINGS IT IS NOT A PURE ADDITION, NAMED RATHER THAN GLOSSED.
        # (a) The TEXT of a usage error: `archive` became an optional
        # positional, the way `destination` did at 2.0.0, so `main` writes the
        # "required: archive" sentence argparse used to write. Same refusal,
        # same code 2.
        # (b) The USAGE LINE of `--help`, for the same reason: `[archive]` is
        # now advertised optional unconditionally, where it used to be
        # mandatory. What is optional is stated in the option's own help text
        # and enforced in `main`; the one-line usage cannot express "optional
        # only with --list-formats".
        # (c) AND THE ONE THAT IS A REAL BEHAVIOURAL REGRESSION, measured on
        # 15 September 2026 and pinned by
        # `TestListingWhatThisMachineCanOpen.test_the_new_option_makes_two_
        # abbreviations_of_linked_bom_ambiguous`: `--l` and `--li` used to be
        # valid abbreviations of `--linked-bom` and now exit 2, because
        # argparse's prefix matching finds `--list-formats` too. An invocation
        # that worked returns a different result, which is why "no existing
        # invocation produces a different result" is NOT written here. The
        # option keeps its name -- it was chosen, and renaming it to dodge an
        # abbreviation nobody documented would be the wrong trade -- and
        # `allow_abbrev` stays on: turning it off would break EVERY
        # abbreviation of every option at once, a far larger break than the
        # two this costs. `--link`, `--linked` and `--linked-bom` are
        # unaffected.
        self.assertEqual("3.1.0", unboxr.__version__)
        source = (PACKAGE_ROOT / "__init__.py").read_text(encoding="utf-8")
        self.assertNotIn("importlib.metadata", source)

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
        """The upstream licence enumerates directories and excludes a vendored
        tree. There is nothing of the sort here, and a clause naming
        directories that do not exist would be worse than none."""
        licence = (REPO_ROOT / "LICENSE.md").read_text(encoding="utf-8")
        self.assertIn("MIT License", licence)
        self.assertIn("Copyright (c) 2026 Rodolphe Dejeunes", licence)
        for absent in ("wheelhouse", "NOTICE.md", "src/", "packaging/"):
            with self.subTest(absent=absent):
                self.assertNotIn(absent, licence)

    def test_the_gitignore_does_not_keep_build_and_dist(self):
        """The upstream project deliberately keeps `build/` and `dist/` for a
        reason that has no object here."""
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
