"""Equivalence proof between the upstream block and `unboxr.extraction`.

WHY THIS IS NOT IN `tests/`
---------------------------
These tests confront `unboxr` with the repository it was carved out of. They
cannot run for anyone who merely clones `unboxr`, and they DISAPPEAR the day
the original block is deleted upstream. Putting them in `tests/` would ship a
package whose suite fails for everybody. `transport/` is excluded from the
distribution and carries that expiry date in this docstring.

HOW TO RUN
----------
Point `UNBOXR_UPSTREAM_ROOT` at a checkout of the upstream project, then:

    UNBOXR_UPSTREAM_ROOT=/path/to/crypto-scan \\
        python -m unittest discover -s transport -t transport

`-t transport`, not `-t .`: `transport/` carries no `__init__.py`, so `-t .`
makes `unittest` treat it as an importable package and stop on `ImportError`
before a single test runs. The form written here is the one that works --
verified in code review on 9 September 2026, where the previous wording was
found to be the only one that does not.

There is no `skipUnless` here on purpose: a missing environment variable is a
HARD failure with an explicit message. A skipped equivalence proof is a green
suite that proves nothing.

WHAT THE PROOF IS, AND WHAT IT IS NOT
-------------------------------------
The master test applies `transport/correspondance.json` BACKWARDS to
`unboxr/extraction.py` and then requires strict AST equality with the original,
function by function -- identifiers included, string constants excluded (they
are translated). An identifier renamed without an entry in the table makes this
fail: the table is the backbone of the proof, not decoration.

It is WEAKER than a textual diff: it proves the code does the same thing, not
that the translated texts say the same thing. Three things it cannot see are
covered by separate tests below: module constants, exception types, and logging
levels. Behaviour itself is covered by `TestBehaviouralEquivalence`.
"""

from __future__ import annotations

import ast
import collections
import copy
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
import textwrap
import logging
import unittest
import zipfile
from contextlib import redirect_stdout
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from unboxr import extraction as transported  # noqa: E402

UPSTREAM_ENV = "UNBOXR_UPSTREAM_ROOT"
UPSTREAM_MODULE = Path("src") / "phase1_scanner_crypto.py"

# Markers delimiting the transported block in the upstream module. Line numbers
# are deliberately NOT hardcoded: they move with every upstream commit, and a
# stale slice would compare the wrong code. The slice is then checked against
# the counts the story measured (24 functions, 9 module constants), so a marker
# that drifts fails loudly instead of silently truncating the proof.
BLOCK_START_MARKER = "# 2d. R"
BLOCK_END_MARKER = "# 3. Scan du code source"

EXPECTED_FUNCTIONS = 24
EXPECTED_CONSTANTS = 9

# Synthesised import header: the block only needs these 15 standard library
# symbols plus the `__future__` import. Importing the upstream module itself
# costs about 1.8 s and drags in its whole dependency graph; executing the slice
# costs about 0.08 s and exposes exactly the 24 functions and 9 constants.
SYNTHESISED_HEADER = """\
from __future__ import annotations
import bz2
import gzip
import hashlib
import lzma
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from urllib.parse import urlparse
"""

STRING_PLACEHOLDER = "<str>"

# --- The CLOSED list of declared divergences ---------------------------------
#
# ELEVEN families, and nothing else. Each one is recognised by an explicit
# transformation below, and each one asserts its CARDINAL. A blanket tolerance
# by function name is forbidden: it would let an unrelated change ride along.
#
# Families 1 to 3 are the ones the story declared:
#
#   1. the logging sites: `print(...)` became `logger.info(...)` and
#      `logger.warning(...)`. The upstream block has 13 print sites; this
#      package has 19 logger sites, and EVERY one of them is counted -- the
#      added function included. Until the code review of 9 September 2026 the
#      tally silently excluded `_declaring_data_filter`, so the package was
#      said to carry 15 sites when it carried 16, and a second logger call
#      inside that function, or a warning downgraded to info there, passed
#      unseen. The gap between 13 and 19 is reconciled below, region by
#      region, and asserted;
#   2. the workspace parameter added to `prepare_source`: exactly one
#      `arguments` node differs, and the one statement it governs;
#   3. the tar security filter: one added FUNCTION, `_declaring_data_filter`,
#      whose BODY is pinned in `DECLARED_ADDED_FUNCTIONS` below and compared
#      like any other code. Asserting only its NAME -- which is all this family
#      did until 9 September 2026 -- left the one function with no upstream
#      counterpart entirely unread: a `return None` added there amputates every
#      matching tar member IN SILENCE, which is precisely what the module's
#      positive-only oracle forbids, and the proof stayed green. The `filter=`
#      keyword itself is no longer folded away by a generic transformation --
#      it now sits inside the pinned region of family 6, which is STRICTER: the
#      whole extraction statement is pinned, instead of tolerating a filter
#      keyword on any `extractall`.
#
# Families 4 to 11 come from two code reviews. The reviews of 8 and 9 September
# 2026 found, between them, ten defects in the transported code. They are not
# translation artefacts: they are deliberate behavioural repairs, and this proof
# is built to fail on any divergence that is not declared. So each one is
# declared here, pinned on BOTH sides, and required to occur exactly once.
#
# ONE EXCEPTION, AND IT IS NAMED. Family 7 is a PURE INSERTION: it has no
# upstream run to match, so its position is declared (`at`) and the sentinel is
# inserted there rather than found. It is pinned on ONE side, not two, and
# `test_the_declared_regions_are_the_only_ones` says so explicitly. Claiming
# otherwise -- as the Completion Notes of 9 September did before this review --
# overstates the rigour of the proof, which the project's first absolute rule
# forbids more firmly than it forbids the weakness itself.
#
# HOW A PINNED REGION IS WRITTEN. `before` is the upstream source it replaces
# (French identifiers), `after` is the source that replaces it (English). Both
# are parsed and normalised exactly like the code they have to match. Message
# texts are written `"<str>"`: string constants are erased before comparison
# because they are translations (AC-2 a), so copying the prose in would prove
# nothing and would rot. What IS matched inside a region is its structure and
# its identifiers -- the new locals the repairs introduce (`dest_resolved`,
# `staging`, `item`, `target`, `moved_any`, `occupied`, `already_occupied`,
# `attempted_archives`, `amputated_archives`) have no entry in the
# correspondence table, so they would fail the proof anywhere OUTSIDE a declared
# region. Everything outside the regions is still compared strictly.
EXPECTED_ORIGINAL_PRINT_SITES = 13
# Counted over EVERY function of the transported module, the added one included.
EXPECTED_LOGGING_SITES = 19
EXPECTED_INFO_SITES = 9
EXPECTED_WARNING_SITES = 10
DIVERGENT_SIGNATURE = "preparer_source"
ADDED_PARAMETER = "workspace"
D26_FILTER_FUNCTION = "_declaring_data_filter"


def _fail_without_upstream() -> Path:
    raw = os.environ.get(UPSTREAM_ENV)
    if not raw:
        raise AssertionError(
            f"{UPSTREAM_ENV} is not set. The equivalence proof needs a checkout "
            f"of the upstream project (crypto-scan) to compare against. Set it "
            f"to the repository root, e.g. {UPSTREAM_ENV}=C:/git/crypto-scan. "
            f"This is a hard failure on purpose: a skipped equivalence proof is "
            f"a green suite that proves nothing."
        )
    root = Path(raw)
    module = root / UPSTREAM_MODULE
    if not module.is_file():
        raise AssertionError(
            f"{UPSTREAM_ENV} points at {root}, where {UPSTREAM_MODULE} does not "
            f"exist. Point it at the root of the upstream repository."
        )
    return module


def _read_original_slice() -> str:
    module = _fail_without_upstream()
    lines = module.read_text(encoding="utf-8").splitlines(keepends=True)
    start = end = None
    for index, line in enumerate(lines):
        if start is None and line.startswith(BLOCK_START_MARKER):
            start = index - 1          # the banner line above the marker
        elif line.startswith(BLOCK_END_MARKER):
            end = index - 2            # stop above the next section banner
            break
    if start is None or end is None or end <= start:
        raise AssertionError(
            f"Could not delimit the transported block in {module}: markers "
            f"{BLOCK_START_MARKER!r} / {BLOCK_END_MARKER!r} not found in that "
            f"order. The upstream file was restructured; fix the markers."
        )
    return "".join(lines[start:end])


def _load_correspondence() -> dict:
    path = REPO_ROOT / "transport" / "correspondance.json"
    return json.loads(path.read_text(encoding="utf-8"))


CORRESPONDENCE = _load_correspondence()
SYMBOLS = {}
for _section in ("functions", "constants", "parameters", "local_variables"):
    SYMBOLS.update(CORRESPONDENCE[_section])
ENUM_VALUES = CORRESPONDENCE["enumeration_values"]
# English -> French, used to de-translate the transported module.
REVERSE_SYMBOLS = {english: french for french, english in SYMBOLS.items()}
REVERSE_ENUM = {english: french for french, english in ENUM_VALUES.items()}


class _Detranslator(ast.NodeTransformer):
    """Rename transported identifiers back to their originals.

    Only names present in the correspondence table are touched. That is the
    whole point: an identifier renamed WITHOUT a table entry keeps its English
    form, does not match the original, and makes the proof fail. The table
    therefore verifies itself.

    Attributes are never renamed -- they belong to the standard library, not to
    this package.
    """

    def visit_Name(self, node: ast.Name) -> ast.AST:
        node.id = REVERSE_SYMBOLS.get(node.id, node.id)
        return self.generic_visit(node)

    def visit_arg(self, node: ast.arg) -> ast.AST:
        node.arg = REVERSE_SYMBOLS.get(node.arg, node.arg)
        return self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        node.name = REVERSE_SYMBOLS.get(node.name, node.name)
        return self.generic_visit(node)


class _Normaliser(ast.NodeTransformer):
    """Erase what the proof deliberately does not compare.

    - string constants become a placeholder: they are translated, so comparing
      them would compare translations, not code. The STRUCTURE of an f-string
      is kept: a `JoinedStr` still alternates literal segments and interpolated
      expressions, so translating `f"File {n} not found"` as `f"{n} not found"`
      removes a node and fails;
    - type annotations are dropped: `str | None` is unchanged by translation,
      but comparing them adds nothing and they carry no behaviour.
    """

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if isinstance(node.value, str):
            return ast.copy_location(ast.Constant(value=STRING_PLACEHOLDER), node)
        return node


class _LoggingNormaliser(ast.NodeTransformer):
    """Declared divergence 1: fold both logging shapes onto a common form.

    `print(f"[INFO] a {x} b {y}")` and `logger.info("a %s b %s", x, y)` are both
    rewritten to `print(x, y)`. The INTERPOLATED EXPRESSIONS survive and are
    compared; the message text does not, and the level does not -- the level is
    asserted separately, and over EVERY function of the module -- the added one
    included, which is where the tally used to stop short.
    """

    def __init__(self) -> None:
        self.print_sites = 0
        self.logger_sites = 0
        self.info_sites = 0
        self.warning_sites = 0

    def visit_Call(self, node: ast.Call) -> ast.AST:
        self.generic_visit(node)
        if isinstance(node.func, ast.Name) and node.func.id == "print":
            self.print_sites += 1
            values = []
            for arg in node.args:
                if isinstance(arg, ast.JoinedStr):
                    values.extend(part.value for part in arg.values
                                  if isinstance(part, ast.FormattedValue))
            return ast.copy_location(
                ast.Call(func=ast.Name(id="print", ctx=ast.Load()),
                         args=values, keywords=[]), node)
        if (isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "logger"):
            self.logger_sites += 1
            if node.func.attr == "info":
                self.info_sites += 1
            elif node.func.attr == "warning":
                self.warning_sites += 1
            return ast.copy_location(
                ast.Call(func=ast.Name(id="print", ctx=ast.Load()),
                         args=list(node.args[1:]), keywords=[]), node)
        return node


@dataclass(frozen=True)
class DeclaredPatch:
    """One pinned region of the closed list of divergences.

    `at` is set only for a pure INSERTION (`before` empty): there is no run to
    match on the upstream side, so the position is declared instead of being
    left free, and the transported side must be found at exactly that index of
    the function body.
    """

    id: str
    function: str            # name on the UPSTREAM side
    why: str
    before: str              # upstream source, French identifiers
    after: str               # this package's source, English identifiers
    at: int | None = None


def _prepare_upstream_snippet(source: str) -> list:
    return [_LoggingNormaliser().visit(node)
            for node in ast.parse(textwrap.dedent(source)).body]


def _prepare_transported_snippet(source: str) -> list:
    # De-translated the same way the transported module is, so the snippet can
    # be READ in English while being MATCHED against French. The names the
    # repairs introduce have no table entry and survive untouched on both
    # sides, which is what makes them safe to write here and unsafe anywhere
    # else.
    nodes = [_Detranslator().visit(node)
             for node in ast.parse(textwrap.dedent(source)).body]
    return [_LoggingNormaliser().visit(node) for node in nodes]


DECLARED_PATCHES = (
    DeclaredPatch(
        id="4-download-creates-its-destination",
        function="telecharger_source",
        why="the destination directory is created before the download writes "
            "into it. Without it the write raised FileNotFoundError, which the "
            "broad `except` below re-reported as a network failure -- a wrong "
            "cause on what is in fact the normal case of an absent directory.",
        before="""
            nom_fichier = Path(urlparse(url).path).name or "<str>"
        """,
        after="""
            try:
                dest_dir.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise RuntimeError(
                    f"<str>{dest_dir}<str>{exc.__class__.__name__}<str>{exc}<str>"
                ) from exc
            file_name = Path(urlparse(url).path).name or "<str>"
        """,
    ),
    DeclaredPatch(
        id="5-containment-is-checked-on-path-components",
        function="_chemin_extraction_sur",
        why="containment is a path relationship, not a string prefix. "
            "`str(target).startswith(str(dest))` accepts a sibling directory "
            "whose name merely extends the destination's name.",
        before="""
            if not str(cible).startswith(str(dest.resolve())):
                raise ValueError(f"<str>{membre}")
        """,
        after="""
            dest_resolved = dest.resolve()
            if target != dest_resolved and dest_resolved not in target.parents:
                raise ValueError(f"<str>{member}")
        """,
    ),
    DeclaredPatch(
        id="6-tar-extraction-is-staged-then-moved",
        function="_extraire_tar_avec_verification",
        why="`extractall` writes members one at a time, so a filter refusing a "
            "LATER member leaves earlier ones on disk -- contradicting the very "
            "message that says the archive is NOT extracted. Staging makes the "
            "claim true. This region also PINS the `filter=` site of family 3. "
            "Reworked on 9 September 2026: `shutil.move` moved a directory "
            "INSIDE an existing directory of the same name, so a second "
            "extraction into the same destination produced `x/x/...` where "
            "`extractall(dest)` merged in place; and the move loop sat outside "
            "the `try`, so a failure part-way left `dest` half populated, the "
            "staging directory orphaned, and the comment claiming an untouched "
            "destination false.",
        before="""
            t.extractall(dest)
        """,
        after="""
            staging = Path(tempfile.mkdtemp(prefix="unboxr_tar_staging_"))
            moved_any = False
            try:
                t.extractall(staging, filter=_declaring_data_filter)
                dest.mkdir(parents=True, exist_ok=True)
                for item in staging.iterdir():
                    moved_any = True
                    target = dest / item.name
                    if item.is_dir() and target.is_dir() and not target.is_symlink():
                        shutil.copytree(item, target, dirs_exist_ok=True,
                                        symlinks=True)
                        shutil.rmtree(item)
                    else:
                        if target.is_dir() and not target.is_symlink():
                            shutil.rmtree(target)
                        elif target.exists() or target.is_symlink():
                            target.unlink()
                        shutil.move(str(item), str(target))
            except Exception:
                if moved_any:
                    logger.warning("<str>", tar_path, dest)
                raise
            finally:
                shutil.rmtree(staging, ignore_errors=True)
        """,
    ),
    DeclaredPatch(
        id="7-the-ledger-of-archives-already-attempted",
        function="aplatir_archives_imbriquees",
        why="a failed extraction never removes its source, so an unguarded "
            "re-scan rediscovers the SAME archive at every level. TWO ledgers, "
            "not one: `attempted_archives` answers 'do not offer this one "
            "again' and takes in an archive that was extracted but could not be "
            "REMOVED; `amputated_archives` answers 'this content is NOT in the "
            "tree', which is false of that same archive. Merging them, as the "
            "single ledger of 8 September did, would make the closing recap of "
            "family 10 assert an amputation that did not happen. They are read "
            "by families 8 and 10 and written by family 9.",
        before="",
        after="""
            attempted_archives: set[Path] = set()
            amputated_archives: set[Path] = set()
        """,
        at=1,
    ),
    DeclaredPatch(
        id="8-an-archive-that-failed-is-not-rediscovered",
        function="aplatir_archives_imbriquees",
        why="one added condition in the generator: an archive already in the "
            "ledger is not offered to the next level. Without it a single "
            "persistently failing archive inflated the amputation count up to "
            "ten times and misattributed the final warning to nesting depth.",
        before="""
            archives_trouvees = sorted(
                (p for p in racine.rglob("<str>") if p.is_file() and est_archive(p)),
                key=lambda c: c.relative_to(racine).as_posix(),
            )
        """,
        after="""
            found_archives = sorted(
                (p for p in root.rglob("<str>")
                 if p.is_file() and p not in attempted_archives and is_archive(p)),
                key=lambda c: c.relative_to(root).as_posix(),
            )
        """,
    ),
    DeclaredPatch(
        id="9-extraction-collision-and-removal-are-reported-apart",
        function="aplatir_archives_imbriquees",
        why="FIVE repairs share one contiguous region and cannot be pinned "
            "apart: (a) two archives with the same base name and different "
            "extensions merged their content with no trace, now announced; "
            "(b) a failed archive joins the ledgers of family 7 instead of "
            "being retried; (c) a failed `unlink` AFTER a successful "
            "extraction is no longer reported as an extraction failure, which "
            "was false -- the content IS in the extracted tree; (d) that same "
            "archive nonetheless joins `attempted_archives`, because it is "
            "still on disk and was otherwise re-discovered and re-extracted at "
            "EVERY level -- the defect (b) closed, re-opened by (c), found on "
            "9 September 2026; (e) the occupancy test now goes through "
            "`is_dir()` and a guarded read, because `iterdir()` on a plain file "
            "of that name raised OUTSIDE any `try` and aborted the whole "
            "flattening, leaving every remaining archive unopened without a "
            "single record. The message no longer names a cause it cannot "
            "know: a reused workspace and an earlier level of the same run "
            "produce the same picture as 'another archive of the same name'.",
        before="""
            try:
                extraire_archive(archive, dest_sous)
                archive.unlink()
            except Exception as exc:
                print(f"{archive}{ext_matchee}{exc}")
        """,
        after="""
            occupied = False
            if sub_dest.is_dir():
                try:
                    occupied = any(sub_dest.iterdir())
                except OSError:
                    occupied = False
            if occupied:
                logger.warning("<str>", archive, sub_dest)
            try:
                extract_archive(archive, sub_dest)
            except Exception as exc:
                logger.warning("<str>", archive, matched_ext, exc)
                attempted_archives.add(archive)
                amputated_archives.add(archive)
                continue
            try:
                archive.unlink()
            except OSError as exc:
                logger.warning("<str>", archive, exc)
                attempted_archives.add(archive)
        """,
    ),
    DeclaredPatch(
        id="10-the-run-does-not-end-on-an-unqualified-success",
        function="aplatir_archives_imbriquees",
        why="the loop leaves by this branch, so an unqualified 'finished' was "
            "the LAST word of a run that had amputated the corpus. Each failure "
            "was announced when it happened, but a reader of the tail sees "
            "completeness. The recap reads `amputated_archives`, never "
            "`attempted_archives` -- an archive kept because its `unlink` "
            "failed is NOT missing from the tree, and naming it here would "
            "assert an amputation that did not happen. Found on 9 September "
            "2026.",
        before="""
            print(f"{niveau - 1}")
        """,
        after="""
            if amputated_archives:
                logger.warning("<str>", len(amputated_archives),
                               "<str>".join(sorted(str(p) for p in amputated_archives)))
            logger.info("<str>", level - 1)
        """,
    ),
    DeclaredPatch(
        id="11-the-first-level-destination-is-guarded-too",
        function="preparer_source",
        why="family 9 guards the NESTED destinations and left the FIRST-level "
            "one unguarded, so a caller that reuses a workspace -- the case "
            "this function's own docstring names -- poured a second extraction "
            "into the first with no trace at all. Same rule as family 9: state "
            "what is observed, never a cause. Found on 9 September 2026.",
        before="""
            print(f"{chemin_local}")
        """,
        after="""
            if destination.is_dir():
                try:
                    already_occupied = any(destination.iterdir())
                except OSError:
                    already_occupied = False
                if already_occupied:
                    logger.warning("<str>", destination)
            logger.info("<str>", local_path)
        """,
    ),
)

PATCH_NODES = {patch.id: (_prepare_upstream_snippet(patch.before),
                          _prepare_transported_snippet(patch.after))
               for patch in DECLARED_PATCHES}

# --- The function that has NO upstream counterpart ---------------------------
#
# Declared divergence 3 adds one function, and until 9 September 2026 the proof
# checked its NAME and nothing else. Both comparison paths skipped it: the
# master test iterates over the UPSTREAM functions, where it does not exist, and
# the level tally excluded it by name. Measured consequences, both green at the
# time: inserting `if member.name.endswith(".py"): return None` made the filter
# drop every matching tar member IN SILENCE -- a corpus amputation of exactly
# the kind the module's positive-only oracle exists to forbid -- and downgrading
# its `logger.warning` to `logger.info` demoted an announced amputation without
# a single test noticing.
#
# So the body is pinned here, in the same form as any declared region: written
# in English, de-translated and normalised exactly like the module, message
# texts erased as `"<str>"`. Annotations are dropped by `_strip_annotations`, so
# they are omitted here rather than repeated.
DECLARED_ADDED_FUNCTIONS = {
    "_declaring_data_filter": """
        def _declaring_data_filter(member, dest_path):
            try:
                return tarfile.data_filter(member, dest_path)
            except tarfile.FilterError as exc:
                logger.warning("<str>", member.name, exc)
                raise
    """,
}

# How many logging sites live INSIDE the pinned regions, per side. The families
# are counted before the regions are folded away, so these numbers are what
# reconciles the two tallies:
#
#     13 upstream prints - 3 inside regions + 8 inside regions = 18 compared
#     18 compared + 1 in the added function                    = 19 in total
#
# Nothing outside a declared region may add or remove a site: the arithmetic is
# asserted, not commented.
PATCHED_PRINT_SITES = 3
PATCHED_LOGGER_SITES = 8
PATCHED_INFO_SITES = 2
PATCHED_WARNING_SITES = 6
# Sites in functions that HAVE an upstream counterpart -- what the master test
# walks. The added function is counted apart, and then together, so that
# neither tally can quietly absorb a site the other one lost.
# String constants, counted over the compared functions once the pinned regions
# are folded and the logging message texts dropped. 111 positions, of which 44
# differ -- docstrings and exception messages, which ARE translated. The other
# 67 are literals that read the same in both languages, and they are what this
# cardinal protects: see
# `test_the_string_constants_that_differ_are_exactly_the_translated_ones`.
EXPECTED_STRING_POSITIONS = 111
EXPECTED_TRANSLATED_STRINGS = 44
EXPECTED_COMPARED_LOGGING_SITES = 18
EXPECTED_COMPARED_INFO_SITES = 9
EXPECTED_COMPARED_WARNING_SITES = 9
ADDED_FUNCTION_WARNING_SITES = 1


def _string_constants(node: ast.AST) -> list:
    """Every string constant reachable from `node`, in walk order.

    Both sides are structurally identical by the time this runs -- the master
    test proves it -- so walk order pairs them position by position.
    """
    return [sub.value for sub in ast.walk(node)
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str)]


def _statement_lists(node: ast.AST):
    """Every list-of-statements reachable from `node`, nested ones included."""
    for sub in ast.walk(node):
        for field in ("body", "orelse", "finalbody"):
            value = getattr(sub, field, None)
            if isinstance(value, list) and value and all(
                    isinstance(item, ast.stmt) for item in value):
                yield value


def _match_key(node: ast.AST) -> str:
    return _dump(_strip_annotations(copy.deepcopy(node)))


def _find_run(function_node: ast.AST, snippet: list) -> list:
    wanted = [_match_key(node) for node in snippet]
    hits = []
    for body in _statement_lists(function_node):
        for index in range(len(body) - len(wanted) + 1):
            if [_match_key(node) for node in body[index:index + len(wanted)]] == wanted:
                hits.append((body, index))
    return hits


def _sentinel(patch: DeclaredPatch) -> ast.stmt:
    # A NAME, never a string: string constants are erased by the normaliser, so
    # a string sentinel would make every region interchangeable and a region
    # folded at the wrong place would still compare equal.
    return ast.Expr(value=ast.Name(id=f"__divergence_{patch.id}__",
                                   ctx=ast.Load()))


def _fold_declared_patches(case: unittest.TestCase, node: ast.FunctionDef,
                           function_name: str, side: str) -> ast.FunctionDef:
    """Replace each declared region of `function_name` by its sentinel.

    `side` is "before" (upstream) or "after" (this package). Each region must
    match EXACTLY once: zero means the code drifted away from its declaration,
    more than one means the declaration is too vague to pin anything.
    """
    for patch in DECLARED_PATCHES:
        if patch.function != function_name:
            continue
        snippet = PATCH_NODES[patch.id][0 if side == "before" else 1]
        if not snippet:
            case.assertIsNotNone(
                patch.at, f"divergence {patch.id} is a pure insertion and must "
                          f"declare the index it is inserted at")
            node.body.insert(patch.at, _sentinel(patch))
            continue
        hits = _find_run(node, snippet)
        case.assertEqual(
            1, len(hits),
            f"divergence {patch.id} must match EXACTLY once on the {side!r} "
            f"side of {function_name}; found {len(hits)}. Either the code "
            f"changed without updating its declaration, or the declaration no "
            f"longer pins a single region.\nWhy this region exists: {patch.why}")
        body, index = hits[0]
        if patch.at is not None:
            case.assertIs(body, node.body,
                          f"divergence {patch.id} declares an index in the "
                          f"function body, but matched a nested body")
            case.assertEqual(patch.at, index,
                             f"divergence {patch.id} moved inside the body")
        body[index:index + len(snippet)] = [_sentinel(patch)]
    return node


def _top_level(tree: ast.Module) -> tuple[dict, list]:
    functions = {node.name: node for node in tree.body
                 if isinstance(node, ast.FunctionDef)}
    # `AnnAssign` as well as `Assign`: `LIMIT: int = 3` is a module constant
    # too, and collecting only `Assign` let one be added without appearing in
    # any comparison -- found in code review on 9 September 2026.
    constants = [target.id for node in tree.body if isinstance(node, ast.Assign)
                 for target in node.targets if isinstance(target, ast.Name)]
    constants += [node.target.id for node in tree.body
                  if isinstance(node, ast.AnnAssign)
                  and isinstance(node.target, ast.Name)]
    return functions, constants


# What a module of this package may contain at the top level, besides the
# functions and the constants that are compared one by one. Anything else --
# a class, a call, an `if`, a `with` -- is code that runs at IMPORT time and
# that no part of the proof reads. A `logger.warning(...)` placed there fires
# before any capture is installed; a `class` enters no compared set at all.
# Both were measured green on 9 September 2026, which is why this list exists.
ALLOWED_MODULE_STATEMENTS = (
    ast.Import, ast.ImportFrom, ast.Assign, ast.AnnAssign, ast.FunctionDef,
    ast.Expr,          # the module docstring, and nothing else -- checked below
)

# The imports the transported module is allowed to carry: the 15 standard
# library symbols the upstream block needs, plus `logging`, which is the whole
# of divergence 1 on the import line. `standard library only` is a promise the
# package makes in its own docstring and in its README; until 9 September 2026
# no test held it, and `import json` -- or any third-party name -- passed.
# The one module-level binding the transported side adds. It is the
# PRECONDITION of declared divergence 1, not an extra: the de-translation only
# recognises logging calls made on a name called `logger`, so AC-2 (c) requires
# it to be named exactly that and obtained from `logging.getLogger(__name__)`.
# Declared here so that it is one NAMED exception rather than a hole.
DECLARED_ADDED_MODULE_BINDINGS = {"logger"}

ALLOWED_IMPORTS = {
    "__future__", "bz2", "gzip", "hashlib", "logging", "lzma", "os",
    "platform", "shutil", "subprocess", "sys", "tarfile", "tempfile",
    "urllib.request", "zipfile", "pathlib", "urllib.parse",
}


def _dump(node: ast.AST) -> str:
    return ast.dump(_Normaliser().visit(copy.deepcopy(node)))


class _TransportFixture(unittest.TestCase):
    """Shared parsing of both sides, done once."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.original_source = _read_original_slice()
        cls.original_tree = ast.parse(cls.original_source)
        cls.transported_source = (REPO_ROOT / "unboxr" / "extraction.py").read_text(
            encoding="utf-8")
        cls.transported_tree = ast.parse(cls.transported_source)
        cls.original_functions, cls.original_constants = _top_level(cls.original_tree)
        cls.transported_functions, cls.transported_constants = _top_level(
            cls.transported_tree)


class TestSliceIntegrity(_TransportFixture):
    """The slice really is the block the story measured."""

    def test_the_slice_holds_24_functions_and_9_constants(self):
        self.assertEqual(EXPECTED_FUNCTIONS, len(self.original_functions))
        self.assertEqual(EXPECTED_CONSTANTS, len(self.original_constants))

    def test_the_correspondence_table_covers_98_symbols(self):
        self.assertEqual(98, len(SYMBOLS))
        self.assertEqual(len(SYMBOLS), len(REVERSE_SYMBOLS),
                         "two originals map to the same transported name; the "
                         "reverse table would be ambiguous")

    def test_the_declared_sub_totals_of_the_table_are_true(self):
        """`_meta.counts` was checked by nothing.

        Only the merged total was asserted, so moving a symbol from
        `parameters` to `local_variables` left all four sub-totals false in
        silence, and a key present in TWO sections was absorbed by
        `SYMBOLS.update()` without a word -- found in code review on
        9 September 2026.
        """
        counts = CORRESPONDENCE["_meta"]["counts"]
        sections = ("functions", "constants", "parameters", "local_variables")
        for section in sections:
            with self.subTest(section=section):
                self.assertEqual(counts[section], len(CORRESPONDENCE[section]))
        self.assertEqual(counts["total_symbols"],
                         sum(counts[section] for section in sections))
        seen = collections.Counter()
        for section in sections:
            seen.update(CORRESPONDENCE[section].keys())
        self.assertEqual([], [name for name, n in seen.items() if n > 1],
                         "a symbol declared in two sections is counted twice "
                         "and silently overwritten when the sections are merged")
        self.assertEqual(counts["total_symbols"], len(seen))

    def test_the_transported_module_adds_no_top_level_code(self):
        """The proof reads functions and constants; nothing else was read.

        A class, a call, or a logging site at module level runs at import time
        and entered no compared set. Measured green on 9 September 2026:
        `SNEAKY = 42`, `class Sneaky:` and a `logger.warning(...)` between the
        imports all crossed the proof untouched.
        """
        unexpected = [ast.dump(node)[:80] for node in self.transported_tree.body
                      if not isinstance(node, ALLOWED_MODULE_STATEMENTS)]
        self.assertEqual([], unexpected)
        expressions = [node for node in self.transported_tree.body
                       if isinstance(node, ast.Expr)]
        self.assertEqual(1, len(expressions),
                         "the only top-level expression is the module docstring")
        self.assertIsInstance(expressions[0].value, ast.Constant)

    def test_the_transported_module_adds_no_constant(self):
        """The symmetric check of the one that exists for functions.

        `test_transport_adds_exactly_one_function_and_it_is_the_d26_filter`
        catches an added FUNCTION. Nothing caught an added CONSTANT: the
        comparison iterates over the keys of the table, which is the upstream
        side, so a surplus on the transported side was invisible.
        """
        self.assertEqual(
            sorted([CORRESPONDENCE["constants"][name]
                    for name in self.original_constants]
                   + sorted(DECLARED_ADDED_MODULE_BINDINGS)),
            sorted(self.transported_constants),
            "a module constant was added, removed or renamed outside the table "
            "and outside DECLARED_ADDED_MODULE_BINDINGS")
        binding = [node for node in self.transported_tree.body
                   if isinstance(node, ast.Assign)
                   and any(isinstance(t, ast.Name) and t.id == "logger"
                           for t in node.targets)]
        self.assertEqual(1, len(binding))
        self.assertEqual(
            ast.dump(ast.parse("logging.getLogger(__name__)").body[0].value),
            ast.dump(binding[0].value),
            "AC-2 (c) requires the logger to be obtained by "
            "logging.getLogger(__name__); the de-translation recognises no "
            "other shape, so this is a constraint of form, not of taste")

    def test_the_transported_module_imports_only_the_standard_library(self):
        """`standard library only` is a promise; this is what holds it."""
        imported = set()
        for node in ast.walk(self.transported_tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module)
        self.assertEqual(set(), imported - ALLOWED_IMPORTS,
                         "an import appeared that the upstream block did not "
                         "need; a third-party dependency would enter here")

    def test_every_original_function_and_constant_is_in_the_table(self):
        for name in self.original_functions:
            self.assertIn(name, CORRESPONDENCE["functions"])
        for name in self.original_constants:
            self.assertIn(name, CORRESPONDENCE["constants"])


class TestMasterEquivalence(_TransportFixture):
    """De-translate, then require strict AST equality, function by function."""

    def _detranslated_functions(self):
        tree = copy.deepcopy(self.transported_tree)
        tree = _Detranslator().visit(tree)
        ast.fix_missing_locations(tree)
        functions, _ = _top_level(tree)
        return functions

    def test_transport_adds_exactly_one_function_and_it_is_the_d26_filter(self):
        extra = set(self.transported_functions) - {
            CORRESPONDENCE["functions"][name] for name in self.original_functions}
        self.assertEqual({D26_FILTER_FUNCTION}, extra,
                         "declared divergence 3 allows exactly one added "
                         "function: the tar filter that announces what it "
                         "refuses. Anything else is an undeclared divergence.")

    def test_every_function_is_ast_identical_after_de_translation(self):
        transported = self._detranslated_functions()
        logging_normaliser = _LoggingNormaliser()
        original_logging = _LoggingNormaliser()

        for name, original_node in self.original_functions.items():
            with self.subTest(function=name):
                self.assertIn(name, transported,
                              f"{name} has no counterpart after de-translation")
                left = copy.deepcopy(original_node)
                right = copy.deepcopy(transported[name])
                left = original_logging.visit(left)
                right = logging_normaliser.visit(right)
                # Folded AFTER the logging normalisation, so the sites inside a
                # pinned region are still counted by family 1 rather than
                # vanishing from the tally with the region.
                left = _fold_declared_patches(self, left, name, "before")
                right = _fold_declared_patches(self, right, name, "after")
                if name == DIVERGENT_SIGNATURE:
                    right = _undo_workspace_parameter(self, right)
                ast.fix_missing_locations(left)
                ast.fix_missing_locations(right)
                self.assertEqual(_dump(_strip_annotations(left)),
                                 _dump(_strip_annotations(right)))

        self.assertEqual(EXPECTED_ORIGINAL_PRINT_SITES,
                         original_logging.print_sites,
                         "the upstream block no longer has 13 print sites")
        self.assertEqual(EXPECTED_COMPARED_LOGGING_SITES,
                         logging_normaliser.logger_sites,
                         "declared divergence 1 is exactly 18 logging sites in "
                         "the functions that have an upstream counterpart")
        self.assertEqual(EXPECTED_COMPARED_INFO_SITES,
                         logging_normaliser.info_sites)
        self.assertEqual(EXPECTED_COMPARED_WARNING_SITES,
                         logging_normaliser.warning_sites)

    def test_the_string_constants_that_differ_are_exactly_the_translated_ones(self):
        """The hole the code review of 9 September 2026 measured.

        `_Normaliser` erases EVERY string constant, on the ground that strings
        are translated. Most are; these are not, and each of the seven below
        was mutated in a real run and passed GREEN:

            ("http", "https")      ->  ("ftp", "https")
            return "source"        ->  return "src"
            rglob("*.tar")         ->  rglob("*.tarx")
            mode: str = "r:*"      ->  "r:"
            environ.get("ProgramFiles")  ->  "ProgrammFiles"
            the 7-Zip flag "-y"    ->  "-n"     (7-Zip then waits on a prompt)
            the staging prefix

        None of them is a translation: they read the same in both languages.

        The rule that closes it, without a list to maintain: a string that is
        IDENTICAL on both sides at the same position must STAY identical, and
        the number of positions where the two differ is a declared cardinal.
        Mutating a technical literal turns an identical position into a
        differing one, the cardinal moves, and the proof fails. Rewording a
        message leaves it differing and changes nothing -- message TEXTS are
        out of scope, and the story says so.

        The comparison runs on the same trees the master test compares, so the
        pinned regions are already folded away and the logging message texts
        already dropped by `_LoggingNormaliser`.
        """
        transported = self._detranslated_functions()
        positions = 0
        differing = []
        for name, original_node in self.original_functions.items():
            left = _LoggingNormaliser().visit(copy.deepcopy(original_node))
            right = _LoggingNormaliser().visit(copy.deepcopy(transported[name]))
            left = _fold_declared_patches(self, left, name, "before")
            right = _fold_declared_patches(self, right, name, "after")
            if name == DIVERGENT_SIGNATURE:
                right = _undo_workspace_parameter(self, right)
            upstream_strings = _string_constants(left)
            moved_strings = _string_constants(right)
            self.assertEqual(len(upstream_strings), len(moved_strings),
                             f"{name} does not even hold the same NUMBER of "
                             f"string constants on both sides")
            positions += len(upstream_strings)
            for was, now in zip(upstream_strings, moved_strings):
                if REVERSE_ENUM.get(now, now) != was:
                    differing.append((name, was, now))

        self.assertEqual(EXPECTED_STRING_POSITIONS, positions,
                         "a string constant was added or removed outside a "
                         "declared region")
        short = [(fn, was, now) for fn, was, now in differing
                 if len(was) < 60 and len(now) < 60]
        self.assertEqual(
            EXPECTED_TRANSLATED_STRINGS, len(differing),
            "\n".join([
            "the number of string constants that differ between the two sides ",
            "moved. A technical literal -- a URL scheme, a glob, a tar mode, a ",
            "subprocess flag, an environment variable name -- reads the same ",
            "in both languages and must stay identical; only messages and ",
            "docstrings are allowed to differ. Short differing constants, ",
            "where a mistranslated literal would show up first:",
            *(f"  {fn}: {was!r} -> {now!r}" for fn, was, now in short),
            ]))

    def test_the_strings_inside_a_declared_region_are_compared_too(self):
        """A pinned region is a tolerance, and it tolerated its own strings.

        `_match_key` erases string constants, so a region matched whatever its
        literals were: the staging prefix could be changed to anything and the
        proof stayed green -- measured on 9 September 2026, the one mutation of
        the seven that survived the cardinal above, because it lives INSIDE a
        region.

        So each declaration is read a second time, against the code it pinned,
        and its strings are required to be equal. `"<str>"` stays a WILDCARD --
        that is how a message text is written, and message texts are out of
        scope -- but anything a declaration spells out is now binding.
        """
        for patch in DECLARED_PATCHES:
            if not patch.after.strip():
                continue
            with self.subTest(divergence=patch.id):
                declared = [_LoggingNormaliser().visit(node) for node in
                            ast.parse(textwrap.dedent(patch.after)).body]
                function = self.transported_functions[
                    CORRESPONDENCE["functions"][patch.function]]
                node = _LoggingNormaliser().visit(copy.deepcopy(function))
                hits = _find_run(node, declared)
                self.assertEqual(1, len(hits),
                                 f"{patch.id} no longer pins a single region "
                                 f"of the transported code")
                body, index = hits[0]
                actual = []
                for statement in body[index:index + len(declared)]:
                    actual.extend(_string_constants(statement))
                expected = []
                for statement in declared:
                    expected.extend(_string_constants(statement))
                self.assertEqual(len(expected), len(actual))
                for was, now in zip(expected, actual):
                    if was == STRING_PLACEHOLDER:
                        continue          # a message text, deliberately free
                    self.assertEqual(was, now,
                                     f"{patch.id} declares this literal; the "
                                     f"code no longer carries it")

    def test_the_extra_logging_sites_are_accounted_for(self):
        """19 is not 13, and the difference is not free.

        The gap between the upstream prints and the transported logger calls
        has to be explained by the declared regions and by the added function,
        and by nothing else -- otherwise family 1 silently absorbs any logging
        site added anywhere. Every term of the arithmetic is asserted.
        """
        self.assertEqual(
            EXPECTED_COMPARED_LOGGING_SITES - EXPECTED_ORIGINAL_PRINT_SITES,
            PATCHED_LOGGER_SITES - PATCHED_PRINT_SITES,
            "the extra logging sites must come from the pinned regions")
        self.assertEqual(EXPECTED_COMPARED_LOGGING_SITES
                         + ADDED_FUNCTION_WARNING_SITES,
                         EXPECTED_LOGGING_SITES,
                         "the module tally is the compared one plus the added "
                         "function, which is where the hole was until "
                         "9 September 2026")
        self.assertEqual(EXPECTED_COMPARED_INFO_SITES
                         + EXPECTED_COMPARED_WARNING_SITES,
                         EXPECTED_COMPARED_LOGGING_SITES)
        self.assertEqual(EXPECTED_INFO_SITES + EXPECTED_WARNING_SITES,
                         EXPECTED_LOGGING_SITES)
        # Counted on the RAW declarations: the cached snippets have already
        # been folded, and a folded site no longer says which level it was.
        counted = _LoggingNormaliser()
        carrying = set()
        for patch in DECLARED_PATCHES:
            one = _LoggingNormaliser()
            for source in (patch.before, patch.after):
                for node in ast.parse(textwrap.dedent(source)).body:
                    counted.visit(copy.deepcopy(node))
                    one.visit(node)
            if one.print_sites or one.logger_sites:
                carrying.add(patch.id)
        self.assertEqual(
            {"6-tar-extraction-is-staged-then-moved",
             "9-extraction-collision-and-removal-are-reported-apart",
             "10-the-run-does-not-end-on-an-unqualified-success",
             "11-the-first-level-destination-is-guarded-too"}, carrying,
            "exactly four regions carry logging; a fifth would mean a site "
            "moved into a region without its declaration saying so")
        self.assertEqual(PATCHED_PRINT_SITES, counted.print_sites)
        self.assertEqual(PATCHED_LOGGER_SITES, counted.logger_sites)
        self.assertEqual(PATCHED_INFO_SITES, counted.info_sites)
        self.assertEqual(PATCHED_WARNING_SITES, counted.warning_sites)

    def test_the_added_function_body_is_pinned(self):
        """Declared divergence 3, compared instead of merely named.

        Asserting the NAME of the one added function -- all this family did
        until 9 September 2026 -- left its body read by nothing at all. A
        `return None` inserted there drops the matching tar members in silence,
        which the module's positive-only oracle forbids, and the proof stayed
        green. So the body is compared to its declaration, exactly like the
        pinned regions.
        """
        self.assertEqual(set(DECLARED_ADDED_FUNCTIONS),
                         set(self.transported_functions)
                         - {CORRESPONDENCE["functions"][name]
                            for name in self.original_functions},
                         "every function without an upstream counterpart must "
                         "have a declaration here")
        for name, source in DECLARED_ADDED_FUNCTIONS.items():
            with self.subTest(function=name):
                # NEITHER side is de-translated: the declaration is written in
                # the transported form, and so is the code. Running the table
                # over one of the two only would rename whichever identifiers
                # happen to have an entry and compare English to French.
                declared = _LoggingNormaliser().visit(
                    ast.parse(textwrap.dedent(source)).body[0])
                actual = _LoggingNormaliser().visit(
                    copy.deepcopy(self.transported_functions[name]))
                ast.fix_missing_locations(declared)
                ast.fix_missing_locations(actual)
                self.assertEqual(_dump(_strip_annotations(declared)),
                                 _dump(_strip_annotations(actual)))

    def test_the_added_function_carries_its_declared_logging(self):
        """Its level, and how many sites -- neither was counted anywhere."""
        counted = _LoggingNormaliser()
        for name in DECLARED_ADDED_FUNCTIONS:
            counted.visit(copy.deepcopy(self.transported_functions[name]))
        self.assertEqual(ADDED_FUNCTION_WARNING_SITES, counted.logger_sites)
        self.assertEqual(ADDED_FUNCTION_WARNING_SITES, counted.warning_sites)
        self.assertEqual(0, counted.info_sites,
                         "a refusal is an amputation: announcing it at the "
                         "informational level would bury it under --quiet")

    def test_each_declared_region_matches_exactly_once_on_each_side(self):
        """The cardinal of every family, asserted on its own.

        The master test above folds the regions as a side effect of comparing;
        this one states the cardinal explicitly so that a declaration which has
        stopped pinning anything fails with its own name rather than as a
        thousand-line AST diff.
        """
        transported = self._detranslated_functions()
        for patch in DECLARED_PATCHES:
            with self.subTest(divergence=patch.id):
                self.assertIn(patch.function, self.original_functions)
                left = _LoggingNormaliser().visit(
                    copy.deepcopy(self.original_functions[patch.function]))
                right = _LoggingNormaliser().visit(
                    copy.deepcopy(transported[patch.function]))
                for side, node in (("before", left), ("after", right)):
                    snippet = PATCH_NODES[patch.id][0 if side == "before" else 1]
                    if not snippet:
                        continue
                    self.assertEqual(1, len(_find_run(node, snippet)),
                                     f"{patch.id} on the {side!r} side")

    def test_the_declared_regions_are_the_only_ones(self):
        """A closed list is only closed if its size is asserted."""
        self.assertEqual(8, len(DECLARED_PATCHES),
                         "eight regions: six from the code review of "
                         "8 September 2026 and two from that of 9 September; "
                         "families 1 to 3 are handled by their own "
                         "transformations")
        one_sided = {patch.id for patch in DECLARED_PATCHES if not patch.before}
        self.assertEqual(
            {"7-the-ledger-of-archives-already-attempted"}, one_sided,
            "exactly one region is a pure insertion, and it is therefore "
            "pinned on ONE side only: there is no upstream run to match, so "
            "its sentinel is inserted at a declared index instead of found. "
            "Every other region is pinned on both. Saying 'all of them are "
            "pinned on both sides' would overstate the proof.")
        self.assertEqual(len(DECLARED_PATCHES),
                         len({patch.id for patch in DECLARED_PATCHES}))
        self.assertEqual(
            {"telecharger_source", "_chemin_extraction_sur",
             "_extraire_tar_avec_verification", "aplatir_archives_imbriquees",
             "preparer_source"},
            {patch.function for patch in DECLARED_PATCHES},
            "the repairs touch five functions and no others")

    def test_the_tar_filter_keyword_sits_inside_a_declared_region(self):
        """Family 3 is no longer folded generically, so it needs saying.

        `_undo_tar_filter` used to strip `filter=` from ANY `extractall`. That
        tolerance is gone: the single site is pinned inside family 6, so a
        filter keyword appearing on a second extraction site would now fail.
        """
        sites = [sub for sub in ast.walk(self.transported_tree)
                 if isinstance(sub, ast.Call)
                 and isinstance(sub.func, ast.Attribute)
                 and sub.func.attr == "extractall"
                 and any(kw.arg == "filter" for kw in sub.keywords)]
        self.assertEqual(1, len(sites))
        pinned = "".join(ast.dump(node) for node in
                         PATCH_NODES["6-tar-extraction-is-staged-then-moved"][1])
        self.assertIn("filter", pinned)

    def test_an_identifier_renamed_outside_the_table_is_caught(self):
        """The property that makes the table load-bearing rather than decorative."""
        mutated = ast.parse(self.transported_source.replace(
            "local_path = Path(source)", "sneaky_path = Path(source)", 1).replace(
            "local_path.exists()", "sneaky_path.exists()", 1))
        mutated = _Detranslator().visit(mutated)
        ast.fix_missing_locations(mutated)
        functions, _ = _top_level(mutated)
        right = _undo_workspace_parameter(
            self, _LoggingNormaliser().visit(functions["preparer_source"]))
        left = _LoggingNormaliser().visit(
            copy.deepcopy(self.original_functions["preparer_source"]))
        ast.fix_missing_locations(left)
        ast.fix_missing_locations(right)
        self.assertNotEqual(_dump(_strip_annotations(left)),
                            _dump(_strip_annotations(right)))


def _strip_annotations(node: ast.AST) -> ast.AST:
    for sub in ast.walk(node):
        if isinstance(sub, ast.arg):
            sub.annotation = None
        elif isinstance(sub, ast.FunctionDef):
            sub.returns = None
    return node


def _undo_workspace_parameter(case: unittest.TestCase, node: ast.FunctionDef):
    """Declared divergence 2, with its cardinal asserted."""
    names = [arg.arg for arg in node.args.args]
    # De-translation has already run, so the added parameter carries its
    # ORIGINAL-side name here: `workspace` maps back to `espace_travail`, which
    # is also the local the original assigns on its first line. That is the
    # whole point of naming it `workspace` rather than inventing a third name.
    case.assertEqual([SYMBOLS["source"], REVERSE_SYMBOLS[ADDED_PARAMETER]], names)
    case.assertEqual(1, len(node.args.defaults))
    node.args.args = node.args.args[:1]
    node.args.defaults = []

    # The one statement the parameter governs: `workspace = workspace or
    # Path(tempfile.mkdtemp(...))` folds back to `espace_travail = Path(...)`.
    # A parameter no body node reads would be dead code, which is why the
    # divergence cannot be confined to the `arguments` node alone.
    folded = 0
    for statement in node.body:
        if (isinstance(statement, ast.Assign)
                and isinstance(statement.value, ast.BoolOp)
                and isinstance(statement.value.op, ast.Or)
                and len(statement.value.values) == 2):
            statement.value = statement.value.values[1]
            folded += 1
    case.assertEqual(1, folded,
                     "declared divergence 2 is exactly one folded statement")
    return node


# Declared divergence 3 used to be folded here by dropping the `filter=`
# keyword from any `extractall`. That generic tolerance is gone: the single
# site is pinned inside the region of family 6, together with the staging it
# now needs, and `test_the_tar_filter_keyword_sits_inside_a_declared_region`
# asserts there is exactly one such site.


class TestWhatTheMasterProofCannotSee(_TransportFixture):
    """AC-2 (d): module constants, exception types, logging levels."""

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.original_namespace = {}
        exec(compile(SYNTHESISED_HEADER + cls.original_source,
                     "<upstream-slice>", "exec"), cls.original_namespace)

    def _detranslate_value(self, value):
        if isinstance(value, str):
            return REVERSE_ENUM.get(value, value)
        if isinstance(value, tuple):
            return tuple(self._detranslate_value(item) for item in value)
        if isinstance(value, frozenset):
            return frozenset(self._detranslate_value(item) for item in value)
        if isinstance(value, list):
            return [self._detranslate_value(item) for item in value]
        if isinstance(value, dict):
            return {self._detranslate_value(k): self._detranslate_value(v)
                    for k, v in value.items()}
        return value

    def test_the_nine_module_constants_are_equal_keys_and_values(self):
        """Without this, 21 entries of the extension table and the 10 magic
        signatures are held by nothing on the unboxr side."""
        for french, english in CORRESPONDENCE["constants"].items():
            with self.subTest(constant=french):
                original = self.original_namespace[french]
                moved = getattr(transported, english)
                self.assertEqual(original, self._detranslate_value(moved))

    def test_the_extension_table_still_has_68_entries(self):
        self.assertEqual(68, len(transported.CATEGORY_BY_EXT))
        self.assertEqual(38, len(transported.NOT_EXTRACTED_EXTENSIONS))
        self.assertEqual(10, len(transported.ARCHIVE_SIGNATURES))
        self.assertEqual(4, len(transported.NATIVE_TAR_MODES))
        self.assertEqual(4, len(transported.CATEGORY_IF_NOT_A_TAR))
        self.assertEqual(4, len(transported.NATURE_BY_EXTENSION))

    @staticmethod
    def _raise_name(node: ast.AST) -> str | None:
        """Dotted name of the exception a `raise` constructs, or None if bare.

        `ast.Name` is not enough: `raise tarfile.FilterError(...)` and
        `raise zipfile.BadZipFile(...)` are `ast.Attribute`, and until
        9 September 2026 they were invisible on BOTH sides -- a test that exists
        precisely because the master proof cannot see exception types had the
        same blind spot one notch further on.
        """
        if not isinstance(node, ast.Raise) or node.exc is None:
            return None
        called = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
        parts = []
        while isinstance(called, ast.Attribute):
            parts.append(called.attr)
            called = called.value
        if not isinstance(called, ast.Name):
            return "<unrecognised>"
        parts.append(called.id)
        return ".".join(reversed(parts))

    def _raised_types(self, tree: ast.Module) -> list[str]:
        return sorted(name for name in
                      (self._raise_name(sub) for sub in ast.walk(tree))
                      if name is not None)

    def _declared_raise_delta(self) -> collections.Counter:
        """What the declared regions add to, or remove from, the raise tally.

        Computed from the declarations themselves rather than written down as a
        number: a region that gains or loses a `raise` then has to say so in its
        own source, and cannot drift away from a hardcoded total.
        """
        delta = collections.Counter()
        for patch in DECLARED_PATCHES:
            for source, sign in ((patch.before, -1), (patch.after, +1)):
                for node in ast.parse(textwrap.dedent(source)).body:
                    for sub in ast.walk(node):
                        name = self._raise_name(sub)
                        if isinstance(sub, ast.Raise):
                            delta[name or "<bare>"] += sign
        for source in DECLARED_ADDED_FUNCTIONS.values():
            for node in ast.parse(textwrap.dedent(source)).body:
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Raise):
                        delta[self._raise_name(sub) or "<bare>"] += 1
        return delta

    def test_the_exception_types_change_only_where_a_region_says_so(self):
        """The master proof does not see them: `raise RuntimeError(...)` and
        `raise ValueError(...)` differ only by a Name the normaliser keeps, but
        nothing forces the SET to be the same size."""
        upstream = collections.Counter(self._raised_types(self.original_tree))
        self.assertEqual(
            {"RuntimeError": 6, "ValueError": 3, "FileNotFoundError": 1},
            dict(upstream))
        moved = collections.Counter(self._raised_types(self.transported_tree))
        delta = collections.Counter({k: v for k, v in
                                     self._declared_raise_delta().items()
                                     if k != "<bare>"})
        self.assertEqual(dict(upstream + delta), dict(moved),
                         "an exception type appeared or vanished outside the "
                         "declared regions and the declared added function")

    def test_exception_messages_did_not_become_log_records(self):
        def counted(tree):
            raises = [sub for sub in ast.walk(tree) if isinstance(sub, ast.Raise)]
            bare = [sub for sub in raises if sub.exc is None]
            return len(raises), len(bare)

        original_raises, original_bare = counted(self.original_tree)
        moved_raises, moved_bare = counted(self.transported_tree)
        delta = self._declared_raise_delta()
        added_bare = delta["<bare>"]
        added_with_message = sum(v for k, v in delta.items() if k != "<bare>")
        # THREE added `raise` on the transported side, and the split is read
        # off the declarations, not asserted from memory: two BARE re-raises
        # (the filter of family 3 re-raising what it has just announced, and
        # the staging of family 6 re-raising after discarding it) and ONE
        # carrying a message (family 4, which tells a destination that cannot
        # be prepared apart from a network failure).
        self.assertEqual((2, 1), (added_bare, added_with_message))
        self.assertEqual(original_bare + added_bare, moved_bare)
        # NOT implied by the two assertions above: those constrain the bare
        # ones and the declarations, this one constrains the module. Before
        # 9 September 2026 this line restated an arithmetic identity and
        # measured nothing -- the property it commented was held by no test.
        self.assertEqual(original_raises - original_bare + added_with_message,
                         moved_raises - moved_bare,
                         "a raise carrying a message was added or removed "
                         "outside the declared regions")

    def test_the_logging_levels_cover_every_function_of_the_module(self):
        """No function is skipped -- that exclusion was the hole.

        `_declaring_data_filter` used to be skipped here "counted separately",
        and it was counted nowhere. Downgrading its warning to an informational
        record then demoted an announced amputation with nothing to catch it.
        """
        info = warning = 0
        for name, node in self.transported_functions.items():
            for sub in ast.walk(node):
                if (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute)
                        and isinstance(sub.func.value, ast.Name)
                        and sub.func.value.id == "logger"):
                    info += sub.func.attr == "info"
                    warning += sub.func.attr == "warning"
        self.assertEqual(EXPECTED_INFO_SITES, info)
        self.assertEqual(EXPECTED_WARNING_SITES, warning)

    def test_the_category_tokens_inside_functions_still_agree(self):
        """The master proof erases string constants, so the dispatch chain of
        `extract_archive` -- `if category == "plain_gzip"` and its eight
        siblings -- would survive a mistranslation. This closes that hole."""
        known = set(ENUM_VALUES) | set(transported.CATEGORY_BY_EXT.values())

        def tokens(tree, reverse):
            found = set()
            for sub in ast.walk(tree):
                if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                    value = reverse.get(sub.value, sub.value)
                    if value in known:
                        found.add(value)
            return found

        self.assertEqual(tokens(self.original_tree, {}),
                         tokens(self.transported_tree, REVERSE_ENUM))


# --- AC-10: equivalence demonstrated by running both chains ------------------

def _zip_fixture(path: Path, entries: dict) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return path


def _tar_gz_fixture(path: Path, entries: dict) -> Path:
    with tarfile.open(path, "w:gz") as archive:
        for name, content in entries.items():
            payload = content.encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    return path


def _zstd_fixture(path: Path) -> Path:
    """Recognised by magic number, and refused out loud."""
    path.write_bytes(b"\x28\xb5\x2f\xfd" + b"\x00" * 32)
    return path


def _filter_refused_tar(path: Path) -> tuple[Path, str]:
    """A tar the security filter refuses and that the original DID extract.

    An absolute member path will not do: the original's own zip-slip guard
    already rejects it, so the case would prove nothing about the filter. What
    the guard lets through and the filter does not is a SYMLINK whose TARGET
    escapes the destination -- the guard only ever looks at the member's own
    name, never at where a link points.

    Where symbolic links cannot be created (Windows without the privilege), the
    bench falls back to a special file, which the original silently skips and
    the filter refuses out loud. The case actually used is returned so the test
    can say which divergence it measured.
    """
    with tarfile.open(path, "w") as archive:
        info = tarfile.TarInfo("link")
        info.type = tarfile.SYMTYPE
        info.linkname = "../../outside"
        archive.addfile(info)
    probe = path.parent / "_symlink_probe"
    try:
        os.symlink(path, probe)
        probe.unlink()
        return path, "symlink escaping the destination"
    except (OSError, NotImplementedError):
        with tarfile.open(path, "w") as archive:
            info = tarfile.TarInfo("pipe")
            info.type = tarfile.FIFOTYPE
            archive.addfile(info)
        return path, "special file"


LEVEL_BY_PREFIX = {"[INFO]": "INFO", "[AVERTISSEMENT]": "WARNING"}

# Suffixes of the extraction directory and of the decompressed file. They are
# TRANSLATED, and nothing more -- naming the extracted tree properly is later
# work. The bench normalises them so that a translated suffix does not read as a
# behavioural divergence; every other component of every path is compared
# literally.
TRANSLATED_SUFFIXES = {"_extrait": "_extracted", "_decompresse": "_decompressed"}


class _RecordCollector(logging.Handler):
    """Captures package records, including the case of NO record at all.

    `assertLogs` cannot be used here: it fails when nothing is logged, and one
    of the six fixtures -- the Zstandard archive, refused by exception before
    any record -- legitimately logs nothing. A capture that cannot express
    "zero events" cannot compare "zero events" on both sides.
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


def _level_of(line: str) -> str:
    for prefix, level in LEVEL_BY_PREFIX.items():
        if line.startswith(prefix):
            return level
    raise AssertionError(f"upstream line carries no level prefix: {line!r}")


class TestBehaviouralEquivalence(_TransportFixture):
    """Same tree, same names, same exceptions, same events in the same order."""

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.original_namespace = {}
        exec(compile(SYNTHESISED_HEADER + cls.original_source,
                     "<upstream-slice>", "exec"), cls.original_namespace)

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="unboxr_equivalence_"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _fixtures(self) -> list[Path]:
        made = self.tmp / "fixtures"
        made.mkdir()
        plain_zip = _zip_fixture(made / "plain.zip", {"a/one.txt": "one"})
        tgz = _tar_gz_fixture(made / "plain.tar.gz", {"b/two.txt": "two"})

        inner = _tar_gz_fixture(made / "_inner.tar.gz", {"deep/three.txt": "three"})
        nested = _zip_fixture(made / "nested.zip",
                              {"outer/note.txt": "note",
                               "outer/inner.tar.gz": inner.read_bytes()})
        inner.unlink()

        bare = _zip_fixture(made / ".zip", {"bare/four.txt": "four"})

        # An archive whose name is a BARE extension, carried INSIDE another
        # one, so that flattening meets it in the tree. AC-10 asks for the
        # fallback naming to be compared, and until 9 September 2026 nothing
        # reached it: `.zip` above is handed straight to `extract_archive`,
        # which never consults `_deterministic_fallback_name` -- only
        # `flatten_nested_archives` does. Instrumenting the function showed it
        # was called ZERO times by the whole bench.
        inner_bare = _tar_gz_fixture(made / "_bare_inner.tar.gz",
                                     {"fell/five.txt": "five"})
        carrier = _zip_fixture(made / "carrier.zip",
                               {"holder/.tar.gz": inner_bare.read_bytes()})
        inner_bare.unlink()

        zstd = _zstd_fixture(made / "payload.tar.zst")
        return [plain_zip, tgz, nested, bare, carrier, zstd]

    def _run_both(self, archive: Path):
        """Returns (original_outcome, transported_outcome).

        An outcome is (relative tree listing, [(level, args)], exception name).
        """
        original_root = self.tmp / "orig" / archive.name
        moved_root = self.tmp / "moved" / archive.name
        original_root.mkdir(parents=True)
        moved_root.mkdir(parents=True)

        buffer = io.StringIO()
        original_error = None
        with redirect_stdout(buffer):
            try:
                self.original_namespace["extraire_archive"](archive, original_root)
                self.original_namespace["aplatir_archives_imbriquees"](original_root)
            except Exception as exc:
                original_error = exc.__class__.__name__
        original_lines = [line for line in buffer.getvalue().splitlines() if line]

        moved_error = None
        with _RecordCollector() as captured:
            try:
                transported.extract_archive(archive, moved_root)
                transported.flatten_nested_archives(moved_root)
            except Exception as exc:
                moved_error = exc.__class__.__name__

        return (
            (_listing(original_root, translate_suffixes=True),
             original_lines, original_error),
            (_listing(moved_root), captured.records, moved_error),
        )

    def test_the_six_fixtures_produce_the_same_tree_and_the_same_events(self):
        for archive in self._fixtures():
            with self.subTest(archive=archive.name):
                (tree_a, lines, error_a), (tree_b, records, error_b) = \
                    self._run_both(archive)

                self.assertEqual(tree_a, tree_b,
                                 "same extracted tree, extraction directory "
                                 "names and digests included")
                self.assertEqual(error_a, error_b, "same exception type")

                self.assertEqual(len(lines), len(records),
                                 f"same number of events\nupstream={lines}\n"
                                 f"transported={[r.getMessage() for r in records]}")
                for line, record in zip(lines, records):
                    self.assertEqual(_level_of(line), record.levelname)
                    for arg in record.args or ():
                        if isinstance(arg, BaseException):
                            # Its message is translated by design; the TYPE is
                            # compared through `error_a`/`error_b` above and by
                            # the exception-type test.
                            continue
                        needle = REVERSE_ENUM.get(str(arg), str(arg))
                        self.assertIn(needle, line,
                                      "the interpolated data differs")

    def test_the_declared_divergence_of_the_tar_filter_is_announced(self):
        """The one divergence AC-10 expects: the filter refuses archives the
        original extracted. A bench that hid it would not satisfy AC-10."""
        archive, case = _filter_refused_tar(self.tmp / "refused.tar")
        original_root = self.tmp / "orig_filter"
        moved_root = self.tmp / "moved_filter"

        original_error = None
        with redirect_stdout(io.StringIO()):
            try:
                self.original_namespace["extraire_archive"](archive, original_root)
            except Exception as exc:
                original_error = exc.__class__.__name__
        self.assertIsNone(original_error,
                          f"the original accepted this archive ({case})")

        with _RecordCollector() as captured:
            with self.assertRaises(tarfile.FilterError):
                transported.extract_archive(archive, moved_root)
        self.assertTrue(
            any("refused by the security filter" in record.getMessage()
                for record in captured.records),
            f"the refusal must be DECLARED, not silent ({case})")
        self.assertEqual([], _listing(moved_root),
                         "the filter refuses the archive, not one member")

    # --- The repairs of 8 and 9 September, exercised by RUNNING them ---------
    #
    # Until 9 September 2026 not one of them was: the fixtures never call
    # `download_source`, never provoke a collision, never fail an `unlink` and
    # never populate the ledger. Every family was held by AST pinning alone --
    # which proves the code is what the declaration says, and nothing about
    # what it DOES. These tests close that gap. Where the repair is a declared
    # divergence, the upstream side is run too, and the difference is asserted
    # rather than hidden.

    def _flatten_both(self, build) -> tuple:
        """Build the same tree twice and flatten it with both chains."""
        upstream_root = self.tmp / "flat_orig"
        moved_root = self.tmp / "flat_moved"
        upstream_root.mkdir(parents=True)
        moved_root.mkdir(parents=True)
        # The suffix is passed in, and it is NOT decoration: the extraction
        # directory is `_extrait` upstream and `_extracted` here, so a fixture
        # meant to occupy that name has to spell it per side. Building the same
        # literal name on both obstructs only one of the two, and the resulting
        # comparison measures nothing -- caught on 9 September 2026.
        build(upstream_root, "_extrait")
        build(moved_root, "_extracted")

        buffer = io.StringIO()
        upstream_error = None
        with redirect_stdout(buffer):
            try:
                self.original_namespace["aplatir_archives_imbriquees"](upstream_root)
            except Exception as exc:
                upstream_error = exc.__class__.__name__
        moved_error = None
        with _RecordCollector() as captured:
            try:
                transported.flatten_nested_archives(moved_root)
            except Exception as exc:
                moved_error = exc.__class__.__name__
        return ((_listing(upstream_root, translate_suffixes=True),
                 [line for line in buffer.getvalue().splitlines() if line],
                 upstream_error),
                (_listing(moved_root), captured.records, moved_error))

    def test_a_tar_extracted_twice_merges_instead_of_nesting(self):
        """Repair of family 6, and the defect that repair introduced.

        `extractall(dest)` merges into an existing directory. Staging plus
        `shutil.move` did NOT: it moved the directory INSIDE the one already
        there, so a second extraction produced `x/x/one.txt` and a third
        raised. Measured on 9 September 2026; upstream is the reference.
        """
        # THREE archives sharing one top-level directory and carrying
        # DIFFERENT members. Extracting the same content twice cannot tell a
        # merge from a replacement -- both end with the same listing -- and a
        # test that cannot tell them apart proves nothing. Each of the three
        # outcomes is now distinguishable: merging keeps all three files,
        # replacing keeps one, nesting builds `x/x/`.
        archives = [
            _tar_gz_fixture(self.tmp / f"twice_{index}.tar.gz",
                            {f"x/{name}.txt": name})
            for index, name in enumerate(("one", "two", "three"))
        ]
        upstream_dest = self.tmp / "twice_orig"
        moved_dest = self.tmp / "twice_moved"
        for archive in archives:
            with redirect_stdout(io.StringIO()):
                self.original_namespace["extraire_archive"](archive, upstream_dest)
            with _RecordCollector():
                transported.extract_archive(archive, moved_dest)
        self.assertEqual(
            ["x/", "x/one.txt", "x/three.txt", "x/two.txt"],
            [entry.split(" sha256:")[0] for entry in _listing(moved_dest)],
            "all three members must be there: one missing means the move "
            "replaced instead of merging, and an `x/x` means it nested")
        self.assertEqual(_listing(upstream_dest, translate_suffixes=True),
                         _listing(moved_dest),
                         "extracting the same tar three times into the same "
                         "destination must merge, exactly as upstream does")

    def test_a_destination_that_is_a_plain_file_does_not_abort_flattening(self):
        """Repair of family 9 (e).

        `any(sub_dest.iterdir())` sat before the `try`, so a plain FILE bearing
        the destination's name raised `NotADirectoryError` through
        `flatten_nested_archives` and left every remaining archive unopened
        without a single record. The upstream chain degraded properly; this
        asserts the transported one does again.
        """
        payload = _zip_fixture(self.tmp / "_seed.zip", {"in/six.txt": "six"})
        blob = payload.read_bytes()
        payload.unlink()

        def build(root, suffix):
            (root / "a.zip").write_bytes(blob)
            (root / f"a{suffix}").write_text("I am a file, not a directory")
            (root / "b.zip").write_bytes(blob)

        upstream_side, moved_side = self._flatten_both(build)
        upstream_lines, upstream_error = upstream_side[1], upstream_side[2]
        moved_tree, records, moved_error = moved_side
        self.assertIsNone(upstream_error)
        self.assertIsNone(moved_error,
                          "the collision CHECK must never be what amputates "
                          "the corpus")
        self.assertIn("b_extracted/", moved_tree,
                      "the archive AFTER the bad destination must still have "
                      "been opened")
        messages = [record.getMessage() for record in records]
        self.assertEqual(
            1, sum("failed" in m for m in messages),
            f"the obstructed archive is announced ONCE: {messages}")
        self.assertEqual(
            1, sum("left unopened" in m for m in messages),
            "and it IS an amputation, so the closing recap names it")
        # DECLARED divergence, asserted rather than hidden: upstream has no
        # ledger, so it re-discovers the same obstructed archive at every level
        # and ends on the maximum-depth warning, blaming nesting for what is
        # one archive that never opened.
        self.assertGreater(len(upstream_lines), len(records))
        self.assertTrue(any("Profondeur maximale" in line
                            for line in upstream_lines))

    def test_an_archive_whose_removal_fails_is_not_re_extracted(self):
        """Repair of family 9 (d) -- a DECLARED divergence, so it is compared.

        A successful extraction whose `unlink` fails leaves the archive on
        disk. Without the ledger it was re-discovered and re-extracted at every
        level, up to the maximum depth, ending on a warning that blamed nesting
        and claimed the content was NOT in the tree -- while it was. The
        upstream chain, which has no ledger, still does exactly that: the
        difference IS the repair.
        """
        payload = _zip_fixture(self.tmp / "_seed2.zip", {"in/seven.txt": "seven"})
        blob = payload.read_bytes()
        payload.unlink()

        def build(root, suffix):
            (root / "locked.zip").write_bytes(blob)

        real_unlink = Path.unlink

        def refusing_unlink(self, *args, **kwargs):
            if self.name == "locked.zip":
                raise OSError("held open by another process")
            return real_unlink(self, *args, **kwargs)

        Path.unlink = refusing_unlink
        try:
            upstream_side, moved_side = self._flatten_both(build)
        finally:
            Path.unlink = real_unlink
        upstream_lines = upstream_side[1]
        moved_tree, records = moved_side[0], moved_side[1]

        messages = [record.getMessage() for record in records]
        self.assertEqual(
            1, sum("could not be removed" in m for m in messages),
            f"the archive must be reported ONCE, not once per level: {messages}")
        self.assertEqual(
            [], [m for m in messages if "Maximum depth" in m],
            "the run stops because there is nothing left to open, not because "
            "it ran out of levels")
        self.assertEqual(
            [], [m for m in messages if "left unopened" in m],
            "its content IS in the extracted tree, so it is not an amputation "
            "and the recap must not name it")
        self.assertIn("locked_extracted/", moved_tree,
                      "the content must be there all the same")
        self.assertGreater(
            len(upstream_lines), len(records),
            "the upstream chain has no ledger and still repeats itself; this "
            "divergence is the repair, and it is declared")

    def test_the_closing_recap_names_only_what_is_really_missing(self):
        """Repair of family 10.

        The loop leaves by the 'finished' branch, so a run that had amputated
        the corpus ended on an unqualified success. The recap reads
        `amputated_archives` and never `attempted_archives`.
        """
        inner = _zstd_fixture(self.tmp / "_inner.tar.zst")
        blob = inner.read_bytes()
        inner.unlink()

        def build(root, suffix):
            (root / "payload.tar.zst").write_bytes(blob)

        moved_side = self._flatten_both(build)[1]
        records, moved_error = moved_side[1], moved_side[2]
        self.assertIsNone(moved_error)
        messages = [record.getMessage() for record in records]
        recap = [m for m in messages if "left unopened" in m]
        self.assertEqual(1, len(recap), messages)
        self.assertIn("payload.tar.zst", recap[0])
        self.assertEqual(
            "WARNING",
            [r.levelname for r in records if "left unopened" in r.getMessage()][0],
            "an amputated corpus is not an informational record")

    def test_a_download_destination_that_is_a_file_is_reported_as_such(self):
        """Repair of family 4.

        `mkdir(exist_ok=True)` absorbs FileExistsError only for a DIRECTORY.
        Placed outside any guard, a destination existing as a plain file raised
        a bare `FileExistsError`, escaping the `RuntimeError` contract this
        function's docstring and message present as its only failure mode.
        """
        occupied = self.tmp / "not_a_directory"
        occupied.write_text("in the way")
        with _RecordCollector():
            with self.assertRaises(RuntimeError) as raised:
                transported.download_source("https://example.invalid/a.zip",
                                            occupied)
        self.assertIn("could not be prepared", str(raised.exception))
        self.assertNotIn("Check network connectivity", str(raised.exception),
                         "a destination that cannot be prepared is not a "
                         "network failure, and must not be reported as one")

    def test_prepare_source_agrees_on_nature_and_digest(self):
        archive = _zip_fixture(self.tmp / "pkg-1.0.whl", {"m/__init__.py": ""})
        with redirect_stdout(io.StringIO()):
            tree_a, nature_a, digest_a = self.original_namespace["preparer_source"](
                str(archive))
        with _RecordCollector():
            tree_b, nature_b, digest_b = transported.prepare_source(
                str(archive), workspace=self.tmp / "ws")
        self.assertEqual(digest_a, digest_b)
        self.assertEqual(REVERSE_ENUM.get(nature_b, nature_b), nature_a)
        self.assertEqual(_listing(tree_a, translate_suffixes=True),
                         _listing(tree_b))


def _listing(root: Path, translate_suffixes: bool = False) -> list[str]:
    """Relative POSIX paths AND the digest of every file.

    The digest is not decoration. Until 9 September 2026 this returned paths
    only, while the assertion that consumes it said "extraction directory names
    and digests included": two trees carrying the same names and DIFFERENT
    content compared equal, so the bench could not have seen an extraction that
    produced empty or truncated files.

    An unreadable entry is reported as such rather than skipped -- a listing
    that quietly drops what it cannot read would compare two absences.
    """
    if not root.exists():
        return []
    entries = []
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if translate_suffixes:
            for french, english in TRANSLATED_SUFFIXES.items():
                relative = relative.replace(french, english)
        if path.is_dir():
            entries.append(relative + "/")
            continue
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            digest = f"<unreadable: {exc.__class__.__name__}>"
        entries.append(f"{relative} sha256:{digest}")
    entries.sort()
    return entries


if __name__ == "__main__":
    unittest.main()
