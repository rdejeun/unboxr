"""The document that says what came out of the extraction, and what did not.

WHY A DOCUMENT AT ALL. The report of `unboxr.report` is a Python object: it
lives as long as the process does. An analyst who has to prove, months later,
which files a downstream conclusion rested on has nothing to open. This module
projects that report, and the tree it goes with, onto a CycloneDX 1.7 document
that outlives the run.

WHAT IT PROVES, AND WHAT IT DOES NOT. It attests the presence and the SHA-256
digest of what it lists. It says nothing whatsoever about what is absent from
it -- the oracle is positive only, here as everywhere else in this package --
and it renders no verdict of any kind.

WHERE THE DIGESTS COME FROM, AND WHY IT IS TWO PLACES. A container that is
OPENED is destroyed by the flattening: the window in which it still exists is
the only one in which it can be hashed, so its digest is taken DURING the
extraction. An ordinary extracted file is still there at the end, and is hashed
by walking the finished tree. The dividing line is the survival of the object,
not convenience.

100% offline, standard library only: no network, no 7-Zip binary, no versioned
fixture. Schema validation is a DELIVERY gesture, run against the official
schema outside this suite -- `jsonschema` is a third-party package and a
boundary guard forbids importing one here.
"""

from __future__ import annotations

import hashlib
import io
import json
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import unboxr.extraction as ux  # noqa: E402
import unboxr.sbom as sb  # noqa: E402
from unboxr import report as rp  # noqa: E402

ZSTD_MAGIC = bytes([0x28, 0xB5, 0x2F, 0xFD])


class _Bench(unittest.TestCase):
    """Builds its own fixtures: no binary is versioned in this repository."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="test_sbom_"))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    def _zip_bytes(self, members) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for arcname, content in members:
                archive.writestr(arcname, content)
        return buffer.getvalue()

    def _zip_at(self, path: Path, members=(("code/aes.c", "int a;"),)) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self._zip_bytes(members))
        return path

    def _tree(self) -> Path:
        root = self.dir / "tree"
        root.mkdir()
        return root

    def _digest_of(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def _entries(self, report):
        return (list(report.opened) + list(report.not_opened)
                + list(report.still_in_tree) + list(report.widened)
                + list(report.not_attested))

    def _properties_of(self, component) -> dict:
        """The properties of a component, which may have none.

        `.get`, NOT `[...]`: a component to which nothing abnormal happened
        carries no `properties` key at all, and that is the ordinary case. A helper that raised there would make every
        test of a clean extraction fail for the wrong reason.
        """
        return {p["name"]: p["value"]
                for p in component.get("properties", [])}

    def _anomalies_of(self, component) -> list:
        """The anomaly codes on a component, in order, or an empty list.

        EMPTY IS THE STATEMENT "nothing abnormal happened to this path", not
        "we did not look": the document promises every anomaly it can observe.
        """
        code = self._properties_of(component).get(sb.ANOMALY_CODE)
        return [] if code is None else code.split(", ")

    def _components(self, document, name: str):
        """Every component of that name. There can be more than
        one: a bare name and a tree-relative path may be the same string and
        name two different files."""
        return [c for c in document["components"] if c["name"] == name]

    def _component(self, document, name: str):
        found = [c for c in document["components"] if c["name"] == name]
        self.assertEqual(1, len(found), "expected exactly one component " + name)
        return found[0]

    def _document_of(self, archive: Path, workspace=None):
        workspace = workspace or self.dir / "w"
        prepared = ux.prepare_source(str(archive), workspace=workspace)
        return prepared, sb.build_document(
            prepared.report, prepared.tree, source=str(archive),
            source_digest=prepared.digest)

    def _entry(self, report, code: str):
        found = [e for e in self._entries(report) if e.code == code]
        self.assertEqual(1, len(found), "expected exactly one " + code + " entry")
        return found[0]


# ---------------------------------------------------------------------------
# The report learns to carry a digest, and the frame its path was computed in
# ---------------------------------------------------------------------------
class TestTheReportCarriesADigest(_Bench):

    def test_a_record_carries_no_digest_unless_one_is_given(self):
        """Three states, never two. `None` is "not computed here", and it is
        the default: a field that defaulted to anything else would make every
        call site that has nothing to hash assert something."""
        held = ux.new_report()
        held.record(rp.NESTED_CONTAINER_OPENED, "a.zip")
        self.assertIsNone(held.opened[0].digest)

    def test_a_record_keeps_the_bare_hexadecimal_digest_it_is_given(self):
        """BARE, never prefixed: the schema's own pattern for a hash value
        admits hexadecimal and nothing else, so a `sha256:` prefix -- which a
        consumer of this package writes elsewhere -- would be refused by the
        validator. Read from the schema on 13 September 2026:
        `definitions.hash-content.pattern`."""
        digest = self._digest_of(b"payload")
        held = ux.new_report()
        held.record(rp.NESTED_CONTAINER_OPENED, "a.zip", digest=digest)
        self.assertEqual(digest, held.opened[0].digest)
        self.assertEqual(64, len(held.opened[0].digest))

    def test_a_record_says_whether_its_path_is_relative_to_the_tree(self):
        """The frame is MARKED where it is known and never guessed afterwards.

        `_reportable_path` is the one place that knows whether it returned a
        path relative to a root or a bare file name, and it forgot which on the
        way out. A cause code cannot be used to recover it: four call sites
        pass `location or <path>`, and the SAME code yields a relative path
        when a location was threaded and a bare name when it was not.
        """
        root = self._tree()
        inside = root / "a" / "b.zip"
        outside = self.dir / "elsewhere" / "b.zip"
        self.assertEqual(("a/b.zip", rp.PATH_IS_TREE_RELATIVE),
                         ux._reportable_path_and_frame(inside, root))
        self.assertEqual(("b.zip", rp.PATH_IS_BARE_NAME),
                         ux._reportable_path_and_frame(outside, root))
        self.assertEqual(("b.zip", rp.PATH_IS_BARE_NAME),
                         ux._reportable_path_and_frame(outside, None))

    def test_a_path_given_as_a_string_has_an_unknown_frame(self):
        """A caller who hands over a string has already computed the path, and
        this package cannot tell what it was computed against. `unknown` is a
        third state and it leans the safe way: it excludes nothing."""
        self.assertEqual(("a/b.zip", rp.PATH_FRAME_UNKNOWN),
                         ux._reportable_path_and_frame("a/b.zip", self._tree()))

    def test_the_single_argument_form_is_still_the_path_alone(self):
        """`_reportable_path` keeps its signature and its return type: it is
        used as a sort key and as a `location`, and both want a string."""
        root = self._tree()
        self.assertEqual("a/b.zip",
                         ux._reportable_path(root / "a" / "b.zip", root))


class TestTheChainFillsInTheDigests(_Bench):

    def test_a_container_destroyed_by_the_flattening_keeps_its_four_facts(self):
        """The one property no walk of the finished tree could ever produce.

        `outer.zip/inner.zip` is opened and REMOVED: at the end of the run the
        file does not exist. Its digest, its path relative to the tree, the
        level it was met at and its parent are all in the report -- the four
        the document needs -- and the digest is the one taken while the file
        was still there.
        """
        root = self._tree()
        inner = self._zip_bytes([("code/aes.c", "int a;")])
        self._zip_at(root / "outer.zip", [("inner.zip", inner)])
        expected = self._digest_of(inner)
        held = ux.new_report()

        ux.flatten_nested_archives(root, report=held)

        self.assertFalse((root / "outer.zip" / "inner.zip").is_file(),
                         "if the archive were still a file, a walk of the tree "
                         "could have produced this record and the test would "
                         "prove nothing")
        entries = [e for e in held.opened
                   if e.code == rp.NESTED_CONTAINER_OPENED
                   and e.path == "outer.zip/inner.zip"]
        self.assertEqual(1, len(entries))
        entry = entries[0]
        self.assertEqual(expected, entry.digest)
        self.assertEqual(2, entry.level)
        self.assertEqual(rp.PATH_IS_TREE_RELATIVE, entry.path_frame)

    def test_the_container_given_as_the_source_reuses_the_digest_already_taken(self):
        """`prepare_source` hashes the received input at the one point both
        origins converge. Hashing it a second time to file the record would
        read the same bytes twice for one value."""
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        expected = self._digest_of(archive.read_bytes())

        prepared = ux.prepare_source(str(archive), workspace=self.dir / "w")

        self.assertEqual(expected, prepared.digest)
        entry = self._entry(prepared.report, rp.INPUT_CONTAINER_OPENED)
        self.assertEqual(expected, entry.digest)

    def test_a_recorded_path_that_is_not_a_file_carries_no_digest(self):
        """`destination_already_occupied` names a DIRECTORY. There is nothing
        to hash, and fabricating a digest of a tree walk would attest something
        else entirely."""
        destination = self.dir / "w"
        (destination / "p.zip").mkdir(parents=True)
        (destination / "p.zip" / "left-over.txt").write_text("x")
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])

        prepared = ux.prepare_source(str(archive), workspace=destination)

        entry = self._entry(prepared.report, rp.DESTINATION_ALREADY_OCCUPIED)
        self.assertIsNone(entry.digest)

    def test_a_digest_that_cannot_be_read_never_escapes_the_recording(self):
        """A guard must never be the thing that shortens the corpus. A read
        failure while filing a record leaves the digest at `None`; it does not
        abort the flattening and lose every remaining archive with it."""
        root = self._tree()
        self._zip_at(root / "first.zip")
        self._zip_at(root / "second.zip")
        held = ux.new_report()

        def _explode(path):
            raise OSError("the disk fights back")

        original = ux._sha256_digest_of_file
        ux._sha256_digest_of_file = _explode
        try:
            ux.flatten_nested_archives(root, report=held)
        finally:
            ux._sha256_digest_of_file = original

        self.assertTrue((root / "first.zip" / "code" / "aes.c").is_file())
        self.assertTrue((root / "second.zip" / "code" / "aes.c").is_file())
        self.assertEqual(2, len(held.opened))
        for entry in held.opened:
            with self.subTest(path=entry.path):
                self.assertIsNone(entry.digest)

    def test_a_cause_filed_twice_keeps_the_digest_of_the_first_filing(self):
        """The identity of an entry is the pair (code, path) and the FIRST
        filing wins. Three codes are filed twice by the chain: a digest added
        only at the outer site would be dropped in silence by the
        deduplication, never to be seen again."""
        digest = self._digest_of(b"payload")
        held = ux.new_report()
        held.record(rp.TAR_CONTENT_PARTLY_MOVED, "a.tar", digest=digest)
        held.record(rp.TAR_CONTENT_PARTLY_MOVED, "a.tar")
        self.assertEqual(1, len(held.not_opened))
        self.assertEqual(digest, held.not_opened[0].digest)


# ---------------------------------------------------------------------------
# The skeleton, and what it makes possible later
# ---------------------------------------------------------------------------
class TestTheSkeletonOfTheDocument(_Bench):

    def test_the_document_declares_the_format_and_the_specification_version(self):
        """The two fields the schema actually requires. Everything else could
        be left out and still validate, which is exactly why the rest of this
        class exists: validation is a floor, not a specification."""
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        _, document = self._document_of(archive)
        self.assertEqual("CycloneDX", document["bomFormat"])
        self.assertEqual("1.7", document["specVersion"])

    def test_the_document_is_addressable_by_a_link_from_another_document(self):
        """A BOM-Link has the shape `urn:cdx:<uuid>/<version>`. Neither piece
        is decoration: a document without them validates perfectly and cannot
        be pointed at, which would have to be undone later."""
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        _, document = self._document_of(archive)
        self.assertEqual(1, document["version"])
        self.assertRegex(
            document["serialNumber"],
            r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

    def test_the_document_names_the_tool_that_produced_it_and_its_version(self):
        """Which formats could be opened, and what the presence of a 7-Zip
        binary changed, both depend on the version. A document silent on its
        producer cannot be diagnosed when two corpora diverge."""
        import unboxr
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        _, document = self._document_of(archive)
        tool = document["metadata"]["tools"]["components"][0]
        self.assertEqual("unboxr", tool["name"])
        self.assertEqual(unboxr.__version__, tool["version"])

    def test_the_document_says_what_it_is_the_document_of(self):
        """Without it, a list of thousands of files never names its subject and
        two documents can only be compared by their contents."""
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        prepared, document = self._document_of(archive)
        subject = document["metadata"]["component"]
        self.assertEqual("p.zip", subject["name"])
        self.assertEqual(prepared.digest, subject["hashes"][0]["content"])
        self.assertEqual([], self._anomalies_of(subject))

    def test_the_subject_of_a_directory_run_has_its_missing_digest_written(self):
        """A directory is not a single file and has nothing to hash. The
        absence is WRITTEN; it is never replaced by a value, and never left to
        be inferred from a missing field."""
        source = self.dir / "given"
        (source / "pkg").mkdir(parents=True)
        (source / "pkg" / "a.txt").write_text("a")
        prepared = ux.prepare_source(str(source))

        document = sb.build_document(prepared.report, prepared.tree,
                                     source=str(source),
                                     source_digest=prepared.digest)

        subject = document["metadata"]["component"]
        self.assertNotIn("hashes", subject)
        # SAID BY THE TYPE, the one reading the schema already provides.
        self.assertEqual(sb.TYPE_NOT_A_FILE, subject["type"])
        self.assertEqual([], self._anomalies_of(subject))

    def test_no_absolute_path_and_no_temporary_directory_name_gets_in(self):
        """This document is meant to be compared between machines. An absolute
        path, or the name of a temporary workspace, would make two runs of the
        same archive differ for a reason that has nothing to do with the
        corpus."""
        archive = self._zip_at(self.dir / "deep" / "p.zip", [("a.txt", "a")])
        _, document = self._document_of(archive)
        text = sb.serialise(document)
        self.assertNotIn(str(self.dir), text)
        self.assertNotIn(self.dir.as_posix(), text)
        self.assertNotIn("test_sbom_", text)


# ---------------------------------------------------------------------------
# Every file, and "every" includes what the flattening destroyed
# ---------------------------------------------------------------------------
class TestEveryFileCarriesItsDigest(_Bench):

    def test_every_file_left_in_the_tree_is_a_component_with_its_digest(self):
        """No exception of extension, of size or of location: the decision to
        hash everything was taken in knowledge of its cost, not in ignorance
        of it."""
        payload = b"some bytes"
        archive = self._zip_at(self.dir / "p.zip", [
            ("src/a.txt", payload), ("src/deep/b.bin", payload),
            ("README", payload)])

        _, document = self._document_of(archive)

        for name in ("src/a.txt", "src/deep/b.bin", "README"):
            with self.subTest(name=name):
                component = self._component(document, name)
                self.assertEqual(sb.TYPE_FILE, component["type"])
                self.assertEqual([{"alg": "SHA-256",
                                   "content": self._digest_of(payload)}],
                                 component["hashes"])

    def test_a_digest_is_bare_hexadecimal_and_never_carries_a_prefix(self):
        """The schema pattern for a hash value accepts hexadecimal of five
        fixed lengths and nothing else. The prefix a consumer of this package
        writes elsewhere is added by that consumer, never here.

        THE CASING, one of the four points the spike left open,
        RE-CHECKED against the schema on 13 September 2026:
        `definitions.hash-alg.enum` contains `SHA-256`, spelled with that
        exact casing and hyphen -- `sha256`, `Sha-256` and `SHA256` are all
        absent from the enumeration."""
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        _, document = self._document_of(archive)
        for component in document["components"]:
            for entry in component.get("hashes", []):
                with self.subTest(name=component["name"]):
                    self.assertRegex(entry["content"], r"^[0-9a-f]{64}$")
                    self.assertEqual("SHA-256", entry["alg"])

    def test_a_container_the_flattening_destroyed_is_still_in_the_document(self):
        """THE PROPERTY THE DIVISION OF LABOUR EXISTS FOR. `vendor/inner.zip`
        does not exist when the run ends: only a digest taken during the
        extraction can put it here, with its path, its level and its parent."""
        inner = self._zip_bytes([("code/aes.c", "int a;")])
        archive = self._zip_at(self.dir / "p.zip", [("vendor/inner.zip", inner)])

        prepared, document = self._document_of(archive)

        self.assertFalse((prepared.tree / "vendor" / "inner.zip").is_file())
        component = self._component(document, "vendor/inner.zip")
        self.assertEqual(self._digest_of(inner), component["hashes"][0]["content"])
        # OPENING IT IS NOT AN ANOMALY, so the component carries no property
        # at all -- but it is HERE, with the digest taken during the run. That
        # is the whole point of the division of labour: no walk of the finished
        # tree could ever produce this component.
        self.assertNotIn("properties", component)

    def test_a_container_nested_two_deep_names_the_container_it_came_out_of(self):
        """The parent is read off the path, which works because a nested
        archive is flattened into a directory carrying its own name verbatim.
        It is matched against what was actually opened, never guessed from a
        list of extensions."""
        deepest = self._zip_bytes([("code/aes.c", "int a;")])
        middle = self._zip_bytes([("inner.zip", deepest)])
        archive = self._zip_at(self.dir / "p.zip", [("outer.zip", middle)])

        _, document = self._document_of(archive)

        # READ OFF THE PATH, which is why the two properties that used to
        # say it were removed: a nested archive is flattened into a directory
        # carrying its own name verbatim, so the path STATES its ancestry, and
        # each container it names is itself a component of this document.
        component = self._component(document, "outer.zip/inner.zip")
        self.assertNotIn("properties", component)
        names = {c["name"] for c in document["components"]}
        self.assertIn("outer.zip", names)
        self.assertIn("outer.zip/inner.zip/code/aes.c", names)
        for container in ("outer.zip", "outer.zip/inner.zip"):
            self.assertTrue(
                any(n.startswith(container + "/") for n in names),
                "the container has content under it, so it is a boundary a "
                "consumer can find by matching prefixes")

    def test_an_empty_file_is_inventoried_with_the_digest_of_no_bytes(self):
        """Not a theoretical case: a plain decompression that fails leaves an
        EMPTY file in the tree. Inventorying it is not fixing it -- the defect
        is recorded as a debt of its own -- but a document that skipped it
        would hide an artefact of failure."""
        archive = self._zip_at(self.dir / "p.zip", [("empty.txt", b"")])
        _, document = self._document_of(archive)
        component = self._component(document, "empty.txt")
        self.assertEqual(self._digest_of(b""), component["hashes"][0]["content"])
        self.assertEqual([], self._anomalies_of(component))

    def test_a_file_that_cannot_be_read_is_inscribed_named_and_counted(self):
        """A broken link, a refused permission, a file removed between the
        listing and the read are ORDINARY events in a walk of a real tree --
        unlike the input archive, whose read failure is an anomaly and
        propagates. Such a file is inscribed WITH ITS STATE NAMED, never
        omitted, and their number is carried in `metadata` so the amputation
        can be measured."""
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        original = sb._digest_of_existing_file
        sb._digest_of_existing_file = lambda path: None
        try:
            _, document = self._document_of(archive)
        finally:
            sb._digest_of_existing_file = original

        component = self._component(document, "a.txt")
        self.assertNotIn("hashes", component)
        self.assertIn(sb.READ_FAILED, self._anomalies_of(component))

    def test_a_symbolic_link_is_inscribed_and_never_followed(self):
        """`is_file()` FOLLOWS a link: hashing one would duplicate the content
        of its target under a second path and invent an alias the tree does not
        have. The link gets a state of its own instead.

        The tree is a stub rather than a real link, and deliberately: creating
        a symbolic link needs a privilege this suite cannot assume, and this
        suite forbids skipping a test. What is under test is the DECISION --
        inscribe, do not follow -- and a stub exercises exactly that, the same
        way the absence of a 7-Zip binary is mocked here and never observed.
        """
        class _Link:
            def __init__(self, name):
                self.name = name

            def relative_to(self, other):
                return self

            def as_posix(self):
                return self.name

            def is_symlink(self):
                return True

            def is_file(self):
                raise AssertionError("a link must not be followed")

        class _Tree:
            def is_dir(self):
                return True

            def rglob(self, pattern):
                return [_Link("vendor/link-to-elsewhere")]

        found = sb._walk_the_tree(_Tree(), set())

        self.assertEqual([("vendor/link-to-elsewhere", None,
                           sb.SYMLINK_NOT_FOLLOWED)], found)

    def test_a_special_node_is_inscribed_not_silently_skipped(self):
        """A FIFO, a socket, a device node: not a directory, not a symlink,
        not a regular file. `unboxr` applies NO exclusion policy -- the walk
        used to fall through `is_file()` being false straight to the next
        path, with nothing written anywhere. Code review. A stub
        stands in for the same portability reason as the symlink above: no
        `os.mkfifo` on Windows, and this suite forbids skipping a test."""
        class _Special:
            def __init__(self, name):
                self.name = name

            def relative_to(self, other):
                return self

            def as_posix(self):
                return self.name

            def is_symlink(self):
                return False

            def is_dir(self):
                return False

            def is_file(self):
                return False

        class _Tree:
            def is_dir(self):
                return True

            def rglob(self, pattern):
                return [_Special("pipe")]

        found = sb._walk_the_tree(_Tree(), set())

        self.assertEqual([("pipe", None, sb.NOT_REGULAR_FILE)], found)

# ---------------------------------------------------------------------------
# What was NOT opened, which is the half a walk of the tree can never supply
# ---------------------------------------------------------------------------
class TestWhatWasNotOpened(_Bench):

    def test_a_container_recognised_and_refused_is_in_the_document_with_its_cause(self):
        """The heaviest amputations of all: a format this tool recognises and
        declines to open appears nowhere else. A Zstandard container is
        recognised by its first bytes and refused -- the standard library has
        no decoder before Python 3.14, and 7-Zip does not handle it either."""
        root = self._tree()
        (root / "refused.tar.zst").write_bytes(ZSTD_MAGIC + b"undecodable")
        held = ux.new_report()
        ux.flatten_nested_archives(root, report=held)

        document = sb.build_document(held, root, source="p.zip")

        component = self._component(document, "refused.tar.zst")
        properties = self._properties_of(component)
        self.assertEqual(rp.ZSTD_NOT_SUPPORTED, properties[sb.ANOMALY_CODE])
        self.assertEqual(rp.text_for(rp.ZSTD_NOT_SUPPORTED),
                         properties[sb.ANOMALY_TEXT])

    def test_a_format_needing_a_binary_this_machine_lacks_is_in_the_document(self):
        """The 7-Zip binary IS present on some machines and absent on others,
        so its absence is MOCKED here and never read off the machine the suite
        happens to run on."""
        root = self._tree()
        (root / "payload.rar").write_bytes(b"Rar!\x1a\x07\x00not really")
        held = ux.new_report()
        original = ux.find_7zip_binary
        ux.find_7zip_binary = lambda: None
        try:
            ux.flatten_nested_archives(root, report=held)
        finally:
            ux.find_7zip_binary = original

        document = sb.build_document(held, root, source="p.zip")

        component = self._component(document, "payload.rar")
        self.assertEqual(rp.SEVEN_ZIP_BINARY_MISSING,
                         self._properties_of(component)[sb.ANOMALY_CODE])

    def test_a_container_still_in_the_tree_is_inventoried_exactly_once(self):
        """It was never opened, so it is still a file the walk would find --
        and it is also a report entry. One component, not two: the identity of
        a component is the PATH."""
        root = self._tree()
        (root / "refused.tar.zst").write_bytes(ZSTD_MAGIC + b"undecodable")
        held = ux.new_report()
        ux.flatten_nested_archives(root, report=held)

        document = sb.build_document(held, root, source="p.zip")

        matching = [c for c in document["components"]
                    if c["name"] == "refused.tar.zst"]
        self.assertEqual(1, len(matching))
        names = [c["name"] for c in document["components"]]
        self.assertEqual(len(names), len(set(names)))

    def test_every_container_not_opened_is_a_component_of_its_own(self):
        """There is no count of the containers left closed: a reader counts
        them in one pass over the components. What must hold is one component
        per path that was not opened, each carrying its own cause."""
        root = self._tree()
        (root / "a.tar.zst").write_bytes(ZSTD_MAGIC + b"one")
        (root / "b.tar.zst").write_bytes(ZSTD_MAGIC + b"two")
        held = ux.new_report()
        ux.flatten_nested_archives(root, report=held)

        document = sb.build_document(held, root, source="p.zip")

        refused = [c for c in document["components"]
                   if rp.ZSTD_NOT_SUPPORTED in self._anomalies_of(c)]
        self.assertEqual({"a.tar.zst", "b.tar.zst"},
                         {c["name"] for c in refused})

    def test_a_cause_code_from_another_version_degrades_by_naming_itself(self):
        """A code this version does not know is not a reason to fail the
        document, and it is not "nothing to report" either. Three states."""
        held = ux.new_report()
        held.record.__func__(held, rp.NESTED_CONTAINER_OPENED, "a.zip")
        held.opened[0] = rp.ContainerRecord(
            code="a_code_from_the_future", path="a.zip",
            path_frame=rp.PATH_IS_TREE_RELATIVE)

        document = sb.build_document(held, None, source="p.zip")

        properties = self._properties_of(self._component(document, "a.zip"))
        self.assertEqual("a_code_from_the_future", properties[sb.ANOMALY_CODE])
        self.assertIn("unknown cause code", properties[sb.ANOMALY_TEXT])


# ---------------------------------------------------------------------------
# One component per PATH, never one per report entry
# ---------------------------------------------------------------------------
class TestOneComponentPerPath(_Bench):

    def test_a_path_carrying_several_anomalies_keeps_all_of_them_in_order(self):
        """None is chosen at the expense of another, and the texts follow the
        same order as the codes."""
        held = ux.new_report()
        held.record(rp.DESTINATION_ALREADY_OCCUPIED, "a.zip",
                    path_frame=rp.PATH_IS_TREE_RELATIVE)
        held.record(rp.ARCHIVE_KEPT_AFTER_SUCCESSFUL_EXTRACTION, "a.zip",
                    path_frame=rp.PATH_IS_TREE_RELATIVE)

        document = sb.build_document(held, None, source="p.zip")

        properties = self._properties_of(self._component(document, "a.zip"))
        codes = properties[sb.ANOMALY_CODE].split(", ")
        self.assertEqual([rp.DESTINATION_ALREADY_OCCUPIED,
                          rp.ARCHIVE_KEPT_AFTER_SUCCESSFUL_EXTRACTION], codes)
        self.assertEqual([rp.text_for(code) for code in codes],
                         properties[sb.ANOMALY_TEXT].split(" | "))

    def test_opening_a_container_is_not_an_anomaly_but_keeps_its_component(self):
        """THE ONE THING THAT MUST NOT BE LOST WITH THE `opened` CODES. Opening
        a container is the nominal case, so it writes no property. But a nested container is DESTROYED by the
        flattening: the instant it was recorded is the only one it could ever
        be hashed at, and no walk of the finished tree can find it again.

        Dropping the COMPONENT along with the property would therefore erase
        that digest from the only document that will ever hold it -- silently,
        and with nothing to notice it. The component stays; it simply carries
        nothing but its name and its digest, like any ordinary file."""
        held = ux.new_report()
        held.record(rp.NESTED_CONTAINER_OPENED, "vendor/inner.zip",
                    digest="a" * 64, path_frame=rp.PATH_IS_TREE_RELATIVE)

        document = sb.build_document(held, None, source="p.zip")

        component = self._component(document, "vendor/inner.zip")
        self.assertEqual([], self._anomalies_of(component))
        self.assertNotIn("properties", component)
        self.assertEqual("a" * 64, component["hashes"][0]["content"])

    def test_a_bare_name_never_removes_a_real_file_of_the_same_name(self):
        """THE COLLISION, AND WHICH WAY THE DOUBT LEANS. A record whose path is
        a bare name cannot be placed in the tree: a file whose relative path
        happens to equal it, character for character, is a DIFFERENT file.
        Dropping it from the document would be the silent amputation this
        document exists to expose, so it stays -- with its own digest."""
        root = self._tree()
        (root / "b.zip").write_bytes(b"the real file in the tree")
        held = ux.new_report()
        held.record(rp.ARCHIVE_OUTSIDE_THE_ANALYSED_ROOT, "b.zip",
                    digest=self._digest_of(b"a completely different archive"),
                    path_frame=rp.PATH_IS_BARE_NAME)

        document = sb.build_document(held, root, source="p.zip")

        # THE COMPROMISE THIS TEST USED TO STATE IS LIFTED, and the reversal is
        # deliberate. It read: "a component is identified by its path, so the
        # foreign cause lands on this one: the only two alternatives are
        # dropping the file -- the silent amputation -- and two components
        # sharing one name, which the identity rule forbids."
        #
        # The third option is the one taken now. A component is identified by
        # (path, FRAME), so the two are two components; they share a `name` and
        # differ by `bom-ref`, which is correct because they are two files.
        # "One component per path" always meant one component per THING, and
        # the frame is what says whether two strings are one thing.
        #
        # What the old compromise cost was measured in review: an archive
        # holding an entry of its own name had that entry's `extraction_failed`
        # attributed to the ARCHIVE, so the document claimed a container it had
        # just opened successfully could not be read.
        real, foreign = sorted(
            self._components(document, "b.zip"),
            key=lambda c: sb.ANOMALY_CODE in self._properties_of(c))
        self.assertEqual(self._digest_of(b"the real file in the tree"),
                         real["hashes"][0]["content"],
                         "the file that is ACTUALLY there keeps its digest")
        self.assertEqual([], self._anomalies_of(real),
                         "and it carries no cause that is not its own")
        self.assertEqual(self._digest_of(b"a completely different archive"),
                         foreign["hashes"][0]["content"],
                         "the record keeps its own digest, on its own "
                         "component")
        self.assertEqual(rp.ARCHIVE_OUTSIDE_THE_ANALYSED_ROOT,
                         self._properties_of(foreign)[sb.ANOMALY_CODE])
        self.assertNotEqual(real["bom-ref"], foreign["bom-ref"])

    def test_a_bare_name_that_collides_with_nothing_keeps_its_own_digest(self):
        """The other half of the same rule. Nothing in the tree answers to this
        name, so the record becomes a component of its own -- and its parent is
        `not_determinable`, because a bare name cannot be placed in a tree."""
        root = self._tree()
        (root / "something-else.txt").write_text("x")
        elsewhere = self._digest_of(b"an archive met outside the root")
        held = ux.new_report()
        held.record(rp.ARCHIVE_OUTSIDE_THE_ANALYSED_ROOT, "b.zip",
                    digest=elsewhere, path_frame=rp.PATH_IS_BARE_NAME)

        document = sb.build_document(held, root, source="p.zip")

        component = self._component(document, "b.zip")
        self.assertEqual(elsewhere, component["hashes"][0]["content"])
        self.assertEqual(sb.NOT_DETERMINABLE,
                         self._properties_of(component)[sb.PARENT_CONTAINER])
        self.assertEqual({"b.zip", "something-else.txt"},
                         {c["name"] for c in document["components"]})

    def test_only_a_tree_relative_record_keeps_the_walk_from_hashing_again(self):
        """THE FRAME IS WHAT DECIDES, and it decides in both directions.

        A tree-relative recorded path CAN be confronted with the tree, so the
        walk leaves it alone and the digest taken during the extraction stands.
        A bare name CANNOT: it excludes nothing, and the file that is really
        there keeps its own digest. Both halves are asserted here, in one test,
        because a mutation that dropped the frame from the rule would otherwise
        only be caught on one side of it.

        The two digests handed to the records are deliberately WRONG -- they
        are digests of other bytes entirely -- so that "the record digest was
        used" and "the file was hashed" cannot be confused.
        """
        root = self._tree()
        (root / "a.txt").write_bytes(b"the real a")
        (root / "b.txt").write_bytes(b"the real b")
        taken_during = self._digest_of(b"what a.txt held before it changed")
        from_elsewhere = self._digest_of(b"a file from outside the root")
        held = ux.new_report()
        held.record(rp.MAXIMUM_DEPTH_REACHED, "a.txt", digest=taken_during,
                    path_frame=rp.PATH_IS_TREE_RELATIVE)
        held.record(rp.ARCHIVE_OUTSIDE_THE_ANALYSED_ROOT, "b.txt",
                    digest=from_elsewhere, path_frame=rp.PATH_IS_BARE_NAME)

        document = sb.build_document(held, root, source="p.zip")

        # `b.txt` is now TWO components -- the record could not be placed in
        # the tree, so it gets its own -- and the one to look at is the file.
        real_b = [c for c in self._components(document, "b.txt")
                  if not self._anomalies_of(c)]
        self.assertEqual(1, len(real_b))
        self.assertEqual(self._digest_of(b"the real b"),
                         real_b[0]["hashes"][0]["content"],
                         "the file that is really there keeps its own digest")
        self.assertEqual(
            taken_during,
            self._component(document, "a.txt")["hashes"][0]["content"],
            "a tree-relative path is confrontable: the walk leaves it alone "
            "and the digest taken during the extraction stands")
        foreign_b = [c for c in self._components(document, "b.txt")
                     if self._anomalies_of(c)]
        self.assertEqual(1, len(foreign_b))
        self.assertEqual(
            from_elsewhere, foreign_b[0]["hashes"][0]["content"],
            "a bare name excludes nothing: the record keeps its own digest on "
            "a component of its own, and the file that is really there keeps "
            "its own on another -- two files, two components")

    def test_a_component_name_is_the_full_relative_path_not_the_base_name(self):
        """`name` is one of the two required fields of a component -- one of
        the four points the spike left open, RE-CHECKED against the
        schema on 13 September 2026: `definitions.component.required` reads
        `["type", "name"]`, exactly as first read on 12 September 2026. Two
        files called `a.txt` in two directories would be indistinguishable to
        a reader if it carried the base name."""
        archive = self._zip_at(self.dir / "p.zip",
                               [("one/a.txt", "1"), ("two/a.txt", "2")])
        _, document = self._document_of(archive)
        names = {c["name"] for c in document["components"]}
        self.assertIn("one/a.txt", names)
        self.assertIn("two/a.txt", names)

    def test_every_reference_is_unique_and_follows_the_sorted_order(self):
        """A reference is derived from the RANK, not from the path.

        THE FUTURE THIS DOCSTRING USED TO ANNOUNCE HAS BEEN SETTLED, AND THE
        OTHER WAY. A reference was to be placed after a `#` in a URN; the link
        this package now writes refuses that form outright, because a rank
        renumbers the moment a file enters or leaves the corpus and such a
        link would break at the next regeneration in silence. A reference is
        valid against THIS document and nothing else, which is exactly why
        nothing points into one.
        """
        archive = self._zip_at(self.dir / "p.zip",
                               [("b.txt", "b"), ("a.txt", "a")])
        _, document = self._document_of(archive)
        references = [c["bom-ref"] for c in document["components"]]
        self.assertEqual(len(references), len(set(references)))
        for reference in references:
            with self.subTest(reference=reference):
                self.assertFalse(reference.startswith("urn:cdx:"))
        self.assertEqual(sorted(c["name"] for c in document["components"]),
                         [c["name"] for c in document["components"]])


# ---------------------------------------------------------------------------
# The properties, and the fact that they are all always there
# ---------------------------------------------------------------------------
class TestTheProperties(_Bench):

    def test_every_property_name_is_prefixed_and_written_in_english(self):
        """The prefix names the PRODUCER. A document written by this package
        must not carry the prefix of a consumer: in a document meant as
        evidence that would be a false indication of provenance."""
        for name in sb.PROPERTY_NAMES:
            with self.subTest(name=name):
                self.assertTrue(name.startswith(sb.PROPERTY_PREFIX))
                local = name[len(sb.PROPERTY_PREFIX):]
                self.assertTrue(local[:1].islower(), local)
                self.assertTrue(local.isalpha(), local)
                self.assertTrue(local.isascii(), local)

    def test_the_names_are_unique_and_split_between_the_two_scopes(self):
        """The count is asserted in this BODY, never engraved in a name, and it
        is COMPUTED from the tables rather than copied: a figure in a test name
        never goes red, it just becomes a lie."""
        self.assertEqual(len(sb.PROPERTY_NAMES), len(set(sb.PROPERTY_NAMES)))
        self.assertEqual(len(sb.METADATA_PROPERTY_NAMES)
                         + len(sb.COMPONENT_PROPERTY_NAMES),
                         len(sb.PROPERTY_NAMES))
        self.assertEqual(set(), set(sb.METADATA_PROPERTY_NAMES)
                         & set(sb.COMPONENT_PROPERTY_NAMES))

    def test_a_property_appears_only_when_something_abnormal_happened(self):
        """The document promises that everything abnormal that can be observed
        is written. So the omission asserts something precise -- "nothing
        abnormal happened to this path" -- and writing it out on every
        component would say no more than leaving it out.

        WHAT MUST HOLD ALONGSIDE IT: `definitions.component.additionalProperties` is `false` in the
        schema (read on 13 September 2026), so a component's `properties` may
        hold the declared names and NO other. An equality cannot stand in for
        that -- the array is usually absent -- so the INCLUSION does, and it
        is checked on every component of both runs below.

        The run under test is the worst one available: a directory source, so
        nothing was extracted and nothing went wrong.
        """
        source = self.dir / "given"
        source.mkdir()
        (source / "a.txt").write_text("a")
        prepared = ux.prepare_source(str(source))

        document = sb.build_document(prepared.report, prepared.tree,
                                     source=str(source),
                                     source_digest=prepared.digest)

        # `metadata` still carries its whole table: the one property left is
        # written on every document, favourable or not, because it is the flag
        # that says whether the promise holds at all.
        emitted = {p["name"] for p in document["metadata"]["properties"]}
        self.assertEqual(set(sb.METADATA_PROPERTY_NAMES), emitted)

        for component in document["components"]:
            with self.subTest(name=component["name"]):
                self.assertNotIn("properties", component)

    def test_no_component_is_ever_silent_about_a_missing_digest(self):
        """THE INVARIANT: a component carries either a digest or an anomaly
        saying why it has none.

        `hashes` has no way to say "not computed". Saying it is only needed
        where a digest is missing, and that must always be said, or a
        component could go silent on the one thing this document exists to
        attest.
        """
        # A FILE WHOSE BYTES CANNOT BE READ, and it has to really be one.
        # This test used to set `chmod(0o444)`, which is READ-ONLY, not
        # unreadable -- the owner opens it perfectly well on every platform --
        # so the branch it exists to exercise was never entered and the test
        # could not fail. Measured in review. The digest function is
        # neutralised instead, which is the technique the neighbouring test
        # already uses and the only one that works the same everywhere.
        source = self.dir / "given"
        source.mkdir()
        (source / "a.txt").write_text("a")
        prepared = ux.prepare_source(str(source))
        original = sb._digest_of_existing_file
        sb._digest_of_existing_file = lambda path: None
        try:
            document = sb.build_document(prepared.report, prepared.tree,
                                         source=str(source),
                                         source_digest=prepared.digest)
        finally:
            sb._digest_of_existing_file = original

        unreadable = self._component(document, "a.txt")
        self.assertNotIn("hashes", unreadable)
        self.assertEqual([sb.READ_FAILED], self._anomalies_of(unreadable),
                         "the component says why it has no digest")

        for component in document["components"] + [
                document["metadata"]["component"]]:
            with self.subTest(name=component["name"]):
                self.assertTrue(
                    component.get("hashes")
                    or self._anomalies_of(component)
                    or component["type"] == sb.TYPE_NOT_A_FILE,
                    "a component with neither a digest nor a reason")
                # The inclusion that stands in for `additionalProperties`.
                self.assertLessEqual(
                    set(self._properties_of(component)),
                    set(sb.COMPONENT_PROPERTY_NAMES))

    def test_a_property_value_is_always_a_string_even_when_it_is_a_number(self):
        """The schema says a property value is a string. Numbers are converted
        here, explicitly, rather than left to a serialiser to decide.

        TESTED ON THE HELPER AND NOT ONLY ON A DOCUMENT: no property this
        package writes today is numeric, so a document alone cannot reach the
        conversion. The guard applies to every property written in future.
        """
        self.assertEqual([{"name": "unboxr:x", "value": "12"}],
                         sb._properties((("unboxr:x", 12),)))

        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        _, document = self._document_of(archive)
        everywhere = list(document["metadata"]["properties"])
        for component in document["components"]:
            everywhere.extend(component.get("properties", []))
        everywhere.extend(
            document["metadata"]["component"].get("properties", []))
        for entry in everywhere:
            with self.subTest(name=entry["name"]):
                self.assertIsInstance(entry["value"], str)

    def test_the_seven_zip_that_ran_is_named_as_a_tool_without_its_path(self):
        """WHAT RAN, NOT WHAT THE MACHINE HAS. The document names the tool
        that took part in the extraction, not the machine's whole capability
        profile, which would describe the environment rather than the
        provenance and make two machines produce two different documents even
        when the difference had changed nothing.

        THE PATH DOES NOT GET IN: it differs
        from one machine to the next and would reopen a divergence in a
        document meant to be compared. The STEM is what is written, and it is
        also the identity that matters -- `7z`, `7za`, `7zr` and `7zz` are
        different products with different coverage.
        """
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        prepared = ux.prepare_source(str(archive), workspace=self.dir / "w")
        binary = str(Path("/nowhere/at/all") / "7zz.exe")
        prepared.report.seven_zip_used = binary

        document = sb.build_document(prepared.report, prepared.tree,
                                     source=str(archive),
                                     source_digest=prepared.digest)

        tools = document["metadata"]["tools"]["components"]
        self.assertEqual(["unboxr", "7zz"], [t["name"] for t in tools])
        self.assertEqual("application", tools[1]["type"])
        # A binary that will not say its version keeps its entry all the same:
        # dropping the tool would hide that 7-Zip ran at all.
        self.assertNotIn("version", tools[1])
        self.assertNotIn(binary, sb.serialise(document))

    def test_a_run_that_never_called_seven_zip_names_only_unboxr(self):
        """NAMING A TOOL THAT DID NOT RUN WOULD BE A FALSE PROVENANCE, and it
        is the failure mode the old availability property had by design: it
        was written on every document, 7-Zip or no 7-Zip."""
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        _, document = self._document_of(archive)
        tools = document["metadata"]["tools"]["components"]
        self.assertEqual(["unboxr"], [t["name"] for t in tools])


# ---------------------------------------------------------------------------
# What the document warns about, and what it must never warn about
# ---------------------------------------------------------------------------
class TestTheWarningsTheDocumentCarries(_Bench):

    # The statements true of every document this package writes -- what it
    # does not prove, the oracle reminder -- live in the README, not in a
    # per-document field. The tests below hold the one place the prose is READ
    # from rather than retyped.

    def test_the_command_composes_its_reminder_on_that_same_constant(self):
        """One sentence, one home. The counting prefix is a logging concern and
        has no place in a document."""
        from unboxr import cli
        self.assertTrue(cli.ORACLE_REMINDER.endswith(rp.ORACLE_REMINDER_SENTENCE))
        self.assertTrue(cli.ORACLE_REMINDER.startswith("%s"))

# ---------------------------------------------------------------------------
# Same input, same bytes -- except for the two fields it declares
# ---------------------------------------------------------------------------
class TestTheDocumentIsDeterministic(_Bench):

    def _without_the_volatile_fields(self, document):
        stripped = dict(document)
        stripped.pop("serialNumber")
        stripped["metadata"] = {k: v for k, v in document["metadata"].items()
                                if k != "timestamp"}
        return sb.serialise(stripped)

    def test_two_runs_over_the_same_input_produce_the_same_bytes(self):
        """Everything but the serial number and the timestamp, which the
        document itself names as volatile."""
        inner = self._zip_bytes([("code/aes.c", "int a;")])
        archive = self._zip_at(self.dir / "p.zip",
                               [("b.txt", "b"), ("a.txt", "a"),
                                ("vendor/inner.zip", inner)])

        _, first = self._document_of(archive, workspace=self.dir / "w1")
        _, second = self._document_of(archive, workspace=self.dir / "w2")

        self.assertEqual(self._without_the_volatile_fields(first),
                         self._without_the_volatile_fields(second))

    # The document does not name its two volatile fields itself: CycloneDX
    # defines both `serialNumber` and `metadata.timestamp` as belonging to the
    # moment a document is made, and a paraphrase of the standard is one more
    # thing that can drift away from what it repeats.

    def test_the_components_are_sorted_on_a_string_and_not_on_a_raw_path(self):
        """A sort on a raw `Path` is not portable: the same tree would be
        walked in two different orders on two systems. The same discipline as
        guarantee 1 of the determinism contract."""
        import inspect
        source = inspect.getsource(sb.build_document)
        self.assertIn("sorted(order)", source)
        self.assertIn("as_posix()", inspect.getsource(sb._walk_the_tree))

    def test_the_serialisation_fixes_every_parameter_that_moves_the_bytes(self):
        """A default that changed would change the bytes of every document
        produced afterwards, with nothing to say so.

        `sort_keys` LEFT THE LIST, AND ITS ABSENCE IS GUARDED IN ITS PLACE.
        The order of the keys now comes from a declared table; asking
        `json.dumps` to sort as well would throw that order away and put the
        keys back in alphabetical order, in silence. What the parameter used
        to protect -- bytes independent of the order the dictionaries happen
        to be written in -- `_in_key_order` protects, so its call is pinned
        here for exactly the reason the parameters are.
        """
        import inspect
        # THE DOCSTRING IS NOT THE CODE. It argues at length about
        # `sort_keys`, and a maintainer writing `# never pass sort_keys=True`
        # as a warning -- the most natural thing to write there -- would make
        # the guard below fail for the exact opposite of its purpose.
        whole = inspect.getsource(sb.serialise)
        halves = whole.split('"""')
        source = halves[0] + "".join(halves[2:])
        self.assertNotIn("sort_keys", source,
                         "the docstring was not stripped, so the guard "
                         "below would be inspecting prose")
        for parameter in ("ensure_ascii=True", "indent=2"):
            with self.subTest(parameter=parameter):
                self.assertIn(parameter, source)
        for call in ("_in_key_order(", "_fold_two_key_objects("):
            with self.subTest(call=call):
                self.assertIn(call, source)
        self.assertNotIn("sort_keys=", source)

    def test_a_file_name_that_no_encoder_can_represent_does_not_lose_the_document(self):
        """A POSIX file system can hand over a name carrying lone surrogates.
        `ensure_ascii=True` escapes it instead of raising, so ONE undecodable
        name cannot cost the whole document -- and the name round-trips."""
        document = {"components": [{"name": "odd/" + chr(0xDCFF) + ".txt"}]}
        text = sb.serialise(document)
        self.assertTrue(text.isascii())
        import json
        self.assertEqual(document, json.loads(text))

    def test_the_written_file_carries_the_line_ending_the_module_chose(self):
        """Text mode translates a newline into a carriage-return pair on
        Windows: the same document would come out as different bytes on two
        machines, with nothing in it to declare the divergence."""
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        _, document = self._document_of(archive)
        destination = self.dir / "out.json"

        sb.write_document(document, destination)

        raw = destination.read_bytes()
        self.assertNotIn(b"\r\n", raw)
        self.assertTrue(raw.endswith(b"\n"))

# ---------------------------------------------------------------------------
# The command writes it on request, and the library still writes nothing
# ---------------------------------------------------------------------------
class _CommandBench(_Bench):
    """Runs the command in process, with its logging isolated."""

    def _run(self, argv):
        import contextlib
        import logging
        from unboxr import cli

        package_logger = logging.getLogger("unboxr")
        handlers = list(package_logger.handlers)
        level = package_logger.level
        out, err = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                try:
                    code = cli.main(argv)
                except SystemExit as exit_code:      # parser.error
                    code = exit_code.code
        finally:
            package_logger.handlers = handlers
            package_logger.setLevel(level)
        return code, out.getvalue(), err.getvalue()

    def _read(self, path: Path):
        import json
        return json.loads(path.read_text(encoding="utf-8"))


class TestTheCommandWritesTheDocument(_CommandBench):

    def test_no_document_is_written_when_none_is_asked_for(self):
        """`unboxr` does not take the liberty of writing a file nobody asked
        for. The option is the whole of the request."""
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        code, out, _ = self._run([str(archive), str(self.dir / "d")])
        self.assertEqual(0, code)
        self.assertEqual([], list(self.dir.glob("*.json")))
        self.assertTrue(out.strip().endswith("p.zip"))

    def test_the_document_goes_to_the_file_and_never_into_stdout(self):
        """`stdout` stays reserved for the path of the extracted tree -- the
        one output of this program that is not a logging record. A consumer
        piping the command into something else must not find a document in the
        middle of it."""
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        document_path = self.dir / "sbom.json"

        code, out, _ = self._run([str(archive), str(self.dir / "d"),
                                  "--sbom", str(document_path)])

        self.assertEqual(0, code)
        self.assertEqual(1, len(out.strip().splitlines()))
        self.assertNotIn("CycloneDX", out)
        document = self._read(document_path)
        self.assertEqual("CycloneDX", document["bomFormat"])
        self.assertEqual(self._digest_of(b"a"),
                         self._component(document, "a.txt")["hashes"][0]["content"])

    def test_a_run_that_fails_still_writes_the_document(self):
        """THE RUN WHERE THE DOCUMENT SAYS THE MOST. There is no tree to walk,
        but the report is alive and full, and the corpus is as amputated as it
        ever gets. The return code stays 1: a failure that produced a document
        is still a failure."""
        refused = self.dir / "p.tar.zst"
        refused.write_bytes(ZSTD_MAGIC + b"undecodable")
        document_path = self.dir / "sbom.json"

        code, _, _ = self._run([str(refused), str(self.dir / "d"),
                                "--sbom", str(document_path)])

        self.assertEqual(1, code)
        document = self._read(document_path)
        metadata = {p["name"]: p["value"]
                    for p in document["metadata"]["properties"]}
        self.assertEqual(sb.OUTCOME_FAILED, metadata[sb.EXTRACTION_OUTCOME])
        # ON THE SUBJECT, NOT AMONG THE COMPONENTS. The refused container IS
        # the input, which `metadata.component` already names; listing it twice
        # would be a duplication, so its anomaly sits on the one place that
        # names it.
        subject = document["metadata"]["component"]
        self.assertEqual("p.tar.zst", subject["name"])
        self.assertEqual([rp.ZSTD_NOT_SUPPORTED], self._anomalies_of(subject))
        self.assertEqual([], [c for c in document["components"]
                              if c["name"] == "p.tar.zst"])
        for component in document["components"]:
            with self.subTest(name=component["name"]):
                self.assertTrue(self._anomalies_of(component),
                                "no file component: there was no tree, so "
                                "every component here comes from the report "
                                "and carries the reason it is there")

    def test_a_source_that_is_already_a_directory_is_inventoried_where_it_is(self):
        """`prepare_source` returns it as it is: nothing is extracted, the
        report is empty, and there is no depth to speak of. Everything under
        it is hashed -- this package applies no exclusion policy, so a `.git`
        directory in the source is inventoried like anything else."""
        source = self.dir / "given"
        (source / ".git").mkdir(parents=True)
        (source / ".git" / "config").write_text("x")
        (source / "pkg.py").write_text("y")
        document_path = self.dir / "sbom.json"

        code, _, _ = self._run([str(source), str(self.dir / "d"),
                                "--sbom", str(document_path)])

        self.assertEqual(0, code)
        document = self._read(document_path)
        metadata = {p["name"]: p["value"]
                    for p in document["metadata"]["properties"]}
        self.assertEqual(sb.OUTCOME_COMPLETE, metadata[sb.EXTRACTION_OUTCOME])
        # `sourceKind` said what `metadata.component.type` already says.
        self.assertEqual(sb.TYPE_NOT_A_FILE,
                         document["metadata"]["component"]["type"])
        self.assertEqual({".git/config", "pkg.py"},
                         {c["name"] for c in document["components"]})

    def test_the_library_writes_nothing_without_being_told_to(self):
        """`build_document` RETURNS a structure; writing is a separate gesture.
        A function that cannot write cannot write by accident -- the silence of
        the library holds by construction, not by discipline."""
        import contextlib
        import inspect
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        before = sorted(path.name for path in self.dir.rglob("*"))

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            prepared = ux.prepare_source(str(archive), workspace=self.dir / "w")
            document = sb.build_document(prepared.report, prepared.tree,
                                         source=str(archive),
                                         source_digest=prepared.digest)

        self.assertIn("bomFormat", document)
        self.assertEqual("", out.getvalue())
        self.assertEqual("", err.getvalue())
        self.assertNotIn("open(", inspect.getsource(sb.build_document))
        del before


class TestTheCommandRefusesAnUnusableOutputPath(_CommandBench):

    def test_a_path_inside_the_inventoried_tree_is_refused_before_anything_runs(self):
        """The document claims to list every file present when the extraction
        finished. Writing it inside that tree makes the claim false at the very
        moment it is written, and a file whose content carries its own digest
        does not exist. Refused at option parsing: usage error, nothing
        extracted, nothing created."""
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        destination = self.dir / "d"

        code, _, err = self._run([
            str(archive), str(destination),
            "--sbom", str(destination / "p.zip" / "sbom.json")])

        self.assertEqual(2, code)
        self.assertIn("inside the tree it inventories", err)
        self.assertFalse(destination.exists(),
                         "nothing may be created before the refusal")

    def test_the_refused_perimeter_is_the_tree_and_not_the_whole_destination(self):
        """Refusing `<destination>/sbom.json`, beside `extracted/`, would be an
        excess: that path is not inventoried by anything."""
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        destination = self.dir / "d"
        destination.mkdir()

        code, _, _ = self._run([str(archive), str(destination),
                                "--sbom", str(destination / "sbom.json")])

        self.assertEqual(0, code)
        self.assertTrue((destination / "sbom.json").is_file())

    def test_the_source_archive_itself_is_refused(self):
        """A file whose content carries its own SHA-256 digest does not
        exist: `--sbom` may not name the archive it is documenting. Code
        review -- unguarded, `--sbom` pointed at the source silently
        overwrote it with the document, exit code 0."""
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        before = archive.read_bytes()

        code, _, err = self._run([str(archive), str(self.dir / "d"),
                                  "--sbom", str(archive)])

        self.assertEqual(2, code)
        self.assertIn("overwrite the source archive", err)
        self.assertEqual(before, archive.read_bytes(),
                         "the source archive must be untouched")

    def test_the_destination_directory_itself_is_refused(self):
        """`--sbom` naming the destination itself, rather than a file inside
        it, does not exist at option-parsing time -- `prepare_source` has not
        run yet -- so the refusal has to compare resolved paths directly
        rather than probing existence. Code review."""
        destination = self.dir / "d"
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])

        code, _, err = self._run([str(archive), str(destination),
                                  "--sbom", str(destination)])

        self.assertEqual(2, code)
        self.assertIn("is the destination directory", err)
        self.assertFalse(destination.exists(),
                         "nothing may be created before the refusal")

    def test_an_unresolvable_source_probe_is_refused_not_silently_read_as_not_a_directory(self):
        """`_inventoried_tree` used to swallow an `OSError` raised while
        probing whether the source is a directory, and silently fall through
        to the archive-style tree -- switching the containment check off
        against the wrong tree without saying so. Code review:
        it now declares the failure the same way `_resolved` already does."""
        from unboxr import cli

        original = Path.is_dir
        def _raising_is_dir(self):
            if self.name == "given":
                raise OSError("permission denied")
            return original(self)
        with mock.patch.object(Path, "is_dir", _raising_is_dir):
            code, _, err = self._run([str(self.dir / "given"), str(self.dir / "d"),
                                      "--sbom", str(self.dir / "s.json")])

        self.assertEqual(2, code)
        self.assertIn("could not be resolved", err)

    def test_the_source_directory_itself_is_refused_for_the_same_reason(self):
        """On this branch the inventoried tree IS the directory the user handed
        over -- plus a second reason of its own: `unboxr` does not write into
        the source it was given."""
        source = self.dir / "given"
        source.mkdir()
        (source / "a.txt").write_text("a")

        code, _, err = self._run([str(source), str(self.dir / "d"),
                                  "--sbom", str(source / "sbom.json")])

        self.assertEqual(2, code)
        self.assertIn("inside the tree it inventories", err)
        self.assertFalse((source / "sbom.json").exists())

    def test_the_comparison_is_on_resolved_paths_and_never_on_strings(self):
        """Two spellings of one path name the same target. A check comparing
        strings would be defeated by the simplest of them."""
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        destination = self.dir / "d"
        disguised = destination / "p.zip" / ".." / "p.zip" / "sbom.json"

        code, _, err = self._run([str(archive), str(destination),
                                  "--sbom", str(disguised)])

        self.assertEqual(2, code)
        self.assertIn("inside the tree it inventories", err)

    def test_a_parent_directory_that_does_not_exist_is_refused_early(self):
        """A long extraction thrown away at the final write would look like
        work that never happened. What is decidable before it starts is decided
        before it starts."""
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        destination = self.dir / "d"

        code, _, err = self._run([str(archive), str(destination),
                                  "--sbom", str(self.dir / "no" / "such" / "s.json")])

        self.assertEqual(2, code)
        self.assertIn("parent directory does not exist", err)
        self.assertFalse(destination.exists())

    def test_an_output_path_that_is_an_existing_directory_is_refused_early(self):
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        already = self.dir / "already"
        already.mkdir()

        code, _, err = self._run([str(archive), str(self.dir / "d"),
                                  "--sbom", str(already)])

        self.assertEqual(2, code)
        self.assertIn("is a directory, not a file", err)

    def test_no_write_probe_is_ever_performed_in_the_users_tree(self):
        """Creating and deleting a test file has a side effect in the user own
        tree and establishes nothing about the instant the real write will
        happen. The choice is stated in the module, not left implicit."""
        import inspect
        from unboxr import cli
        source = inspect.getsource(cli.check_document_path)
        self.assertIn("NO WRITE PROBE", source)
        self.assertNotIn("touch(", source)
        self.assertNotIn("unlink(", source)

    def test_a_write_that_fails_after_extraction_is_named_and_costs_the_code(self):
        """The residue of the early check, handled rather than left silent. The
        extraction is NOT lost -- `stdout` still carries the tree -- but the
        run reports failure rather than pretending a document exists."""
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        document_path = self.dir / "sbom.json"
        original = sb.write_document
        sb.write_document = lambda document, destination: (_ for _ in ()).throw(
            OSError("the disk filled up"))
        try:
            code, out, err = self._run([str(archive), str(self.dir / "d"),
                                        "--sbom", str(document_path)])
        finally:
            sb.write_document = original

        self.assertEqual(1, code)
        self.assertIn("could not be written", err)
        self.assertIn("the disk filled up", err)
        self.assertTrue(out.strip().endswith("p.zip"),
                        "the extraction is not lost because a write failed")


class TestADirectoryPathIsNeverCalledAFile(_Bench):

    def test_a_recorded_path_that_names_a_directory_is_not_typed_as_a_file(self):
        """CycloneDX closes its component types at thirteen values and none of
        them is "directory" -- read from the schema on 13 September 2026. Typing
        one `file` would be a false statement in a document meant as evidence;
        it is typed `data`, the one value that asserts a collection rather than
        a single file or a piece of software. What actually tells it apart is
        the anomaly `not_regular_file`, which is also what the type
        is COMPUTED from -- one fact, stated once, read in two places.

        `--no-archive-dir` is used here (rather than the default mode) so the
        occupied directory is named after the WORKSPACE ("w"), never after
        the archive ("p.zip") the way the default mode's target is:
        the two would otherwise carry the very same bare name,
        and `_component` -- exactly one match by name -- could no longer
        isolate the directory-typed component this test exists to check from
        the archive's own file-typed one."""
        destination = self.dir / "w"
        destination.mkdir(parents=True)
        (destination / "left-over.txt").write_text("x")
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])

        prepared = ux.prepare_source(str(archive), workspace=destination,
                                     no_archive_dir=True)
        document = sb.build_document(prepared.report, prepared.tree,
                                     source=str(archive),
                                     source_digest=prepared.digest)

        component = self._component(document, "w")
        self.assertEqual(sb.TYPE_NOT_A_FILE, component["type"])
        self.assertNotEqual(sb.TYPE_FILE, component["type"])
        self.assertNotIn("hashes", component)
        # The anomaly that DID bring it here explains the missing digest on its
        # own; `read_failed` is not appended beside it, because nothing tried
        # to read a directory and failed.
        self.assertEqual([rp.DESTINATION_ALREADY_OCCUPIED],
                         self._anomalies_of(component))
        self.assertNotIn(sb.READ_FAILED, self._anomalies_of(component))


class TestAFileThatWasNeverADirectoryIsNeverCalledOne(_Bench):
    """Code review. `DESTINATION_ALREADY_OCCUPIED` is the ONE report
    code no call site ever hashes, because its recorded path IS a directory.
    Every other digest-less record names something that WAS a file: typing it
    `not_a_file` was a false statement, made for the wrong reason."""

    def test_a_record_whose_digest_could_not_be_taken_is_a_read_failure_not_a_non_file(self):
        held = ux.new_report()
        held.record(rp.NESTED_CONTAINER_OPENED, "vendor/inner.zip",
                    path_frame=rp.PATH_IS_TREE_RELATIVE)  # digest=None: a read
                                                          # that failed, not a
                                                          # directory

        document = sb.build_document(held, self._tree(), source="p.zip")

        component = self._component(document, "vendor/inner.zip")
        self.assertEqual(sb.TYPE_FILE, component["type"],
                         "a container that was hashed and destroyed is a "
                         "file, even when its digest could not be taken")
        # THE GUARD THAT KEEPS IT FROM GOING SILENT. `nested_container_opened`
        # writes no property, so without the fallback this component would
        # carry neither a digest nor a reason.
        self.assertIn(sb.READ_FAILED, self._anomalies_of(component))

    def test_a_container_already_gone_by_the_time_this_ran_is_not_a_directory(self):
        """`EXTRACTION_KEPT_UNDER_PROVISIONAL_NAME` is recorded with no digest
        by design: `archive.unlink()` already succeeded (`extraction.py`), so
        the file is gone. It was never a directory."""
        held = ux.new_report()
        held.record(rp.EXTRACTION_KEPT_UNDER_PROVISIONAL_NAME, "archive_deadbeef",
                    path_frame=rp.PATH_IS_TREE_RELATIVE)

        document = sb.build_document(held, self._tree(), source="p.zip")

        component = self._component(document, "archive_deadbeef")
        self.assertEqual(sb.TYPE_FILE, component["type"])
        self.assertNotEqual(sb.TYPE_NOT_A_FILE, component["type"])
        self.assertNotIn("hashes", component)
        # ITS OWN CAUSE IS THE EXPLANATION, and no `read_failed` is invented
        # beside it. Saying a read failed would assert an event that never
        # took place: the file was gone before anything tried to read it.
        self.assertEqual([rp.EXTRACTION_KEPT_UNDER_PROVISIONAL_NAME],
                         self._anomalies_of(component))


class TestATreeThatCannotBeWalkedFailsRatherThanLies(_Bench):
    """Code review. Swallowing the walk's own `OSError` used to
    produce a document declaring `extractionOutcome=complete` with zero file
    components: the very amputation this document exists to make visible,
    left completely unnamed."""

    def test_an_unwalkable_tree_raises_instead_of_producing_an_empty_complete_document(self):
        held = ux.new_report()
        held.record(rp.INPUT_CONTAINER_OPENED, "p.zip", digest=self._digest_of(b"x"))

        with self.assertRaises(OSError):
            sb.build_document(held, self.dir / "does" / "not" / "exist",
                              source="p.zip")


class TestASignedURLNeverLeaksIntoTheDocument(_Bench):
    """Code review. A raw split on `/` kept a URL's query string --
    where a signed URL carries its credential -- in `metadata.component.name`,
    and that string changes on every fetch, breaking determinism on a field
    never declared volatile."""

    def test_the_query_string_and_fragment_are_stripped_like_download_source_strips_them(self):
        name = sb._bare_name(
            "https://host/pkg-1.2.3.tar.gz?X-Amz-Signature=SECRET&e=1#frag")
        self.assertEqual("pkg-1.2.3.tar.gz", name)
        self.assertNotIn("SECRET", name)

    def test_a_url_with_no_path_component_falls_back_to_unknown_not_the_query(self):
        name = sb._bare_name("https://host/download?file=pkg.tar.gz")
        self.assertNotIn("file=pkg.tar.gz", name)

    def test_a_plain_path_is_unaffected(self):
        self.assertEqual("p.zip", sb._bare_name("/tmp/workspace/p.zip"))


# The document carries no depth property. The bound only matters when it is
# REACHED, and that case files a `maximum_depth_reached` anomaly on every
# container left closed. The value of `--max-depth` is not in the document;
# that is a declared limit, written down here rather than discovered later.


class TestContainersNotOpenedCountsComponentsNotRecords(_Bench):
    """Code review. `report.amputation_count()` counts RECORDS
    (`len(report.not_opened)`), and one path may carry several codes
    without becoming several components: a container refused for two reasons
    at once used to make this number exceed the actual not-opened components
    in `components`."""

    def test_two_causes_on_one_path_are_counted_once(self):
        held = ux.new_report()
        held.record(rp.TAR_REFUSED_BY_SECURITY_FILTER, "a.tar")
        held.record(rp.TAR_CONTENT_PARTLY_MOVED, "a.tar")
        self.assertEqual(2, len(held.not_opened), "two records, as expected")

        document = sb.build_document(held, self._tree(), source="p.zip")

        not_opened_components = [c for c in document["components"]
                                 if c["name"] == "a.tar"]
        self.assertEqual(1, len(not_opened_components),
                         "one component: the identity rule")
        # Both causes are on that one component, in order: the identity rule
        # merges the records without dropping either reason.
        self.assertEqual([rp.TAR_REFUSED_BY_SECURITY_FILTER,
                          rp.TAR_CONTENT_PARTLY_MOVED],
                         self._anomalies_of(not_opened_components[0]))


class TestACauseOrderNeverDependsOnFillOrder(_Bench):
    """Code review. Nothing held this order, and relying on it would have
    meant relying on an unguaranteed property. Two reports that file
    the same two causes for the same path in the OPPOSITE order must produce
    the identical `causeCode`/`causeText` join -- proving the document does
    not lean on the report's internal list fill order, only on the genre a
    code belongs to and its own canonical declaration rank."""

    def test_the_joined_cause_code_does_not_depend_on_recording_order(self):
        forward = ux.new_report()
        forward.record(rp.TAR_REFUSED_BY_SECURITY_FILTER, "a.tar")
        forward.record(rp.TAR_CONTENT_PARTLY_MOVED, "a.tar")

        backward = ux.new_report()
        backward.record(rp.TAR_CONTENT_PARTLY_MOVED, "a.tar")
        backward.record(rp.TAR_REFUSED_BY_SECURITY_FILTER, "a.tar")

        tree_a = self.dir / "tree_a"
        tree_a.mkdir()
        tree_b = self.dir / "tree_b"
        tree_b.mkdir()
        doc_forward = sb.build_document(forward, tree_a, source="p.zip")
        doc_backward = sb.build_document(backward, tree_b, source="p.zip")

        code_forward = self._properties_of(
            self._component(doc_forward, "a.tar"))[sb.ANOMALY_CODE]
        code_backward = self._properties_of(
            self._component(doc_backward, "a.tar"))[sb.ANOMALY_CODE]
        self.assertEqual(code_forward, code_backward)


class TestAHashIsNeverTakenForARecordThatWillBeDiscarded(_Bench):
    """Code review. `_record` used to hash BEFORE the report's own
    `(code, path)` deduplication, so a file re-examined at every flattening
    level (an office container left in place, a residual archive) paid for a
    full read each time even though only the first filing was ever kept."""

    def test_a_duplicate_code_and_path_is_not_hashed_again(self):
        calls = []
        original = ux._digest_of_existing_file
        def _counting(path):
            calls.append(path)
            return original(path)
        held = ux.new_report()
        target = self._zip_at(self.dir / "office.docx", [("x", "y")])

        with mock.patch.object(ux, "_digest_of_existing_file", _counting):
            ux._record(held, rp.OFFICE_CONTAINER_EXCLUDED, target,
                      digest_of=target)
            ux._record(held, rp.OFFICE_CONTAINER_EXCLUDED, target,
                      digest_of=target)
            ux._record(held, rp.OFFICE_CONTAINER_EXCLUDED, target,
                      digest_of=target)

        self.assertEqual(1, len(held.not_opened), "still one entry: dedup unchanged")
        self.assertEqual(1, len(calls),
                         "only the filing that survived paid for a hash")

# ---------------------------------------------------------------------------
# The link to another BOM, and the ratchet that holds it because the schema
# holds nothing
# ---------------------------------------------------------------------------
#
# The value below is a well-formed BOM-Link of DOCUMENT shape. The UUID is the
# one the schema's own documentation uses as an example, so nothing about it
# is accidental.
GOOD_LINK = "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1"


class TestTheLinkPatternIsTranscribedOnceWithItsProvenance(_Bench):
    """The pattern is the ONE thing standing between this document and a link
    that leads nowhere.

    `externalReference.url` is an `anyOf` whose first branch is a plain
    `iri-reference` string, and that branch swallows everything: measured on
    13 September 2026 against the official schema, a document whose link reads
    `anything at all` validates with ZERO errors. So the ratchet is this
    package's own, and a second transcription of the pattern would be the
    second source of truth this repository refuses everywhere else.
    """

    @staticmethod
    def _package_files():
        return sorted((REPO_ROOT / "unboxr").glob("*.py"))

    @staticmethod
    def _string_constants(path):
        import ast
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        return [node.value for node in ast.walk(tree)
                if isinstance(node, ast.Constant) and isinstance(node.value, str)]

    def _comment_block_above(self, name: str) -> str:
        """The contiguous comment lines immediately above a module-level
        assignment, as one whitespace-normalised line.

        Located by AST rather than by counting lines, so that inserting
        anything above it does not silently empty this guard. NORMALISED
        because a comment block is wrapped prose: a sentence straddles a line
        break, and asserting on the raw text would fail on a reflow that
        changed nothing -- the same discipline the contract guards already
        apply to the module docstring and the README.
        """
        import ast
        path = REPO_ROOT / "unboxr" / "sbom.py"
        lines = path.read_text(encoding="utf-8").splitlines()
        tree = ast.parse("\n".join(lines), filename=str(path))
        found = [node for node in tree.body
                 if isinstance(node, ast.Assign)
                 and any(getattr(target, "id", None) == name
                         for target in node.targets)]
        self.assertEqual(1, len(found), "exactly one assignment of " + name)
        index = found[0].lineno - 2          # 1-based lineno, then the line above
        block = []
        while index >= 0 and lines[index].lstrip().startswith("#"):
            block.append(lines[index])
            index -= 1
        import re
        joined = " ".join(line.lstrip().lstrip("#")
                          for line in reversed(block))
        return re.sub(r"\s+", " ", joined).strip()

    def test_the_pattern_is_transcribed_at_exactly_one_place(self):
        """By AST, never by `grep`: the parser joins adjacent string literals
        into one constant, so a pattern written over two lines is ONE value
        here where a textual search would see two fragments and find neither.

        The conjunction is deliberate -- a docstring may well show an example
        URN, which is not a transcription of the pattern; carrying the
        character class as well is what makes it one.
        """
        transcriptions = []
        for path in self._package_files():
            for value in self._string_constants(path):
                if "urn:cdx:" in value and "[0-9a-f]{8}" in value:
                    transcriptions.append((path.name, value))
        self.assertEqual(1, len(transcriptions), transcriptions)
        self.assertEqual("sbom.py", transcriptions[0][0])
        self.assertEqual(sb.BOM_LINK_DOCUMENT_PATTERN, transcriptions[0][1])

    def test_the_transcription_carries_its_source_its_tag_and_its_date(self):
        """A pattern written down without saying where it came from cannot be
        re-confronted to the schema by anyone but the person who wrote it."""
        block = self._comment_block_above("BOM_LINK_DOCUMENT_PATTERN")
        for fragment in ("bomLinkDocumentType", "1.7", "13 September 2026"):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, block)

    def test_the_transcription_says_why_it_is_not_read_at_run_time(self):
        """Reading the schema at run time would be the obvious move, and it is
        refused for a reason that has to be written down where the decision
        is, or the next reader undoes it."""
        block = self._comment_block_above("BOM_LINK_DOCUMENT_PATTERN")
        for fragment in ("not vendored", "declares no dependency",
                         "state of that machine"):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, block)

    def test_the_reason_is_the_fact_and_never_a_requirement_number_of_elsewhere(self):
        """This package is published on its own. A reader of its source has
        never seen any project backlog, and a reason stated by reference to
        a number there is no reason at all.

        The guard that already forbids those tokens covers the extraction
        docstring and the README only -- this module is outside it, which is
        exactly why the check is repeated here.
        """
        block = self._comment_block_above("BOM_LINK_DOCUMENT_PATTERN")
        for token in ("NFR-", "AC-", "10.5", "deferred-work"):
            with self.subTest(token=token):
                self.assertNotIn(token, block)

    def test_the_raw_string_is_what_is_exported_and_the_compiled_form_derives(self):
        """A delivery check compares this constant to the schema CHARACTER FOR
        CHARACTER. It cannot do that against a compiled object."""
        self.assertIsInstance(sb.BOM_LINK_DOCUMENT_PATTERN, str)
        self.assertTrue(sb.BOM_LINK_DOCUMENT_PATTERN.startswith("^"))
        self.assertTrue(sb.BOM_LINK_DOCUMENT_PATTERN.endswith("$"))

    def test_the_pattern_and_its_predicate_are_both_reachable_from_the_package(self):
        """EXPORTING IS TWO GESTURES, not one: the name has to enter `__all__`
        AND the import block. A name listed in one and missing from the other
        passes every other test in this suite.

        The consumer is named: a caller that has to form such a URN in the
        other direction reads the pattern from here rather than transcribing
        it a second time somewhere else.
        """
        import unboxr
        for name in ("BOM_LINK_DOCUMENT_PATTERN", "is_bom_link_to_a_document",
                     "InvalidBomLinkError", "LINKED_BOM_COMMENT"):
            with self.subTest(name=name):
                self.assertIn(name, unboxr.__all__)
                self.assertIs(getattr(sb, name), getattr(unboxr, name))


class TestAMalformedLinkIsRefused(_Bench):
    """SEVEN counter-proofs, each with a test of its own.

    Four are the ones the schema spike of 8 September 2026 measured the
    validator ACCEPTING. Three more come from reading the pattern itself on
    13 September 2026: they are the mistakes its shape invites, and no
    document of the file said so before.
    """

    def test_a_well_formed_document_link_is_accepted(self):
        """A ratchet that refuses everything proves nothing either."""
        self.assertTrue(sb.is_bom_link_to_a_document(GOOD_LINK))

    def test_a_link_with_no_version_at_all_is_refused(self):
        """Accepted by the schema, measured 8 September 2026 and
        re-confirmed 13 September 2026."""
        self.assertFalse(sb.is_bom_link_to_a_document(
            "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79"))

    def test_a_version_of_zero_is_refused(self):
        """The pattern reads `[1-9][0-9]*`: a BOM's first version is 1, and a
        link to version 0 points at a document that cannot exist. Accepted by
        the schema, measured 8 September 2026 and re-confirmed
        13 September 2026."""
        self.assertFalse(sb.is_bom_link_to_a_document(
            "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/0"))

    def test_something_that_is_not_a_uuid_at_all_is_refused(self):
        """Accepted by the schema, measured 8 September 2026 and
        re-confirmed 13 September 2026."""
        self.assertFalse(sb.is_bom_link_to_a_document("urn:cdx:not-a-uuid/1"))

    def test_a_value_that_is_not_a_urn_of_this_kind_is_refused(self):
        """The plainest case, and the schema accepts it too: its first branch
        is a bare string. Measured 8 September 2026 and re-confirmed
        13 September 2026."""
        self.assertFalse(sb.is_bom_link_to_a_document("anything at all"))

    def test_a_link_that_kept_the_urn_uuid_prefix_is_refused(self):
        """THE MISTAKE THE SHAPE INVITES. A serial number reads
        `urn:uuid:<uuid>` and a link reads `urn:cdx:<uuid>/<version>`: the
        UUID is BARE in the second. Pasting a serial number in produces a
        value the pattern refuses -- and that nothing else would. Measured
        13 September 2026."""
        self.assertFalse(sb.is_bom_link_to_a_document(
            "urn:cdx:urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79/1"))

    def test_an_uppercase_uuid_is_refused(self):
        """The pattern spells the character class `[0-9a-f]`, lowercase. The
        same UUID in capitals is a different string to it, and a UUID printed
        by a tool that upper-cases is the ordinary way to arrive here.
        Measured 13 September 2026."""
        self.assertFalse(sb.is_bom_link_to_a_document(
            "urn:cdx:3E671687-395B-41F5-A30F-A58921A69B79/1"))

    def test_a_trailing_newline_is_refused_and_tells_the_two_calls_apart(self):
        """THE ONE COUNTER-PROOF THAT DISTINGUISHES `fullmatch` FROM `match`.

        Python's `$` accepts a final newline; the `$` of ECMA-262, which is
        the semantics a JSON Schema pattern carries, does not. Measured on
        13 September 2026, and asserted here as the measurement it is: `match`
        returns a match on this value and `fullmatch` returns none. The
        ratchet being the only defence -- the schema swallows the lot -- a
        hole of exactly this shape would never be seen by anything.
        """
        import re
        self.assertIsNotNone(
            re.match(sb.BOM_LINK_DOCUMENT_PATTERN, GOOD_LINK + "\n"),
            "the measurement this whole test rests on")
        self.assertIsNone(
            re.fullmatch(sb.BOM_LINK_DOCUMENT_PATTERN, GOOD_LINK + "\n"))
        self.assertFalse(sb.is_bom_link_to_a_document(GOOD_LINK + "\n"))

    def test_the_element_form_is_refused_although_the_schema_admits_it(self):
        """A DECISION OF THIS PACKAGE, not a constraint of the format, and
        reversible as such. Two reasons, either of which suffices: `unboxr`
        knows no `bom-ref` of the document it points at, and a `bom-ref` of
        its own is a RANK that renumbers the moment a file enters or leaves
        the corpus -- so a link into an element would break at the next
        regeneration, in silence, the schema seeing nothing."""
        self.assertFalse(sb.is_bom_link_to_a_document(
            GOOD_LINK + "#unboxr-component-7"))

    def test_anything_that_is_not_a_string_is_refused_rather_than_raising(self):
        """The predicate answers a question; it does not decide that a caller
        handing over the wrong kind of thing has a link."""
        for value in (None, 1, b"urn:cdx:", ["a"]):
            with self.subTest(value=value):
                self.assertFalse(sb.is_bom_link_to_a_document(value))


class TestTheDocumentCarriesTheLink(_Bench):

    def _document_with_a_link(self, link=GOOD_LINK):
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        prepared = ux.prepare_source(str(archive), workspace=self.dir / "w")
        return sb.build_document(prepared.report, prepared.tree,
                                 source=str(archive),
                                 source_digest=prepared.digest,
                                 linked_bom=link)

    def test_the_link_is_written_at_the_root_and_never_on_metadata(self):
        """Read from the schema on 13 September 2026: `externalReferences`
        exists at the ROOT of a BOM and does NOT exist on `metadata`. Writing
        it there would make the document invalid -- and the mistake is an easy
        one, `metadata` being where everything else this package adds goes."""
        document = self._document_with_a_link()
        self.assertIn("externalReferences", document)
        self.assertNotIn("externalReferences", document["metadata"])
        self.assertEqual(1, len(document["externalReferences"]))

    def test_the_entry_carries_three_keys_and_invents_none(self):
        """`externalReference` is `additionalProperties: false` and admits
        `url`, `comment`, `type`, `hashes` and `properties` -- read from the
        schema on 13 September 2026. A key of this package's own devising
        would make the document invalid, and there is no `unboxr:` property
        here for the same reason there is none anywhere else the schema
        already provides the field."""
        entry = self._document_with_a_link()["externalReferences"][0]
        self.assertEqual({"type", "url", "comment"}, set(entry))

    def test_the_type_is_the_schema_value_for_a_bill_of_materials(self):
        """One of the 47 values of the enumeration, read on 13 September 2026,
        and the one described as a bill of materials."""
        entry = self._document_with_a_link()["externalReferences"][0]
        self.assertEqual("bom", entry["type"])

    def test_the_comment_says_what_the_link_does_not_attest(self):
        """POSITIVE ONLY, APPLIED TO THE LINK ITSELF. `unboxr` does not open
        the document it points at: it cannot know that it exists, and it
        cannot know that it describes this extraction. A link that said
        nothing would be read as asserting both."""
        entry = self._document_with_a_link()["externalReferences"][0]
        self.assertEqual(sb.LINKED_BOM_COMMENT, entry["comment"])
        self.assertIn("does not open", sb.LINKED_BOM_COMMENT)
        self.assertIn("neither that the document exists",
                      sb.LINKED_BOM_COMMENT)
        self.assertIn("describes this extraction", sb.LINKED_BOM_COMMENT)

    def test_the_link_is_taken_as_given_and_never_composed_here(self):
        """`unboxr` receives the URN formed. It does not assemble one out of a
        serial number and a version, because how a caller numbers its own
        documents is not this package's business -- and a composer would be a
        point of extension built for a consumer that has not asked for it.

        Proven on the observable: the URN written is the string handed over,
        and it has nothing to do with this document's own serial number.
        """
        document = self._document_with_a_link()
        self.assertEqual(GOOD_LINK, document["externalReferences"][0]["url"])
        self.assertNotIn(document["serialNumber"].removeprefix("urn:uuid:"),
                         document["externalReferences"][0]["url"])

    def test_the_urn_that_is_actually_written_satisfies_the_pattern(self):
        """THE RATCHET BITES ON THE OUTPUT, NEVER ON THE INPUT. Confronting
        the value handed in would leave a transformation made downstream of
        the check -- a strip, a join, a re-encoding -- entirely unseen."""
        document = self._document_with_a_link()
        self.assertTrue(sb.is_bom_link_to_a_document(
            document["externalReferences"][0]["url"]))

    def test_a_malformed_link_raises_rather_than_being_written(self):
        """The library refuses what it knows to be false. It does not write
        it, and the failure carries the value it refused."""
        with self.assertRaises(sb.InvalidBomLinkError) as raised:
            self._document_with_a_link("urn:cdx:not-a-uuid/1")
        self.assertIn("urn:cdx:not-a-uuid/1", str(raised.exception))

    def test_a_malformed_link_is_never_quietly_downgraded_to_no_link(self):
        """A silent fallback would make the attachment the caller asked for
        disappear, leaving a document that looks exactly like one nobody ever
        wanted linked."""
        with self.assertRaises(sb.InvalidBomLinkError):
            self._document_with_a_link(GOOD_LINK + "#unboxr-component-1")


class TestTheAbsenceOfALinkIsAStatedFact(_Bench):

    def _document_without_a_link(self):
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        _, document = self._document_of(archive)
        return document

    def test_without_a_link_the_key_is_absent_and_never_an_empty_array(self):
        """AN EMPTY ARRAY WOULD READ AS "we looked, there is none" -- a
        negative drawn from an absence, which is the one reading this package
        refuses everywhere.

        AND THIS IS A RULE OF THIS PACKAGE, NOT OF THE FORMAT: measured on
        13 September 2026, a document carrying `externalReferences: []`
        validates with zero errors. Saying so keeps a later reader from
        relaxing this as a redundant restatement of the schema.
        """
        document = self._document_without_a_link()
        self.assertNotIn("externalReferences", document)

    # What an absent reference means -- that none was supplied, never that this
    # extraction belongs to none -- is a rule of READING this format, true of
    # every document, which is what the README is for, not a per-document
    # field.

    def test_the_link_adds_no_property_of_this_package_to_the_document(self):
        """A property whose native field the schema already provides does not
        exist here: the link is `externalReferences`, the sense of it is the
        native `comment`. The published table of property names is unchanged,
        and so is the minor-version rule that goes with it."""
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        prepared = ux.prepare_source(str(archive), workspace=self.dir / "w")
        document = sb.build_document(prepared.report, prepared.tree,
                                     source=str(archive),
                                     source_digest=prepared.digest,
                                     linked_bom=GOOD_LINK)
        text = sb.serialise(document)
        names = {p["name"] for p in document["metadata"]["properties"]}
        self.assertEqual(set(sb.METADATA_PROPERTY_NAMES), names)
        self.assertNotIn("unboxr:linkedBom", text)


class TestTheInjectionHooksSurviveTheLink(_Bench):
    """`serial_number=` and `timestamp=` have been accepted from the start
    and had no test and no caller: measured on 13 September 2026. The
    link restructures the very `return` they feed into, so a hook broken in
    passing would have gone unnoticed. They are covered now."""

    def test_an_injected_serial_number_and_timestamp_are_used_as_given(self):
        held = ux.new_report()
        document = sb.build_document(
            held, self._tree(), source="p.zip",
            serial_number="urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
            timestamp="2026-09-13T00:00:00+00:00")
        self.assertEqual("urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
                         document["serialNumber"])
        self.assertEqual("2026-09-13T00:00:00+00:00",
                         document["metadata"]["timestamp"])

    def test_the_hooks_still_default_to_a_value_the_document_computes(self):
        held = ux.new_report()
        document = sb.build_document(held, self._tree(), source="p.zip")
        self.assertTrue(document["serialNumber"].startswith("urn:uuid:"))
        self.assertEqual(1, document["version"])


class TestTheCommandLinksTheDocument(_CommandBench):

    def test_the_option_writes_the_link_into_the_document(self):
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        document_path = self.dir / "sbom.json"

        code, out, _ = self._run([str(archive), str(self.dir / "d"),
                                  "--sbom", str(document_path),
                                  "--linked-bom", GOOD_LINK])

        self.assertEqual(0, code)
        document = self._read(document_path)
        self.assertEqual(GOOD_LINK, document["externalReferences"][0]["url"])
        # `stdout` still carries the tree and nothing else.
        self.assertEqual(1, len(out.strip().splitlines()))
        self.assertNotIn("urn:cdx:", out)

    def test_a_malformed_link_is_refused_at_option_parsing(self):
        """Refused BEFORE anything is extracted: usage error, no destination
        created, no document written. A long extraction thrown away at the
        final write would look like work that never happened."""
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        destination = self.dir / "d"
        document_path = self.dir / "sbom.json"

        code, _, err = self._run([str(archive), str(destination),
                                  "--sbom", str(document_path),
                                  "--linked-bom", "urn:cdx:not-a-uuid/1"])

        self.assertEqual(2, code)
        self.assertIn("--linked-bom", err)
        self.assertFalse(destination.exists(),
                         "nothing may be created before the refusal")
        self.assertFalse(document_path.exists())

    def test_a_malformed_link_wins_over_an_unusable_destination(self):
        """Two refusals are possible from these arguments -- the link's own
        shape, and `--sbom`'s destination sitting inside the tree it would
        inventory -- and nothing before this test pinned which one a caller
        actually sees. `check_linked_bom` runs BEFORE `check_document_path`
        (by design): the link fault is the only one decidable from
        the arguments alone, with no state of the file system able to
        preempt it. A reordering of the two calls in `main` would silently
        change the reported cause with nothing here to go red."""
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        destination = self.dir / "d"

        code, _, err = self._run([
            str(archive), str(destination),
            "--sbom", str(destination / "p.zip" / "sbom.json"),
            "--linked-bom", "urn:cdx:not-a-uuid/1"])

        self.assertEqual(2, code)
        self.assertIn("--linked-bom", err)
        self.assertNotIn("inside the tree it inventories", err)
        self.assertFalse(destination.exists(),
                         "nothing may be created before the refusal")

    def test_the_link_option_without_the_document_option_is_refused(self):
        """An option that has no object is REFUSED, never ignored: ignoring it
        would let a caller believe an attachment was recorded somewhere when
        no document was written at all.

        The dependency is checked BEFORE the value: an option with no object
        at all is not examined for the shape of its argument, or a caller who
        forgot `--sbom` would be sent to fix the wrong thing.
        """
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        destination = self.dir / "d"

        code, _, err = self._run([str(archive), str(destination),
                                  "--linked-bom", "urn:cdx:not-a-uuid/1"])

        self.assertEqual(2, code)
        self.assertIn("--sbom", err)
        self.assertFalse(destination.exists())

    def test_the_failure_path_carries_the_link_too(self):
        """THE RUN THAT MOST NEEDS REATTACHING. There is no tree, the corpus is
        as amputated as it ever gets, and the document says so -- a run in
        that state is precisely the one an analyst has to be able to tie back
        to the conclusion it fed. The document is written by TWO call sites in
        the command, and wiring only the nominal one would leave this branch
        without a link and nothing would go red."""
        refused = self.dir / "p.tar.zst"
        refused.write_bytes(ZSTD_MAGIC + b"undecodable")
        document_path = self.dir / "sbom.json"

        code, _, _ = self._run([str(refused), str(self.dir / "d"),
                                "--sbom", str(document_path),
                                "--linked-bom", GOOD_LINK])

        self.assertEqual(1, code)
        document = self._read(document_path)
        metadata = {p["name"]: p["value"]
                    for p in document["metadata"]["properties"]}
        self.assertEqual(sb.OUTCOME_FAILED, metadata[sb.EXTRACTION_OUTCOME])
        self.assertEqual(GOOD_LINK, document["externalReferences"][0]["url"])

    def test_a_source_that_is_already_a_directory_carries_the_link_too(self):
        """Nothing is extracted on this branch and the report is empty; the
        link is written exactly as it is anywhere else."""
        source = self.dir / "given"
        source.mkdir()
        (source / "pkg.py").write_text("y")
        document_path = self.dir / "sbom.json"

        code, _, _ = self._run([str(source), str(self.dir / "d"),
                                "--sbom", str(document_path),
                                "--linked-bom", GOOD_LINK])

        self.assertEqual(0, code)
        document = self._read(document_path)
        metadata = {p["name"]: p["value"]
                    for p in document["metadata"]["properties"]}
        self.assertEqual(sb.TYPE_NOT_A_FILE,
                         document["metadata"]["component"]["type"])
        self.assertEqual(GOOD_LINK, document["externalReferences"][0]["url"])

    def test_without_the_option_no_document_carries_a_link(self):
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        document_path = self.dir / "sbom.json"

        code, _, _ = self._run([str(archive), str(self.dir / "d"),
                                "--sbom", str(document_path)])

        self.assertEqual(0, code)
        self.assertNotIn("externalReferences", self._read(document_path))


# ---------------------------------------------------------------------------
# The keys come out in the order the schema declares them
# ---------------------------------------------------------------------------
class _OrderBench(_Bench):
    """Documents covering every branch that can add a key.

    ONE DOCUMENT IS NOT ENOUGH, and the reason is the whole point of the guard
    below: `externalReferences`, and with it `url` and `comment`, exist only
    when a link was supplied, and `hashes` is absent from a subject that is not
    a file. A guard built on the nominal document alone would pass while
    knowing nothing of half the keys this package can write.
    """

    def _every_shape_of_document(self):
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a"),
                                                    ("b.txt", "b")])
        prepared = ux.prepare_source(str(archive), workspace=self.dir / "w")
        linked = sb.build_document(
            prepared.report, prepared.tree, source=str(archive),
            source_digest=prepared.digest,
            linked_bom=GOOD_LINK)
        plain = sb.build_document(
            prepared.report, prepared.tree, source=str(archive),
            source_digest=prepared.digest)

        source_dir = self.dir / "src"
        source_dir.mkdir()
        (source_dir / "c.txt").write_text("c", encoding="utf-8")
        from_directory = ux.prepare_source(str(source_dir),
                                           workspace=self.dir / "w2")
        directory = sb.build_document(
            from_directory.report, from_directory.tree, source=str(source_dir),
            source_digest=from_directory.digest)

        failed = sb.build_document(
            prepared.report, None, source=str(archive),
            source_digest=prepared.digest)

        # A FILE WHOSE DIGEST COULD NOT BE READ. The subject of a directory
        # document already gives a `metadata.component` with no `hashes`, but
        # not a COMPONENT without one, and the two are different objects with
        # different tables. Same substitution the read-failure test uses.
        original = sb._digest_of_existing_file
        sb._digest_of_existing_file = lambda path: None
        try:
            unhashed = sb.build_document(
                prepared.report, prepared.tree, source=str(archive),
                source_digest=prepared.digest)
        finally:
            sb._digest_of_existing_file = original

        return {"linked": linked, "plain": plain, "directory": directory,
                "failed": failed, "unhashed": unhashed}

    def _keys_of(self, value, found=None):
        found = set() if found is None else found
        if isinstance(value, dict):
            found.update(value)
            for nested in value.values():
                self._keys_of(nested, found)
        elif isinstance(value, list):
            for nested in value:
                self._keys_of(nested, found)
        return found

    def _every_dict_reversed(self, value):
        """The same document with EVERY object's keys written backwards.

        Reversing only the root and `metadata` would prove almost nothing:
        those two are already in the schema's order, and the objects
        `build_document` writes out of order -- components, properties,
        hashes, the link -- would never be touched.
        """
        if isinstance(value, dict):
            return {key: self._every_dict_reversed(value[key])
                    for key in reversed(list(value))}
        if isinstance(value, list):
            return [self._every_dict_reversed(item) for item in value]
        return value

    def _objects_of(self, value, found=None):
        found = [] if found is None else found
        if isinstance(value, dict):
            found.append(value)
            for nested in value.values():
                self._objects_of(nested, found)
        elif isinstance(value, list):
            for nested in value:
                self._objects_of(nested, found)
        return found


class TestTheKeysComeOutInTheOrderOfTheSchema(_OrderBench):

    def test_every_key_the_document_produces_is_declared_in_a_table(self):
        """THE GUARD THAT REPLACES `sort_keys`. Sorting made the bytes
        independent of the order `build_document` happens to write its
        dictionaries in. The table does that now -- but only for the keys it
        knows, so a field added tomorrow and forgotten here would come out at
        an arbitrary place with nobody the wiser."""
        for shape, document in self._every_shape_of_document().items():
            for key in sorted(self._keys_of(document)):
                with self.subTest(shape=shape, key=key):
                    self.assertIn(key, sb.KEY_ORDER)

    def test_the_branches_that_add_keys_really_are_exercised(self):
        """A guard whose corpus never reaches the optional branches would pass
        while proving nothing of them. Checked POSITIVELY, so that a document
        that stopped carrying a link could not quietly empty the guard above."""
        shapes = self._every_shape_of_document()
        linked = self._keys_of(shapes["linked"])
        self.assertLessEqual({"externalReferences", "url", "comment"}, linked)
        self.assertIn("hashes", linked)
        self.assertNotIn("externalReferences", self._keys_of(shapes["plain"]))
        subject = shapes["directory"]["metadata"]["component"]
        self.assertNotIn("hashes", subject)
        without = [c for c in shapes["unhashed"]["components"]
                   if "hashes" not in c]
        self.assertTrue(without, "no component without a digest in the corpus")

    def test_each_object_carries_its_keys_in_the_order_of_its_type(self):
        """Read from the schema, not deduced: `hashes` comes BEFORE
        `properties` on a component, and the link reads `url, comment, type`."""
        document = self._every_shape_of_document()["linked"]
        self.assertEqual(
            ["bomFormat", "specVersion", "serialNumber", "version", "metadata",
             "components", "externalReferences"],
            list(document))
        self.assertEqual(["timestamp", "tools", "component", "properties"],
                         list(document["metadata"]))

        # THE ORDER IS A PROPERTY OF THE TEXT, not of the structure
        # `build_document` returns: that one still comes back in the order it
        # was written in, and the link is the object where the two differ.
        reread = json.loads(sb.serialise(document))
        self.assertEqual(["url", "comment", "type"],
                         list(reread["externalReferences"][0]))
        # FILTERED TO THE KEYS THIS COMPONENT ACTUALLY HAS: a
        # component carries `properties` only when something abnormal happened
        # to it. The ORDER is what this test holds, and asserting presence as
        # well would make it fail for a reason it is not about.
        declared = ["type", "bom-ref", "name", "hashes", "properties"]
        self.assertEqual([k for k in declared if k in reread["components"][0]],
                         list(reread["components"][0]))
        # And one component that DOES carry properties, so the position of
        # `properties` after `hashes` is really exercised.
        with_properties = [c for c in reread["components"] if "properties" in c]
        for component in with_properties:
            self.assertEqual([k for k in declared if k in component],
                             list(component))
        self.assertEqual(["type", "name", "version"],
                         list(reread["metadata"]["tools"]["components"][0]))
        self.assertEqual(["name", "value"],
                         list(reread["metadata"]["properties"][0]))
        self.assertEqual(["alg", "content"],
                         list(reread["components"][0]["hashes"][0]))

    def test_each_object_matches_a_declared_table_and_obeys_it(self):
        """`KEY_ORDER` IS NOT ENOUGH TO CHECK AGAINST. A key transcribed into
        the WRONG per-type table still lands in the derived total order, so
        the guard above would pass while a component came out misordered.
        This one holds each object against the table its key set belongs to.
        """
        for shape, document in self._every_shape_of_document().items():
            for obj in self._objects_of(json.loads(sb.serialise(document))):
                keys = list(obj)
                tables = [order for order in sb.SCHEMA_KEY_ORDER.values()
                          if set(keys) <= set(order)]
                with self.subTest(shape=shape, keys=tuple(keys)):
                    self.assertTrue(
                        tables, "no declared table covers this key set")
                    for order in tables:
                        self.assertEqual([k for k in order if k in obj], keys)

    def test_a_key_no_table_declares_is_never_lost(self):
        """It comes out AFTER the declared keys, alphabetically. Losing it, or
        raising on it, would make a public function refuse a document it has
        no business judging."""
        document = {"components": [], "zzz": 1, "aaa": 2, "bomFormat": "x"}
        self.assertEqual(["bomFormat", "components", "aaa", "zzz"],
                         list(json.loads(sb.serialise(document))))

    def test_the_total_order_respects_every_table_it_was_derived_from(self):
        """The applied order is DERIVED, never written beside the tables: two
        sources of truth for the same thing drift the day one is edited."""
        rank = {key: index for index, key in enumerate(sb.KEY_ORDER)}
        for kind, order in sb.SCHEMA_KEY_ORDER.items():
            for earlier, later in zip(order, order[1:]):
                with self.subTest(kind=kind, earlier=earlier, later=later):
                    self.assertLess(rank[earlier], rank[later])

    def test_tables_that_contradict_each_other_are_refused(self):
        """No arbitrary order is invented when no order exists. Today the six
        tables agree; a key added tomorrow could make them disagree, and the
        failure has to be loud."""
        with self.assertRaises(ValueError) as capture:
            sb._derive_total_key_order({"one": ("a", "b"), "two": ("b", "a")})
        self.assertIn("a", str(capture.exception))
        self.assertIn("b", str(capture.exception))

    def test_the_bytes_no_longer_depend_on_the_order_of_construction(self):
        """What `sort_keys=True` actually bought, kept. Reordering two
        assignments in `build_document` must not change one byte."""
        document = self._every_shape_of_document()["linked"]
        self.assertEqual(sb.serialise(document),
                         sb.serialise(self._every_dict_reversed(document)))

    def test_a_dictionary_held_in_a_tuple_is_ordered_like_any_other(self):
        """`json.dumps` encodes a tuple as an array exactly as it encodes a
        list, so a dictionary inside one IS written. Skipping it would leave
        its keys in the order the caller built them -- the one property this
        table exists to remove."""
        built_one_way = sb.serialise(
            {"components": ({"zzz": 1, "aaa": 2, "name": "x"},)})
        built_the_other = sb.serialise(
            {"components": ({"name": "x", "aaa": 2, "zzz": 1},)})
        self.assertEqual(built_one_way, built_the_other)
        self.assertEqual(
            sb.serialise({"components": [{"name": "x", "aaa": 2, "zzz": 1}]}),
            built_one_way)

    def test_a_circular_document_raises_the_error_it_always_raised(self):
        """Before the ordering pass existed, `json.dumps` caught the cycle
        itself and raised `ValueError: Circular reference detected`. Walking
        the document first would exhaust the stack instead and hand the caller
        a `RecursionError` -- a different exception, and a message that never
        names the cycle."""
        through_a_list = {"components": []}
        through_a_list["components"].append(through_a_list)
        onto_itself = {}
        onto_itself["metadata"] = onto_itself
        for document in (through_a_list, onto_itself):
            with self.subTest(document=type(document["components"][0])
                              if "components" in document else "self"):
                with self.assertRaises(ValueError) as capture:
                    sb.serialise(document)
                self.assertIn("Circular reference", str(capture.exception))

    def test_a_deeply_nested_document_still_serialises(self):
        """The ordering pass spends a Python frame per level before the C
        encoder runs, so the ceiling is lower than a plain recursive encoder's. The exact figure
        depends on the interpreter's recursion limit and is named in
        `_in_key_order`; what is pinned here is that ordinary depths -- far
        beyond anything a file tree produces -- are untouched."""
        deep = {"name": "leaf"}
        for _ in range(200):
            deep = {"components": [deep]}
        self.assertEqual(deep, json.loads(sb.serialise(deep)))

    def test_a_value_json_cannot_represent_is_never_folded(self):
        """`json.loads` accepts `NaN` and the infinities, and `json.dumps`
        emits them: the document was already unreadable by a strict reader,
        and that is older than this pass. What must not happen is a guard that
        announces it read the pair back as JSON and folded one anyway."""
        text = sb.serialise(
            {"components": [{"name": "x", "value": float("nan")}]})
        self.assertNotIn('{ "name"', text)
        self.assertIn("NaN", text)

    def test_the_source_of_the_order_is_named_and_dated(self):
        """A transcription whose provenance is not written down is a value
        nobody can re-check. The schema is versioned in no repository here."""
        self.assertIn("bom-1.7.schema.json", sb.SCHEMA_KEY_ORDER_SOURCE)
        self.assertIn("2026", sb.SCHEMA_KEY_ORDER_SOURCE)


# ---------------------------------------------------------------------------
# Two objects make up the tissue of the document, and each cost four lines
# ---------------------------------------------------------------------------
class TestTheDocumentFoldsItsTwoKeyObjects(_OrderBench):

    def test_a_property_and_a_hash_each_take_one_line(self):
        document = self._every_shape_of_document()["linked"]
        text = sb.serialise(document)
        self.assertIn(
            '{ "name": "unboxr:extractionOutcome", "value": "complete" }',
            text)
        self.assertRegex(text, r'\{ "alg": "SHA-256", "content": "[0-9a-f]+" \}')

    def test_no_object_of_another_shape_is_folded(self):
        """The criterion is the EXACT set of keys, never a resemblance of
        shape. The link has three keys and stays where it is."""
        document = self._every_shape_of_document()["linked"]
        text = sb.serialise(document)
        self.assertIn('"url": "' + GOOD_LINK + '",',
                      [line.strip() for line in text.splitlines()])
        self.assertNotIn('{ "url"', text)
        self.assertNotIn('{ "timestamp"', text)
        self.assertNotIn('{ "type": "file"', text)

    def test_a_two_key_object_whose_values_are_not_scalar_is_left_alone(self):
        """`serialise` is public and takes an arbitrary document. A window of
        four lines applied on the set of keys alone would break this one."""
        document = {"components": [{"name": {"deep": 1}, "value": [1, 2]}]}
        text = sb.serialise(document)
        self.assertNotIn('{ "name"', text)
        self.assertEqual(document, json.loads(text))

    def test_an_empty_container_is_not_a_scalar_either(self):
        document = {"components": [{"name": "x", "value": {}}]}
        text = sb.serialise(document)
        self.assertNotIn('{ "name"', text)
        self.assertEqual(document, json.loads(text))

    def test_the_folded_text_reads_back_to_exactly_the_same_object(self):
        """THE TEST THAT MATTERS MOST: it catches any escaping mistake the
        fold could make. A lone surrogate, a quote, a literal newline and a
        brace all go through the pass that reformats the text."""
        awkward = ("odd/" + chr(0xDCFF) + '/"quoted"/line\nbreak/'
                   "}/{/ends with brace }")
        document = {"components": [
            {"name": awkward, "value": awkward},
            {"alg": "SHA-256", "content": "ab" * 32},
        ]}
        text = sb.serialise(document)
        self.assertTrue(text.isascii())
        self.assertEqual(document, json.loads(text))

    def test_every_document_this_package_builds_reads_back_unchanged(self):
        for shape, document in self._every_shape_of_document().items():
            with self.subTest(shape=shape):
                self.assertEqual(document, json.loads(sb.serialise(document)))

    def test_the_gain_is_the_one_that_was_measured(self):
        """Measured on a FLAT zip of two files, which is the reference
        recipe: 58 lines before, 4 foldable objects, 46 lines after.

        THE THREE NUMBERS ARE LOW and the fold's share of the gain is small: the same document measured 189 -> 90 when every component
        carried five properties and `metadata` carried thirteen. What folding
        saves is proportional to how many two-key objects there are, and a
        document that writes a property only when something went wrong has
        almost none. The fold is kept because the objects it folds are still
        the tissue of a document with anomalies in it -- not because it still
        halves a clean one."""
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a"),
                                                    ("b.txt", "b")])
        _, document = self._document_of(archive)
        folded = sb.serialise(document).splitlines()
        unfolded = json.dumps(document, ensure_ascii=True, indent=2).splitlines()
        foldable = [o for o in self._objects_of(document)
                    if frozenset(o) in sb.FOLDED_KEY_SETS]
        recipe = ("measured on the FLAT two-file zip of the reference recipe; "
                  "a document with a link measures 65 -> 53. If a property "
                  "was added to the document, re-measure and update all three "
                  "numbers here -- do not relax the test")
        self.assertEqual(4, len(foldable), recipe)
        self.assertEqual(58, len(unfolded), recipe)
        self.assertEqual(46, len(folded), recipe)


# ---------------------------------------------------------------------------
# The calculated timestamp stops at the second it actually measures
# ---------------------------------------------------------------------------
class TestTheCalculatedTimestampStopsAtTheSecond(_OrderBench):

    def test_the_default_timestamp_carries_no_fraction_of_a_second(self):
        """The microsecond was taken when the document was BUILT, not when it
        was written, and nothing in an extraction is measured at that scale."""
        document = self._every_shape_of_document()["plain"]
        stamp = document["metadata"]["timestamp"]
        self.assertNotIn(".", stamp)
        self.assertTrue(stamp.endswith("+00:00"), stamp)

    def test_it_is_a_datetime_and_not_a_truncated_string(self):
        """A string cut at a fixed offset works until the shape moves, then
        writes a false date. The value has to survive being read back."""
        from datetime import datetime, timezone
        document = self._every_shape_of_document()["plain"]
        stamp = datetime.fromisoformat(document["metadata"]["timestamp"])
        self.assertEqual(0, stamp.microsecond)
        self.assertEqual(timezone.utc, stamp.tzinfo)

    def test_an_injected_timestamp_keeps_its_own_precision(self):
        """A caller who imposes a value imposes its shape too. Truncating it
        here would silently rewrite what the caller asked for."""
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        prepared = ux.prepare_source(str(archive), workspace=self.dir / "w")
        precise = "2026-09-13T00:00:00.123456+00:00"
        document = sb.build_document(
            prepared.report, prepared.tree, source=str(archive),
            source_digest=prepared.digest,
            timestamp=precise)
        self.assertEqual(precise, document["metadata"]["timestamp"])

class TestParentContainerSurvivesOnlyWhereThePathCannotSayIt(_Bench):
    """Design decision of 16 September 2026.

    The other three per-component properties were removed because the path
    states its own ancestry: a nested archive is flattened into a directory
    carrying its own name, so `outer.zip/inner.zip/a.c` says where it came
    from and each container it names is itself a component. A consumer reads
    the ancestry off the paths.

    THAT READING FAILS IN THREE CASES, and the ordinary one is a path through
    a PROVISIONAL extraction directory, whose name is a digest of a path and
    says nothing about what it holds. A consumer walking prefixes there finds
    no parent and would conclude there is NONE -- an *unknown* turned into a
    favourable answer, which is precisely what this project's rules forbid.

    So the property survives exactly there, with `not_determinable` as its
    only value, and the absence of the property is what says "read the path".
    """

    def test_a_path_through_a_provisional_directory_says_it_cannot_be_read(self):
        held = ux.new_report()
        provisional = "archive_" + "a" * ux.PROVISIONAL_DIGEST_LENGTH
        held.record(rp.EXTRACTION_KEPT_UNDER_PROVISIONAL_NAME,
                    provisional + "/code/aes.c", digest="b" * 64,
                    path_frame=rp.PATH_IS_TREE_RELATIVE)

        document = sb.build_document(held, None, source="p.zip")

        component = self._component(document, provisional + "/code/aes.c")
        self.assertEqual(sb.NOT_DETERMINABLE,
                         self._properties_of(component)[sb.PARENT_CONTAINER])

    def test_the_only_value_it_ever_takes_is_not_determinable(self):
        """Never the name of a real parent. Writing that would add a
        property repeating what the path says."""
        inner = self._zip_bytes([("code/aes.c", "int a;")])
        archive = self._zip_at(self.dir / "p.zip",
                               [("vendor/inner.zip", inner)])

        _, document = self._document_of(archive)

        written = [self._properties_of(c).get(sb.PARENT_CONTAINER)
                   for c in document["components"]]
        self.assertEqual([], [v for v in written
                              if v not in (None, sb.NOT_DETERMINABLE)])

    def test_an_ordinary_nested_file_carries_no_parent_at_all(self):
        """Its path states its ancestry and the container is a component of
        this document; a property saying it again would be the duplication
        this release exists to remove."""
        inner = self._zip_bytes([("code/aes.c", "int a;")])
        archive = self._zip_at(self.dir / "p.zip",
                               [("vendor/inner.zip", inner)])

        _, document = self._document_of(archive)

        leaf = self._component(document, "vendor/inner.zip/code/aes.c")
        self.assertNotIn(sb.PARENT_CONTAINER, self._properties_of(leaf))
        self.assertNotIn("properties", leaf)
        # What replaces it: the container really is here, so a consumer can
        # match the prefix against a component it can see.
        self.assertIn("vendor/inner.zip",
                      {c["name"] for c in document["components"]})


class TestTheSubjectNeverGoesSilentEither(_Bench):
    """The invariant applies to `metadata.component`, and it used not to.

    The guard reads the entry's digest; the subject wrote `source_digest`, a
    different value. On the CLI's failure branch that parameter is `None`,
    because `prepare_source` raised -- so the digest the report was holding
    never reached the document, and the subject came out with no `hashes`, no
    anomaly it could be caught on, and the type `data` that exempted it. Three
    ways of being silent at once, on the one run where the document matters
    most.
    """

    def test_a_refused_input_carries_its_digest_on_the_subject(self):
        refused = self.dir / "p.tar.zst"
        refused.write_bytes(ZSTD_MAGIC + b"undecodable")
        held = ux.new_report()
        try:
            ux.prepare_source(str(refused), self.dir / "w", held)
        except Exception:
            pass

        document = sb.build_document(held, None, source=str(refused),
                                     source_digest=None)

        subject = document["metadata"]["component"]
        from_the_report = [r.digest for r in held.not_opened if r.digest]
        self.assertEqual(1, len(from_the_report))
        self.assertEqual(from_the_report[0],
                         subject["hashes"][0]["content"],
                         "the digest the report was holding reaches the "
                         "document")
        self.assertEqual([rp.ZSTD_NOT_SUPPORTED], self._anomalies_of(subject))

    def test_a_refused_input_is_a_file_and_is_never_typed_data(self):
        """`data` is what says "the source was a directory" since `sourceKind`
        was removed. A refused archive is a regular file whose bytes were read
        and hashed; typing it `data` was a false statement, and one that now
        contradicts another part of the document."""
        refused = self.dir / "p.tar.zst"
        refused.write_bytes(ZSTD_MAGIC + b"undecodable")
        held = ux.new_report()
        try:
            ux.prepare_source(str(refused), self.dir / "w", held)
        except Exception:
            pass

        document = sb.build_document(held, None, source=str(refused),
                                     source_digest=None)

        self.assertEqual(sb.TYPE_FILE,
                         document["metadata"]["component"]["type"])


class TestTheInputContainerIsNamedByTheReportNotGuessed(_Bench):
    """Measured, not asserted in prose.

    The rule is the IDENTITY of the entry, never its rank, and never a string
    comparison with the source's bare name. Each of the inferences that looks
    obvious was measured false, and each dropped a component and its digest in
    silence.
    """

    def test_a_directory_holding_a_file_of_its_own_name_keeps_that_file(self):
        """`LICENSE/LICENSE` is the everyday shape of this. Comparing the path
        to the source's bare name deleted the file AND its digest, with no
        anomaly and no trace -- the amputation this document exists to make
        visible, made invisible."""
        source = self.dir / "tools"
        source.mkdir()
        (source / "tools").write_text("the real content")
        (source / "other.txt").write_text("x")
        prepared = ux.prepare_source(str(source))

        document = sb.build_document(prepared.report, prepared.tree,
                                     source=str(source),
                                     source_digest=prepared.digest)

        component = self._component(document, "tools")
        self.assertEqual(self._digest_of(b"the real content"),
                         component["hashes"][0]["content"])

    def test_an_archive_holding_an_entry_of_its_own_name_keeps_them_apart(self):
        """Two files, one string. The archive is the subject; the entry is a
        component of its own. Merging them attributed the ENTRY's
        `extraction_failed` to the ARCHIVE, so the document claimed a container
        it had just opened successfully could not be read."""
        decoy = b"a decoy that is not an archive at all"
        archive = self._zip_at(self.dir / "p.zip",
                               [("p.zip", decoy), ("a.txt", "a")])
        prepared, document = self._document_of(archive)

        subject = document["metadata"]["component"]
        self.assertEqual("p.zip", subject["name"])
        self.assertEqual([], self._anomalies_of(subject),
                         "the archive was opened: it carries no anomaly, and "
                         "certainly not one belonging to its own content")
        entry = self._component(document, "p.zip")
        self.assertEqual(self._digest_of(decoy),
                         entry["hashes"][0]["content"])
        self.assertIn(rp.EXTRACTION_FAILED, self._anomalies_of(entry))

    def test_the_rule_is_the_identity_and_never_the_rank(self):
        """An archive whose name sorts AFTER everything it contains. If the
        rule were "the first component", this document would lose a file
        instead of the input."""
        archive = self._zip_at(self.dir / "zzz.zip",
                               [("aaa.txt", "a"), ("bbb.txt", "b")])
        _, document = self._document_of(archive)

        self.assertEqual("zzz.zip", document["metadata"]["component"]["name"])
        self.assertEqual({"aaa.txt", "bbb.txt"},
                         {c["name"] for c in document["components"]})


class TestEveryDigestOfANestedChainSurvives(_Bench):
    """The DIGESTS, at two levels, not just the names.

    A container the flattening destroyed can be hashed at exactly one instant,
    and no walk of the finished tree can find it again. The two-level test
    asserted names and prefixes; the digest assertion lived only in the
    one-level test, so the deeper half of the rule was held by nothing.
    """

    def test_a_two_level_nesting_carries_three_digests(self):
        deepest = self._zip_bytes([("code/aes.c", "int a;")])
        middle = self._zip_bytes([("inner.zip", deepest)])
        archive = self._zip_at(self.dir / "p.zip", [("outer.zip", middle)])

        _, document = self._document_of(archive)

        expected = {
            "outer.zip": self._digest_of(middle),
            "outer.zip/inner.zip": self._digest_of(deepest),
            "outer.zip/inner.zip/code/aes.c": self._digest_of(b"int a;"),
        }
        for name, digest in expected.items():
            with self.subTest(name=name):
                component = self._component(document, name)
                self.assertEqual(digest, component["hashes"][0]["content"])


class TestTheSevenZipBannerIsReadOrRefused(_Bench):
    """The other half of the tool entry. The tool entry was tested; the reading was not.

    A fabricated version is worse than a missing one: `version` is optional and
    the entry is written without it, so `None` was always the available and
    correct degraded answer.
    """

    def test_a_line_that_does_not_name_the_product_yields_nothing(self):
        """Measured cases, both plausible: a dynamic loader warning and a
        wrapper preamble. Unanchored, the first dotted number of the first five
        lines won, and `6.0` or `1.8` went into the document as a 7-Zip
        version."""
        for line in ("warning: libstdc++.so.6.0.25 not found, falling back",
                     "Java HotSpot 1.8 wrapper",
                     "Loading configuration 2.4 from /etc"):
            with self.subTest(line=line):
                self.assertIsNone(ux._SEVEN_ZIP_BANNER.search(line))

    def test_the_transcribed_banners_each_yield_their_own_version(self):
        for line, expected in (
                ("7-Zip 23.01 (x64) : Copyright (c) 1999-2023", "23.01"),
                ("7-Zip (z) 21.07 (x64) : Copyright", "21.07"),
                ("7-Zip [64] 16.02 : Copyright (c) 1999-2016", "16.02"),
                ("p7zip Version 16.02 (locale=en_US)", "16.02"),
                ("7-Zip [64] 9.20.1 : Copyright", "9.20.1")):
            with self.subTest(line=line):
                self.assertTrue(ux._SEVEN_ZIP_BANNER.search(line))
                self.assertEqual(
                    expected, ux._SEVEN_ZIP_VERSION.search(line).group(1),
                    "a three-component version is not truncated to two")

    def test_a_binary_that_cannot_be_run_says_nothing_and_never_raises(self):
        self.assertIsNone(
            ux.seven_zip_version(str(self.dir / "no-such-7zz.exe")))


class TestTheToolIsRecordedOnlyWhenItReallyRan(_Bench):
    """End to end. The fact and its projection were tested apart -- one
    test set the field by hand, the other read it -- so nothing held the wiring
    that puts the two together."""

    def test_a_binary_that_never_started_is_not_recorded_as_a_producer(self):
        held = ux.new_report()
        with self.assertRaises(Exception):
            ux.extract_with_7zip(self.dir / "x.7z", self.dir / "out",
                                 str(self.dir / "no-such-7zz.exe"),
                                 report=held)

        self.assertIsNone(held.seven_zip_used,
                          "nothing ran, so nothing produced this document")
        document = sb.build_document(held, None, source="x.7z")
        self.assertEqual(["unboxr"],
                         [t["name"] for t in
                          document["metadata"]["tools"]["components"]])


class TestTheReadmeExamplesStillCallTheRealSignature(_Bench):
    """A README example that passes a keyword the signature does not accept
    raises `TypeError` for anyone who types what it says.

    The ratchet that compares the README's PROPERTY NAMES against the code
    never looks at the code blocks, so this one does.
    """

    def test_every_keyword_the_readme_passes_exists_in_the_signature(self):
        import inspect
        import re as _re
        readme = (Path(__file__).resolve().parent.parent
                  / "README.md").read_text(encoding="utf-8")
        accepted = set(inspect.signature(sb.build_document).parameters)

        calls = _re.findall(r"build_document\((.*?)\)", readme, _re.DOTALL)
        self.assertTrue(calls, "the README is expected to show the call")
        for call in calls:
            for keyword in _re.findall(r"(\w+)\s*=", call):
                with self.subTest(keyword=keyword):
                    self.assertIn(keyword, accepted)


if __name__ == "__main__":
    unittest.main(verbosity=2)
