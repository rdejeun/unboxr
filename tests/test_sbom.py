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
                + list(report.still_in_tree) + list(report.widened))

    def _properties_of(self, component) -> dict:
        return {p["name"]: p["value"] for p in component["properties"]}

    def _component(self, document, name: str):
        found = [c for c in document["components"] if c["name"] == name]
        self.assertEqual(1, len(found), "expected exactly one component " + name)
        return found[0]

    def _document_of(self, archive: Path, workspace=None):
        workspace = workspace or self.dir / "w"
        prepared = ux.prepare_source(str(archive), workspace=workspace)
        return prepared, sb.build_document(
            prepared.report, prepared.tree, source=str(archive),
            source_digest=prepared.digest, source_kind=sb.SOURCE_IS_ARCHIVE)

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
        (destination / "extracted").mkdir(parents=True)
        (destination / "extracted" / "left-over.txt").write_text("x")
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
        self.assertEqual(sb.DIGEST_COMPUTED,
                         self._properties_of(subject)[sb.DIGEST_STATE])

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
                                     source_digest=prepared.digest,
                                     source_kind=sb.SOURCE_IS_DIRECTORY)

        subject = document["metadata"]["component"]
        self.assertNotIn("hashes", subject)
        self.assertEqual(sb.DIGEST_NOT_A_FILE,
                         self._properties_of(subject)[sb.DIGEST_STATE])

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

        THE CASING, one of the four points the spike left open (AC-1.4),
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
        properties = self._properties_of(component)
        self.assertEqual(rp.NESTED_CONTAINER_OPENED, properties[sb.CAUSE_CODE])
        self.assertEqual("1", properties[sb.NESTING_LEVEL])
        self.assertEqual(sb.NONE_VALUE, properties[sb.PARENT_CONTAINER])

    def test_a_container_nested_two_deep_names_the_container_it_came_out_of(self):
        """The parent is read off the path, which works because a nested
        archive is flattened into a directory carrying its own name verbatim.
        It is matched against what was actually opened, never guessed from a
        list of extensions."""
        deepest = self._zip_bytes([("code/aes.c", "int a;")])
        middle = self._zip_bytes([("inner.zip", deepest)])
        archive = self._zip_at(self.dir / "p.zip", [("outer.zip", middle)])

        _, document = self._document_of(archive)

        component = self._component(document, "outer.zip/inner.zip")
        properties = self._properties_of(component)
        self.assertEqual("outer.zip", properties[sb.PARENT_CONTAINER])
        self.assertEqual("2", properties[sb.NESTING_LEVEL])
        leaf = self._component(document, "outer.zip/inner.zip/code/aes.c")
        self.assertEqual("outer.zip/inner.zip",
                         self._properties_of(leaf)[sb.PARENT_CONTAINER])

    def test_an_empty_file_is_inventoried_with_the_digest_of_no_bytes(self):
        """Not a theoretical case: a plain decompression that fails leaves an
        EMPTY file in the tree. Inventorying it is not fixing it -- the defect
        is recorded as a debt of its own -- but a document that skipped it
        would hide an artefact of failure."""
        archive = self._zip_at(self.dir / "p.zip", [("empty.txt", b"")])
        _, document = self._document_of(archive)
        component = self._component(document, "empty.txt")
        self.assertEqual(self._digest_of(b""), component["hashes"][0]["content"])
        self.assertEqual(sb.DIGEST_COMPUTED,
                         self._properties_of(component)[sb.DIGEST_STATE])

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
        self.assertEqual(sb.DIGEST_READ_FAILED,
                         self._properties_of(component)[sb.DIGEST_STATE])
        metadata = {p["name"]: p["value"]
                    for p in document["metadata"]["properties"]}
        self.assertEqual("1", metadata[sb.FILES_WITHOUT_DIGEST])

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
                           sb.DIGEST_SYMLINK_NOT_FOLLOWED)], found)

    def test_a_special_node_is_inscribed_not_silently_skipped(self):
        """A FIFO, a socket, a device node: not a directory, not a symlink,
        not a regular file. `unboxr` applies NO exclusion policy -- the walk
        used to fall through `is_file()` being false straight to the next
        path, with nothing written anywhere. Review of story 14.4. A stub
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

        self.assertEqual([("pipe", None, sb.DIGEST_NOT_A_FILE)], found)

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

        document = sb.build_document(held, root, source="p.zip",
                                     source_kind=sb.SOURCE_IS_ARCHIVE)

        component = self._component(document, "refused.tar.zst")
        properties = self._properties_of(component)
        self.assertEqual(rp.ZSTD_NOT_SUPPORTED, properties[sb.CAUSE_CODE])
        self.assertEqual(rp.text_for(rp.ZSTD_NOT_SUPPORTED),
                         properties[sb.CAUSE_TEXT])

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

        document = sb.build_document(held, root, source="p.zip",
                                     source_kind=sb.SOURCE_IS_ARCHIVE)

        component = self._component(document, "payload.rar")
        self.assertEqual(rp.SEVEN_ZIP_BINARY_MISSING,
                         self._properties_of(component)[sb.CAUSE_CODE])

    def test_a_container_still_in_the_tree_is_inventoried_exactly_once(self):
        """It was never opened, so it is still a file the walk would find --
        and it is also a report entry. One component, not two: the identity of
        a component is the PATH."""
        root = self._tree()
        (root / "refused.tar.zst").write_bytes(ZSTD_MAGIC + b"undecodable")
        held = ux.new_report()
        ux.flatten_nested_archives(root, report=held)

        document = sb.build_document(held, root, source="p.zip",
                                     source_kind=sb.SOURCE_IS_ARCHIVE)

        matching = [c for c in document["components"]
                    if c["name"] == "refused.tar.zst"]
        self.assertEqual(1, len(matching))
        names = [c["name"] for c in document["components"]]
        self.assertEqual(len(names), len(set(names)))

    def test_the_document_carries_the_size_of_the_amputation(self):
        """A reader must be able to measure what is missing without counting
        the entries by hand."""
        root = self._tree()
        (root / "a.tar.zst").write_bytes(ZSTD_MAGIC + b"one")
        (root / "b.tar.zst").write_bytes(ZSTD_MAGIC + b"two")
        held = ux.new_report()
        ux.flatten_nested_archives(root, report=held)

        document = sb.build_document(held, root, source="p.zip",
                                     source_kind=sb.SOURCE_IS_ARCHIVE)

        metadata = {p["name"]: p["value"]
                    for p in document["metadata"]["properties"]}
        self.assertEqual("2", metadata[sb.CONTAINERS_NOT_OPENED])

    def test_a_cause_code_from_another_version_degrades_by_naming_itself(self):
        """A code this version does not know is not a reason to fail the
        document, and it is not "nothing to report" either. Three states."""
        held = ux.new_report()
        held.record.__func__(held, rp.NESTED_CONTAINER_OPENED, "a.zip")
        held.opened[0] = rp.ContainerRecord(
            code="a_code_from_the_future", path="a.zip",
            path_frame=rp.PATH_IS_TREE_RELATIVE)

        document = sb.build_document(held, None, source="p.zip",
                                     source_kind=sb.SOURCE_IS_ARCHIVE)

        properties = self._properties_of(self._component(document, "a.zip"))
        self.assertEqual("a_code_from_the_future", properties[sb.CAUSE_CODE])
        self.assertIn("unknown cause code", properties[sb.CAUSE_TEXT])


# ---------------------------------------------------------------------------
# One component per PATH, never one per report entry
# ---------------------------------------------------------------------------
class TestOneComponentPerPath(_Bench):

    def test_a_path_carrying_several_causes_keeps_all_of_them_in_order(self):
        """A container opened and then kept is the ordinary case of one path
        with two causes. None is chosen at the expense of another, and the
        texts follow the same order as the codes."""
        held = ux.new_report()
        held.record(rp.NESTED_CONTAINER_OPENED, "a.zip",
                    path_frame=rp.PATH_IS_TREE_RELATIVE)
        held.record(rp.ARCHIVE_KEPT_AFTER_SUCCESSFUL_EXTRACTION, "a.zip",
                    path_frame=rp.PATH_IS_TREE_RELATIVE)

        document = sb.build_document(held, None, source="p.zip",
                                     source_kind=sb.SOURCE_IS_ARCHIVE)

        properties = self._properties_of(self._component(document, "a.zip"))
        codes = properties[sb.CAUSE_CODE].split(", ")
        self.assertEqual([rp.NESTED_CONTAINER_OPENED,
                          rp.ARCHIVE_KEPT_AFTER_SUCCESSFUL_EXTRACTION], codes)
        self.assertEqual([rp.text_for(code) for code in codes],
                         properties[sb.CAUSE_TEXT].split(" | "))

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

        document = sb.build_document(held, root, source="p.zip",
                                     source_kind=sb.SOURCE_IS_ARCHIVE)

        component = self._component(document, "b.zip")
        self.assertEqual(self._digest_of(b"the real file in the tree"),
                         component["hashes"][0]["content"],
                         "the digest of the file that is ACTUALLY there must "
                         "win over one carried by a record that could not be "
                         "placed in the tree")
        # THE COMPROMISE, STATED RATHER THAN HIDDEN. A component is identified
        # by its path, so the foreign cause lands on this one: the only two
        # alternatives are dropping the file -- the silent amputation -- and
        # two components sharing one name, which the identity rule forbids.
        # What matters is that the FILE keeps its own digest, and it does.
        self.assertEqual(rp.ARCHIVE_OUTSIDE_THE_ANALYSED_ROOT,
                         self._properties_of(component)[sb.CAUSE_CODE])

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

        document = sb.build_document(held, root, source="p.zip",
                                     source_kind=sb.SOURCE_IS_ARCHIVE)

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

        document = sb.build_document(held, root, source="p.zip",
                                     source_kind=sb.SOURCE_IS_ARCHIVE)

        self.assertEqual(
            taken_during,
            self._component(document, "a.txt")["hashes"][0]["content"],
            "a tree-relative path is confrontable: the walk leaves it alone "
            "and the digest taken during the extraction stands")
        self.assertEqual(
            self._digest_of(b"the real b"),
            self._component(document, "b.txt")["hashes"][0]["content"],
            "a bare name excludes nothing: the file that is really there was "
            "walked, and it keeps its own digest")

    def test_a_component_name_is_the_full_relative_path_not_the_base_name(self):
        """`name` is one of the two required fields of a component -- one of
        the four points the spike left open (AC-1.4), RE-CHECKED against the
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
        """A reference is derived from the RANK, not from the path: a later
        story places it after a `#` in a URN, where a path would bring
        characters to escape. The consequence is that a reference is only
        valid against THIS document -- one file entering or leaving the corpus
        renumbers everything."""
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

    def test_every_property_is_emitted_even_when_its_value_is_not_computable(self):
        """AN OMISSION ASSERTS. A property that only appeared in the favourable
        case would read, by its absence, as "not applicable" rather than "not
        determined" -- and the two are not the same fact.

        The equality below (not a subset check) is also where the LAST of the
        four points the spike left open (AC-1.4) is proven: WHERE A PROPERTY
        IS ADMITTED, read from the schema on 13 September 2026,
        `definitions.component.additionalProperties` is `false` -- a
        component's `properties` array holds these five names and no other,
        so asserting the set is EQUAL to the declared table (never merely a
        superset of it) is what stands in for that schema constraint here,
        `jsonschema` itself being out of reach of this suite.

        The run under test is the worst one available: a directory source, so
        there is no depth to report, and nothing was extracted."""
        source = self.dir / "given"
        source.mkdir()
        (source / "a.txt").write_text("a")
        prepared = ux.prepare_source(str(source))

        document = sb.build_document(prepared.report, prepared.tree,
                                     source=str(source),
                                     source_digest=prepared.digest,
                                     source_kind=sb.SOURCE_IS_DIRECTORY)

        emitted = {p["name"] for p in document["metadata"]["properties"]}
        self.assertEqual(set(sb.METADATA_PROPERTY_NAMES), emitted)
        for component in document["components"]:
            with self.subTest(name=component["name"]):
                self.assertEqual(set(sb.COMPONENT_PROPERTY_NAMES),
                                 {p["name"] for p in component["properties"]})

    def test_a_property_value_is_always_a_string_even_when_it_is_a_number(self):
        """The schema says a property value is a string. Numbers are converted
        here, explicitly, rather than left to a serialiser to decide."""
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        _, document = self._document_of(archive)
        everywhere = list(document["metadata"]["properties"])
        for component in document["components"]:
            everywhere.extend(component["properties"])
        everywhere.extend(document["metadata"]["component"]["properties"])
        for entry in everywhere:
            with self.subTest(name=entry["name"]):
                self.assertIsInstance(entry["value"], str)

    def test_the_depth_of_a_directory_run_is_not_applicable_and_never_zero(self):
        """`prepare_source` returns a directory as it is: no flattening happens
        at all. Writing `0` would assert a measurement that was never taken."""
        source = self.dir / "given"
        source.mkdir()
        (source / "a.txt").write_text("a")
        prepared = ux.prepare_source(str(source))

        document = sb.build_document(prepared.report, prepared.tree,
                                     source=str(source),
                                     source_digest=prepared.digest,
                                     source_kind=sb.SOURCE_IS_DIRECTORY)

        metadata = {p["name"]: p["value"]
                    for p in document["metadata"]["properties"]}
        self.assertEqual(sb.NOT_APPLICABLE, metadata[sb.DEPTH_REACHED])
        self.assertEqual(sb.NOT_APPLICABLE, metadata[sb.DEPTH_LIMIT])
        self.assertEqual(sb.SOURCE_IS_DIRECTORY, metadata[sb.SOURCE_KIND])

    def test_the_document_declares_that_this_package_excludes_nothing(self):
        """Whether `__pycache__` or `node_modules` belong in an analysed corpus
        is the consumer policy, applied after extraction. Saying so out loud
        beats leaving it to be discovered."""
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        _, document = self._document_of(archive)
        metadata = {p["name"]: p["value"]
                    for p in document["metadata"]["properties"]}
        self.assertEqual(sb.NO_EXCLUSION, metadata[sb.EXCLUSION_POLICY])

    def test_the_capability_of_the_machine_is_declared_without_its_path(self):
        """`NFR` of the consumer aside, the fact matters: two machines, one
        archive, two corpora. The BINARY PATH does not get in -- it differs
        from one machine to the next and would reopen a divergence in a
        document meant to be compared. Availability answers the question."""
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        _, document = self._document_of(archive)
        metadata = {p["name"]: p["value"]
                    for p in document["metadata"]["properties"]}
        self.assertIn(metadata[sb.SEVEN_ZIP_AVAILABLE], ("true", "false"))
        profile = ux.probe_capability_profile()
        self.assertEqual(str(profile.recognised_extensions),
                         metadata[sb.RECOGNISED_EXTENSIONS])
        self.assertEqual(str(profile.extensions_needing_seven_zip),
                         metadata[sb.EXTENSIONS_NEEDING_SEVEN_ZIP])
        if profile.seven_zip_binary:
            self.assertNotIn(profile.seven_zip_binary, sb.serialise(document))


# ---------------------------------------------------------------------------
# What the document warns about, and what it must never warn about
# ---------------------------------------------------------------------------
class TestTheWarningsTheDocumentCarries(_Bench):

    def test_the_document_says_what_it_does_not_prove(self):
        """A TECHNICAL caveat, about this document and nothing else: it does
        not claim anything about what is absent from it, and it carries no
        verdict."""
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        _, document = self._document_of(archive)
        metadata = {p["name"]: p["value"]
                    for p in document["metadata"]["properties"]}
        scope = metadata[sb.DOCUMENT_SCOPE]
        self.assertIn("attests NOTHING about anything absent from it", scope)
        self.assertIn("no verdict of any kind", scope)

    def test_the_oracle_reminder_is_read_from_its_one_constant(self):
        """Read, never retyped. It used to exist only as prose in a docstring
        and as a logging format string beginning with a placeholder -- neither
        of which a document can reuse."""
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        _, document = self._document_of(archive)
        metadata = {p["name"]: p["value"]
                    for p in document["metadata"]["properties"]}
        self.assertEqual(rp.ORACLE_REMINDER_SENTENCE, metadata[sb.ORACLE_REMINDER])
        self.assertNotIn("%s", metadata[sb.ORACLE_REMINDER])

    def test_the_command_composes_its_reminder_on_that_same_constant(self):
        """One sentence, one home. The counting prefix is a logging concern and
        has no place in a document."""
        from unboxr import cli
        self.assertTrue(cli.ORACLE_REMINDER.endswith(rp.ORACLE_REMINDER_SENTENCE))
        self.assertTrue(cli.ORACLE_REMINDER.startswith("%s"))

    def test_no_scope_warning_of_the_consumer_ever_reaches_the_document(self):
        """Checked POSITIVELY. This package mints no verdict, so the two scope
        warnings a verdict-bearing document owes have no object here -- and the
        vocabulary that carries them must not appear either."""
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        _, document = self._document_of(archive)
        text = sb.serialise(document)
        for token in ("non-standard cryptography", "ECCN", "772.1", "742.15",
                      "cryptographic-asset", "revue_humaine", "CBOM",
                      "phase1", "phase2"):
            with self.subTest(token=token):
                self.assertNotIn(token, text)


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

    def test_the_two_volatile_fields_are_named_in_the_document_itself(self):
        """Making them comparable is another story. Declaring them is this
        one: an omission would assert that they are stable."""
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])
        _, document = self._document_of(archive)
        metadata = {p["name"]: p["value"]
                    for p in document["metadata"]["properties"]}
        self.assertEqual("serialNumber, metadata.timestamp",
                         metadata[sb.VOLATILE_FIELDS])

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
        produced afterwards, with nothing to say so."""
        import inspect
        source = inspect.getsource(sb.serialise)
        for parameter in ("ensure_ascii=True", "indent=2", "sort_keys=True"):
            with self.subTest(parameter=parameter):
                self.assertIn(parameter, source)

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
        self.assertTrue(out.strip().endswith("extracted"))

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
        self.assertEqual(rp.ZSTD_NOT_SUPPORTED,
                         self._properties_of(
                             self._component(document, "p.tar.zst"))[sb.CAUSE_CODE])
        for component in document["components"]:
            with self.subTest(name=component["name"]):
                self.assertNotEqual(sb.NO_ENTRY,
                                    self._properties_of(component)[sb.CAUSE_CODE],
                                    "no file component: there was no tree")

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
        self.assertEqual(sb.SOURCE_IS_DIRECTORY, metadata[sb.SOURCE_KIND])
        self.assertEqual(sb.OUTCOME_COMPLETE, metadata[sb.EXTRACTION_OUTCOME])
        self.assertEqual(sb.NOT_APPLICABLE, metadata[sb.DEPTH_REACHED])
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
                                         source_digest=prepared.digest,
                                         source_kind=sb.SOURCE_IS_ARCHIVE)

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
            "--sbom", str(destination / "extracted" / "sbom.json")])

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
        exist: `--sbom` may not name the archive it is documenting. Review of
        story 14.4 -- unguarded, `--sbom` pointed at the source silently
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
        rather than probing existence. Review of story 14.4."""
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
        against the wrong tree without saying so. Review of story 14.4:
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
        disguised = destination / "extracted" / ".." / "extracted" / "sbom.json"

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
        self.assertTrue(out.strip().endswith("extracted"),
                        "the extraction is not lost because a write failed")


class TestADirectoryPathIsNeverCalledAFile(_Bench):

    def test_a_recorded_path_that_names_a_directory_is_not_typed_as_a_file(self):
        """CycloneDX closes its component types at thirteen values and none of
        them is "directory" -- read from the schema on 13 September 2026. Typing
        one `file` would be a false statement in a document meant as evidence;
        it is typed `data`, the one value that asserts a collection rather than
        a single file or a piece of software. What actually tells it apart is
        `unboxr:digestState`, which says `not_a_file` and is always emitted."""
        destination = self.dir / "w"
        (destination / "extracted").mkdir(parents=True)
        (destination / "extracted" / "left-over.txt").write_text("x")
        archive = self._zip_at(self.dir / "p.zip", [("a.txt", "a")])

        _, document = self._document_of(archive, workspace=destination)

        component = self._component(document, "extracted")
        self.assertEqual(sb.TYPE_NOT_A_FILE, component["type"])
        self.assertNotEqual(sb.TYPE_FILE, component["type"])
        self.assertNotIn("hashes", component)
        properties = self._properties_of(component)
        self.assertEqual(sb.DIGEST_NOT_A_FILE, properties[sb.DIGEST_STATE])
        self.assertEqual(rp.DESTINATION_ALREADY_OCCUPIED,
                         properties[sb.CAUSE_CODE],
                         "its cause is never lost: that is the constraint that "
                         "decided between the two honest ways of writing it")


class TestAFileThatWasNeverADirectoryIsNeverCalledOne(_Bench):
    """Review of story 14.4. `DESTINATION_ALREADY_OCCUPIED` is the ONE report
    code no call site ever hashes, because its recorded path IS a directory.
    Every other digest-less record names something that WAS a file: typing it
    `not_a_file` was the false statement AC-1.9 forbids for the wrong reason."""

    def test_a_record_whose_digest_could_not_be_taken_is_a_read_failure_not_a_non_file(self):
        held = ux.new_report()
        held.record(rp.NESTED_CONTAINER_OPENED, "vendor/inner.zip",
                    path_frame=rp.PATH_IS_TREE_RELATIVE)  # digest=None: a read
                                                          # that failed, not a
                                                          # directory

        document = sb.build_document(held, self._tree(), source="p.zip",
                                     source_kind=sb.SOURCE_IS_ARCHIVE)

        component = self._component(document, "vendor/inner.zip")
        self.assertEqual(sb.TYPE_FILE, component["type"],
                         "a container that was hashed and destroyed is a "
                         "file, even when its digest could not be taken")
        self.assertEqual(sb.DIGEST_READ_FAILED,
                         self._properties_of(component)[sb.DIGEST_STATE])

    def test_a_container_already_gone_by_the_time_this_ran_is_a_read_failure_too(self):
        """`EXTRACTION_KEPT_UNDER_PROVISIONAL_NAME` is recorded with no digest
        by design: `archive.unlink()` already succeeded (`extraction.py`), so
        the file is gone. It was never a directory."""
        held = ux.new_report()
        held.record(rp.EXTRACTION_KEPT_UNDER_PROVISIONAL_NAME, "archive_deadbeef",
                    path_frame=rp.PATH_IS_TREE_RELATIVE)

        document = sb.build_document(held, self._tree(), source="p.zip",
                                     source_kind=sb.SOURCE_IS_ARCHIVE)

        component = self._component(document, "archive_deadbeef")
        self.assertEqual(sb.TYPE_FILE, component["type"])
        self.assertEqual(sb.DIGEST_READ_FAILED,
                         self._properties_of(component)[sb.DIGEST_STATE])


class TestATreeThatCannotBeWalkedFailsRatherThanLies(_Bench):
    """Review of story 14.4. Swallowing the walk's own `OSError` used to
    produce a document declaring `extractionOutcome=complete` with zero file
    components: the very amputation this document exists to make visible,
    left completely unnamed."""

    def test_an_unwalkable_tree_raises_instead_of_producing_an_empty_complete_document(self):
        held = ux.new_report()
        held.record(rp.INPUT_CONTAINER_OPENED, "p.zip", digest=self._digest_of(b"x"))

        with self.assertRaises(OSError):
            sb.build_document(held, self.dir / "does" / "not" / "exist",
                              source="p.zip", source_kind=sb.SOURCE_IS_ARCHIVE)


class TestASignedURLNeverLeaksIntoTheDocument(_Bench):
    """Review of story 14.4. A raw split on `/` kept a URL's query string --
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


class TestDepthIsNeverAMeasurementThatWasNeverTaken(_Bench):
    """Review of story 14.4. `report.depth_reached` defaults to `0`, not
    `None`: on the failure path, where flattening never starts, that default
    used to read as a genuine "stopped at level 0" instead of "never ran".
    `depth_limit` is the reliable signal -- it is set, together with
    `depth_reached`, at the very first line of `flatten_nested_archives`."""

    def test_depth_reached_is_unknown_not_zero_when_flattening_never_started(self):
        held = ux.new_report()
        held.record(rp.EXTRACTION_FAILED, "not_an_archive.zip")
        # depth_limit and depth_reached both untouched: their dataclass
        # defaults, exactly the state of a report handed back by a
        # `prepare_source` that raised before flattening began.

        document = sb.build_document(held, None, source="not_an_archive.zip",
                                     source_kind=sb.SOURCE_UNDETERMINED)

        properties = {p["name"]: p["value"]
                     for p in document["metadata"]["properties"]}
        self.assertEqual(sb.UNKNOWN, properties[sb.DEPTH_REACHED])
        self.assertEqual(sb.UNKNOWN, properties[sb.DEPTH_LIMIT])

    def test_depth_reached_zero_is_still_reported_when_flattening_genuinely_ran(self):
        held = ux.new_report()
        held.depth_limit = 10
        held.depth_reached = 0

        document = sb.build_document(held, self._tree(), source="p.zip",
                                     source_kind=sb.SOURCE_IS_ARCHIVE)

        properties = {p["name"]: p["value"]
                     for p in document["metadata"]["properties"]}
        self.assertEqual("0", properties[sb.DEPTH_REACHED])
        self.assertEqual("10", properties[sb.DEPTH_LIMIT])


class TestContainersNotOpenedCountsComponentsNotRecords(_Bench):
    """Review of story 14.4. `report.amputation_count()` counts RECORDS
    (`len(report.not_opened)`), and AC-4.1 lets one path carry several codes
    without becoming several components: a container refused for two reasons
    at once used to make this number exceed the actual not-opened components
    in `components`."""

    def test_two_causes_on_one_path_are_counted_once(self):
        held = ux.new_report()
        held.record(rp.TAR_REFUSED_BY_SECURITY_FILTER, "a.tar")
        held.record(rp.TAR_CONTENT_PARTLY_MOVED, "a.tar")
        self.assertEqual(2, len(held.not_opened), "two records, as expected")

        document = sb.build_document(held, self._tree(), source="p.zip",
                                     source_kind=sb.SOURCE_IS_ARCHIVE)

        properties = {p["name"]: p["value"]
                     for p in document["metadata"]["properties"]}
        not_opened_components = [c for c in document["components"]
                                 if c["name"] == "a.tar"]
        self.assertEqual(1, len(not_opened_components),
                         "one component: AC-4.1's identity rule")
        self.assertEqual(str(len(not_opened_components)),
                         properties[sb.CONTAINERS_NOT_OPENED],
                         "the amplitude of the amputation matches what the "
                         "components array actually shows")


class TestACauseOrderNeverDependsOnFillOrder(_Bench):
    """Review of story 14.4, AC-7.3: "aucun test ne le tient... s'y fier
    serait s'appuyer sur une propriete non garantie." Two reports that file
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
        doc_forward = sb.build_document(forward, tree_a, source="p.zip",
                                        source_kind=sb.SOURCE_IS_ARCHIVE)
        doc_backward = sb.build_document(backward, tree_b, source="p.zip",
                                         source_kind=sb.SOURCE_IS_ARCHIVE)

        code_forward = self._properties_of(
            self._component(doc_forward, "a.tar"))[sb.CAUSE_CODE]
        code_backward = self._properties_of(
            self._component(doc_backward, "a.tar"))[sb.CAUSE_CODE]
        self.assertEqual(code_forward, code_backward)


class TestAHashIsNeverTakenForARecordThatWillBeDiscarded(_Bench):
    """Review of story 14.4. `_record` used to hash BEFORE the report's own
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
