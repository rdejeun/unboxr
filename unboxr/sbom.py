"""The corpus, as a document that outlives the run.

WHY THIS EXISTS. `unboxr.report` is a Python object: it lives exactly as long
as the process that built it. Someone who has to prove, months later, which
files a downstream conclusion rested on has nothing to open. This module
projects that report -- and the tree it goes with -- onto a CycloneDX 1.7
document, so the corpus stops being an assertion and becomes a record.

WHAT IT ATTESTS, AND WHAT IT DOES NOT. It attests that the files it lists were
there when the run finished, and it attests their SHA-256 digests. On the
CORPUS the oracle is positive only: the document says NOTHING about what was
inside a container nobody opened. It renders no verdict of any kind, and none
may be read into it.

ON THE ANOMALIES IT PROMISES THE OPPOSITE, and that is what 3.0 changed. Every
abnormal event this package can observe is written here, so a component with no
properties is not a silence -- it says nothing abnormal happened to that path.
The promise is bounded by what is observable at a boundary this package
crosses, and the README names that bound rather than letting a reader assume it
away.

WHY A MODULE OF ITS OWN, AND NOT MORE OF `unboxr.report`. That module is the
DATA -- the vocabulary of causes, the filing rules, the capability profile. A
CycloneDX document is a PROJECTION of that data, with a vocabulary of its own
and a dependency on a published schema. Merging the two would make the data
contract an annexe of one output format.

IMPORT DIRECTION: `report` <- `extraction` <- `sbom` <- `cli`. This module never
imports `cli`, which imports `extraction`; the reverse would be a cycle.

TWO PLACES SUPPLY THE DIGESTS, AND THE DIVIDING LINE IS THE SURVIVAL OF THE
OBJECT. A container that is OPENED is destroyed by the flattening, so the
instant it is recorded is the only one at which it can be hashed -- its digest
comes from the report, taken DURING the extraction. An ordinary extracted file
is still there at the end, and is hashed by walking the finished tree. Reading
the first rule as forbidding the walk would mean recording tens of thousands of
files one by one while they are all still present; reading it as mere
convenience would lose every container the flattening consumed.

THIS MODULE WRITES NOTHING BY ITSELF. `build_document` RETURNS a structure;
`write_document` is a separate gesture a caller has to ask for. A function that
cannot write cannot write by accident, which is how the library stays silent by
construction rather than by discipline.

NO EXCLUSION POLICY. `unboxr` has none -- not `__pycache__`, not `.git`, not
`node_modules`. Whether those belong in an analysed corpus is the consumer's
policy, applied after extraction, and introducing it here would make this
document depend on a decision that is not this package's to take. Until 3.0 the
document repeated that in a property of its own, on every document, always with
the same value: a constant says nothing per document, and it belongs in the
README, where it now lives alone.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from urllib.parse import urlparse

from .extraction import (
    PATH_IS_TREE_RELATIVE,
    PROVISIONAL_DIGEST_LENGTH,
    _digest_of_existing_file,
    is_url,
    seven_zip_version,
)
from .report import (
    CAUSE_KINDS,
    CAUSE_TEXTS,
    DESTINATION_ALREADY_OCCUPIED,
    NOT_REGULAR_FILE,
    OPENED,
    READ_FAILED,
    SYMLINK_NOT_FOLLOWED,
    text_for,
)

# The canonical rank of a cause code, read from `CAUSE_TEXTS`'s own
# declaration order -- the one table the crypto-scan story (AC-3.2) already
# treats as where a code's identity lives. Used below to order multiple
# causes on one path WITHOUT relying on the report's internal list fill
# order: no test holds that order today, and leaning on it would be leaning
# on a property this package does not guarantee. Decided by Rodolphe in code
# review, story 14.4: the genre a code belongs to (opened, not_opened,
# still_in_tree, widened) already fixes the coarse order; this fixes the rest.
_CAUSE_RANK = {code: rank for rank, code in enumerate(CAUSE_TEXTS)}

# --- The property names -------------------------------------------------------
#
# PREFIXED `unboxr:`, ALWAYS. A document produced by this package, which is
# published and versioned on its own, must not carry the prefix of a consumer:
# that would be a false indication of provenance in a document whose whole
# purpose is to be evidence. The prefix names the PRODUCER.
#
# ENGLISH, lowerCamelCase, like every other identifier in this package.
#
# A NAME THAT THE SCHEMA ALREADY PROVIDES DOES NOT EXIST HERE. `hashes`, `type`,
# `name` and `metadata.tools` are native CycloneDX fields; wrapping any of them
# in a property would be a second way of saying the same thing.
#
# NO VALUE EVER MIXES A MACHINE VALUE WITH EXPLANATORY PROSE. A code and its
# text are two properties, so that a consumer reads one and displays the other
# instead of splitting a string on punctuation.
#
# A PROPERTY IS WRITTEN ONLY WHEN SOMETHING ABNORMAL HAPPENED, and this is the
# rule that reversed in 3.0. Until then every property was emitted on every
# component, `unboxr:causeCode = no_entry` included, because an omission would
# have read as "not applicable" rather than "not determined" -- true under a
# positive-only oracle, where a silence cannot be told apart from an unasked
# question.
#
# The document now promises the opposite on anomalies: every abnormal event
# this package can observe is written. An omission therefore ASSERTS something
# precise -- "nothing abnormal happened to this path" -- and repeating that
# seven hundred times over an ordinary archive adds nothing. The two halves are
# one decision: the promise is what makes the silence readable, and without it
# the omissions would be uninterpretable.
#
# The table is published in README.md and a test compares the two IN BOTH
# DIRECTIONS. Adding a name here is an addition to the published contract and
# raises the minor version; REMOVING one, as 3.0 did to fourteen of them,
# raises the major.
PROPERTY_PREFIX = "unboxr:"

# On `metadata.properties`: the one thing true of the RUN that nothing else
# says. It survived the cull of 3.0 alone, and not for convenience -- it is the
# flag that says the exhaustivity promise DOES NOT HOLD for this document. A
# run that died partway could not observe the anomalies it never reached, and
# without this a truncated document would be indistinguishable from a clean
# one, its silence reading as "nothing abnormal".
EXTRACTION_OUTCOME = "unboxr:extractionOutcome"

# On a component: what is true of ONE path, when something abnormal is true of
# it at all.
ANOMALY_CODE = "unboxr:anomalyCode"
ANOMALY_TEXT = "unboxr:anomalyText"

# The one survivor of the four per-component properties 3.0 removed, and it
# survives in a single case. The other three -- `digestState`, `nestingLevel`,
# `parentContainer` when it names a real parent -- are all derivable from the
# path and the anomalies, because a nested archive is flattened into a
# directory carrying its own name: `outer.zip/inner.zip/code/aes.c` states its
# own ancestry, and the containers it names are themselves components.
#
# THAT READING FAILS IN THREE CASES (see `_parent_container`), and one of them
# is ordinary: a path that passes through a provisional extraction directory,
# whose name is a digest. There, a consumer walking prefixes finds no parent
# and would conclude there is NONE -- turning "unknown" into a favourable
# answer. So the property is written exactly when it would say
# `not_determinable`, and `not_determinable` is the only value it ever takes.
PARENT_CONTAINER = "unboxr:parentContainer"

METADATA_PROPERTY_NAMES = (EXTRACTION_OUTCOME,)
COMPONENT_PROPERTY_NAMES = (ANOMALY_CODE, ANOMALY_TEXT, PARENT_CONTAINER)
PROPERTY_NAMES = METADATA_PROPERTY_NAMES + COMPONENT_PROPERTY_NAMES


# --- Closed vocabularies ------------------------------------------------------
#
# The extraction either finished or it did not. Two values, and the second is
# written on the failure path rather than left to an absent document.
OUTCOME_COMPLETE = "complete"
OUTCOME_FAILED = "failed"

# The only value `PARENT_CONTAINER` ever carries. Its PRESENCE is the message;
# the value spells it out for a reader who has the document and not the README.
NOT_DETERMINABLE = "not_determinable"

# Values used inside this module, never written as a property value.
UNKNOWN = "unknown"
NONE_VALUE = "none"

# The shape of the one name this package fabricates for a provisional
# extraction directory. Built from the exported length, never retyped as a
# literal: a path passing through one of these carries no readable parent.
_PROVISIONAL_NAME = re.compile(r"^archive_[0-9a-f]{%d}$" % PROVISIONAL_DIGEST_LENGTH)

# CycloneDX has no "directory" component type -- the enumeration is closed at 13
# values, read from the schema on 13 September 2026. A path that names a
# directory is therefore NOT typed `file`, which would be a false statement in a
# document meant as evidence; it is typed `data`, the one value in that
# enumeration that asserts a collection of values rather than a single file or a
# piece of software.
#
# WHAT TELLS THEM APART IS NOW THE ANOMALY, not a property of this module's own:
# a component carrying `not_regular_file` is typed `data`, everything else
# `file`. That reproduces the previous behaviour exactly, symbolic links
# included -- they were typed `file` before, their digest state not being
# `not_a_file`, and they still are. Reading "not file content" as "type data"
# and quietly retyping them would be a behaviour change wearing the clothes of
# a cleanup.
TYPE_FILE = "file"
TYPE_NOT_A_FILE = "data"
TYPE_TOOL = "application"


# --- The link to another BOM --------------------------------------------------
#
# A BOM says which other BOM it belongs to with a BOM-Link: a URN of the shape
# `urn:cdx:<uuid>/<version>`, where the UUID is the one carried by the other
# document's serial number -- BARE, with no `urn:uuid:` prefix in front of it --
# and the version is that document's own.
#
# WHAT THE SCHEMA DOES NOT DO, AND IT IS THE REASON THIS CONSTANT EXISTS.
# `externalReference.url` is an `anyOf` whose first branch is a plain
# `iri-reference` string, and that branch accepts anything at all. Measured on
# 13 September 2026 against the official schema: a document whose link reads
# `anything at all` validates with ZERO errors, and so does one pointing at
# version 0 of a document that is not a UUID. A validator cannot be asked to
# hold this; the check below is the only thing that does.
#
# TRANSCRIBED, NOT READ AT RUN TIME, and the reason is a fact about this
# repository rather than a preference: the schema is not vendored here, this
# package declares no dependency at all, and a test reading a cache that
# belongs to one machine would make its own result depend on the state of that
# machine. So the pattern is read at the source, written down WITH ITS
# PROVENANCE, and re-confronted to the schema at delivery time.
#
# Source: `definitions.bomLinkDocumentType.pattern`, CycloneDX schema tag 1.7
# -- never `master`, which diverges from it -- read on 13 September 2026.
#
# THE RAW STRING, with the compiled form derived from it below: a delivery
# check comparing this constant to the schema character for character cannot
# do so against a compiled object.
BOM_LINK_DOCUMENT_PATTERN = (
    "^urn:cdx:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    "/[1-9][0-9]*$"
)

# ALREADY ANCHORED at both ends by the schema itself: nothing is added here,
# and `fullmatch` below is not redundant with it. See the predicate.
_BOM_LINK_DOCUMENT = re.compile(BOM_LINK_DOCUMENT_PATTERN)

# What the link does NOT attest, in the native `comment` field -- never in a
# property of this package's own, the rule being that a name the schema
# already provides does not get invented a second time here.
#
# THE POSITIVE-ONLY ORACLE, APPLIED TO THE LINK ITSELF. `unboxr` does not open
# the document it is pointed at: it cannot know that it exists, and it cannot
# know that it describes this extraction. Both would be read into a bare link.
LINKED_BOM_COMMENT = (
    "The BOM this document belongs to, as supplied by the caller. unboxr "
    "does not open it and does not resolve it: this reference attests "
    "neither that the document exists nor that it describes this extraction."
)


class InvalidBomLinkError(ValueError):
    """A link this package will not write, because it knows it to be false.

    Raised rather than dropped. Silently writing no link would make the
    attachment the caller asked for disappear, leaving a document
    indistinguishable from one nobody ever wanted linked.
    """


# ONE explanation, not two independently worded ones. This module's own
# refusal and the command's option-parsing refusal (`unboxr/cli.py`) used to
# each spell out the shape and the element-form rationale in their own words,
# and the two had already drifted -- "a reference of this package renumbers"
# here against "a reference of the extraction document renumbers" there. The
# same discipline as `BOM_LINK_DOCUMENT_PATTERN` applies: one source, read
# from here, never retyped.
INVALID_BOM_LINK_REASON = (
    "not a BOM-Link to a document: %r. The shape is "
    "urn:cdx:<uuid>/<version>, with the uuid in lowercase "
    "hexadecimal and bare -- no urn:uuid: prefix -- and a version of "
    "1 or more. A link to an element of a document (...#<bom-ref>) "
    "is refused: a reference of the document renumbers whenever the "
    "corpus changes."
)


def is_bom_link_to_a_document(candidate) -> bool:
    """Whether a value is a BOM-Link of DOCUMENT shape.

    `fullmatch`, NEVER `match`, AND IT IS NOT A MATTER OF STYLE. Python's `$`
    also matches just before a final newline; the `$` of ECMA-262, which is
    the semantics a JSON Schema pattern carries, does not. A value ending in a
    newline -- the ordinary residue of reading a URN out of a file -- would
    pass a `match` and be written into a document no validator will ever
    question, this check being its only defence.

    THE ELEMENT SHAPE, `...#<bom-ref>`, IS REFUSED, and that is a decision of
    this package rather than a constraint of the format, reversible as such.
    Two reasons, each sufficient: `unboxr` knows no `bom-ref` of the document
    it points at, and its own references are RANKS that renumber the moment a
    file enters or leaves the corpus -- so a link into an element would break
    at the next regeneration, in silence.

    A value that is not a string is refused rather than raising: this answers
    a question, it does not decide that a caller who handed over the wrong
    kind of thing has a link.
    """
    if not isinstance(candidate, str):
        return False
    return _BOM_LINK_DOCUMENT.fullmatch(candidate) is not None


def _tool_version() -> str:
    """The package version, read from its one source of truth.

    Imported INSIDE the function on purpose: `unboxr/__init__.py` imports this
    module, so a module-level import of the version would read a
    half-initialised package. At call time the package is fully loaded.
    """
    from . import __version__
    return __version__


def _bare_name(text) -> str:
    """The last component of a source, never the path that led to it.

    No absolute path and no temporary directory name enters this document: both
    depend on the machine, and this document is meant to be compared between
    machines. A URL is reduced the same way -- what identifies the subject is
    the file that was fetched, not the route to it.

    A URL takes the PATH component only, exactly as `download_source`
    (`extraction.py`) does when it names the file it writes to disk. A raw
    split on `/` would keep the query string and fragment: a signed URL's
    query string can carry a bearer credential (`?X-Amz-Signature=...`), which
    has no business in a document meant to be kept and shared, and it changes
    on every fetch of the same artefact -- silently breaking determinism on a
    field this document does not declare volatile (review of story 14.4).
    """
    if text is None:
        return UNKNOWN
    text = str(text)
    if is_url(text):
        cleaned = urlparse(text).path.rstrip("/")
    else:
        cleaned = text.replace("\\", "/").rstrip("/")
    if not cleaned:
        return UNKNOWN
    return cleaned.rsplit("/", 1)[-1] or UNKNOWN


def _properties(pairs) -> list:
    """`properties` entries. The value is ALWAYS a string: the schema says so,
    so numbers are converted here rather than left to a serialiser."""
    return [{"name": name, "value": str(value)} for name, value in pairs]


def _hashes(digest):
    """The native `hashes` field, or nothing at all.

    BARE hexadecimal, never prefixed: the schema's `hash-content` pattern
    accepts hexadecimal of five fixed lengths and nothing else, so a `sha256:`
    prefix is refused. Read from the schema on 13 September 2026. The algorithm
    name is `SHA-256`, spelled exactly as the `hash-alg` enumeration spells it.

    An absent digest leaves the field out because `hashes` has no way to say
    "not computed" -- `unboxr:digestState` is what says it, and it is always
    emitted.
    """
    if not digest:
        return None
    return [{"alg": "SHA-256", "content": digest}]


def _walk_the_tree(tree: Path, skip: set):
    """Every file left in the tree, with its digest -- or with why it has none.

    ORDINARY FAILURES, NOT ANOMALIES. A broken symbolic link, a refused
    permission, a file removed between the listing and the read: all three are
    everyday events in a walk of a real tree, and none of them may fail the
    document. Each is inscribed WITH ITS STATE NAMED, never omitted -- a file
    quietly dropped is exactly the amputation this document exists to make
    visible -- and their number is counted in `metadata`.

    SYMBOLIC LINKS ARE NOT FOLLOWED. `is_file()` follows them, so hashing one
    would duplicate the content of its target under a second path and invent an
    alias the tree does not have. The link is inscribed with a state of its own
    instead.

    DIRECTORIES ARE NOT INSCRIBED: this walk inventories files.
    """
    found = []
    # THE THIRD ELEMENT IS AN ANOMALY CODE OR `None`, where it used to be one of
    # four digest states. The fourth state said "the digest was computed", which
    # 3.0 has nothing to write about: it is the ordinary case.
    #
    # CHECKED, NOT LEFT TO `rglob` TO RAISE. A missing root used to be caught
    # by an `OSError` from `rglob` itself on older Python -- current pathlib
    # instead treats a non-existent root as "no matches", returning an EMPTY
    # list in silence. Swallowing that used to produce a document declaring
    # `extractionOutcome=complete` with zero file components: the total
    # amputation this document exists to make visible, left completely
    # unnamed. Raised HERE instead, deterministically, regardless of what any
    # given Python version's glob happens to do. The caller (`build_document`,
    # then `write_document`/`_write_document` in `cli.py`) already turns an
    # exception into a NAMED failure; per-entry failures below stay caught,
    # because those genuinely are ordinary.
    if not tree.is_dir():
        raise NotADirectoryError(
            f"the tree to inventory does not exist or is not a directory: "
            f"{tree}")
    entries = list(tree.rglob("*"))
    for path in entries:
        try:
            relative = path.relative_to(tree).as_posix()
        except ValueError:       # pragma: no cover - rglob yields descendants
            continue
        if relative in skip:
            continue
        try:
            if path.is_symlink():
                found.append((relative, None, SYMLINK_NOT_FOLLOWED))
                continue
            if path.is_dir():
                continue      # directories are not inscribed: see above
            if not path.is_file():
                # A FIFO, a socket, a device node: not a directory, not a
                # symlink, not a regular file either. `unboxr` applies no
                # exclusion policy (module docstring) -- silently skipping
                # these here, as the walk used to, would contradict that and
                # drop them with no trace at all. `not_a_file` is the state
                # already used for "this path exists but is not file content
                # to hash". Reviewed in story 14.4.
                found.append((relative, None, NOT_REGULAR_FILE))
                continue
        except OSError:
            found.append((relative, None, READ_FAILED))
            continue
        digest = _digest_of_existing_file(path)
        found.append((relative, digest, None if digest else READ_FAILED))
    return found


def _parent_container(relative: str, frame: str, opened_paths: set) -> str:
    """The container this path came out of, read off the path itself.

    It works because a nested archive is flattened into a directory carrying
    that archive's own name, verbatim: `outer.zip/inner.zip/code/aes.c` names
    its own ancestry. The parent is the LONGEST ancestor that was actually
    recorded as opened -- measured against the report, never guessed from a
    list of extensions.

    THREE CASES WHERE THAT READING DOES NOT HOLD, and each returns
    `not_determinable` rather than a plausible answer: a path that is a bare
    name (nothing to place in the tree), one whose frame is unknown, and one
    passing through a provisional extraction directory, whose name is a digest
    of a path and says nothing about what it holds.
    """
    if frame != PATH_IS_TREE_RELATIVE:
        return NOT_DETERMINABLE
    segments = relative.split("/")
    if any(_PROVISIONAL_NAME.match(segment) for segment in segments):
        return NOT_DETERMINABLE
    ancestors = ["/".join(segments[:n]) for n in range(len(segments) - 1, 0, -1)]
    for ancestor in ancestors:
        if ancestor in opened_paths:
            return ancestor
    return NONE_VALUE


def _anomaly_pairs(codes):
    """The code/text pair for a path, or nothing at all when nothing happened.

    TWO PROPERTIES, NEVER ONE. A consumer on the other side of a language
    boundary translates the CODE and ignores the text, so mixing a machine
    value and prose into one string would force it to split on punctuation.

    AN EMPTY LIST IS THE ORDINARY CASE since 3.0, and it is what makes the
    caller leave `properties` out. There is no `no_entry` any more: the absence
    of the key is the statement.
    """
    if not codes:
        return []
    return [(ANOMALY_CODE, ", ".join(codes)),
            (ANOMALY_TEXT, " | ".join(text_for(code) for code in codes))]


def _seven_zip_tool(report):
    """The 7-Zip entry of `metadata.tools`, or nothing.

    WRITTEN ONLY WHEN THE BINARY ACTUALLY RAN. `capability.seven_zip_binary`
    says what the machine HAS; naming that here would describe the environment
    the document was made in rather than what made it.

    THE STEM, NEVER THE PATH. `find_7zip_binary()` returns an absolute path,
    which on Windows sits under Program Files or WindowsApps -- and no absolute
    path belongs in a document meant to be compared between machines, which is
    the whole reason `_bare_name` exists above. The stem also happens to be the
    identity that matters: `7z`, `7za`, `7zr` and `7zz` are different products
    with different coverage.

    THE VERSION IS OPTIONAL AND MAY BE MISSING. A fork whose banner this
    package cannot parse still gets its entry: dropping the tool over an
    unreadable banner would hide that 7-Zip ran at all, which is the part a
    reader needs.
    """
    binary = getattr(report, "seven_zip_used", None)
    if not binary:
        return None
    entry = {"type": TYPE_TOOL, "name": Path(binary).stem}
    version = seven_zip_version(binary)
    if version:
        entry["version"] = version
    return entry


def build_document(report, tree=None, *, source=None, source_digest=None,
                   serial_number=None, timestamp=None, linked_bom=None):
    """The CycloneDX 1.7 document, as a structure. Nothing is written here.

    `tree` is the directory the extraction produced, or `None` when the run
    failed before there was one -- the case where the corpus is most amputated
    and the document matters most. `source` names what was handed over,
    `source_digest` is its bare hexadecimal SHA-256 when it had one.

    `linked_bom` is a BOM-Link, RECEIVED ALREADY FORMED. This function does
    not compose one out of a serial number and a version: how a caller
    numbers its own documents is not this package's business, and a composer
    would be a point of extension nobody has asked for. A link it cannot
    recognise raises `InvalidBomLinkError`; `None` leaves the key out
    entirely, an empty array being a way of saying "we looked, there is none"
    that this package does not have.

    ONE COMPONENT PER PATH, never one per report entry. The identity of a
    report entry is the pair (cause, path) and one path can carry several
    causes -- a container opened and then kept is the ordinary case. Every
    anomaly is present, in a deterministic order, and the texts follow the same
    order: none is chosen at the expense of another.

    `source_kind` WAS REMOVED IN 3.0 and is no longer accepted. It fed two
    things that no longer exist: the `sourceKind` property, which said what
    `metadata.component.type` already says, and the two depth properties. A
    parameter that no longer changes anything is worse than an absent one.
    """
    # BEFORE ANYTHING IS BUILT. A document half-assembled and then thrown away
    # costs a full walk of the tree for nothing, and the fault is decidable
    # from the argument alone.
    if linked_bom is not None and not is_bom_link_to_a_document(linked_bom):
        raise InvalidBomLinkError(INVALID_BOM_LINK_REASON % (linked_bom,))

    entries = {}
    order = []

    def _entry(path: str):
        if path not in entries:
            entries[path] = {"codes": [], "digest": None, "frame": None,
                             "names_a_directory": False}
            order.append(path)
        return entries[path]

    # GENRE FIRST, THEN CAUSE RANK -- NEVER THE REPORT'S OWN FILL ORDER. The
    # genre a list belongs to is a structural property of the report, fixed
    # here in source, not something the report promises to preserve; within one
    # genre, `_CAUSE_RANK` breaks ties on the code's OWN canonical position,
    # and `path` last for full stability.
    def _canonically_ordered(genre):
        return sorted(genre, key=lambda r: (
            _CAUSE_RANK.get(r.code, len(_CAUSE_RANK)), r.path))

    # `not_attested` IS IN THE CHAIN even though today's walk attaches its
    # codes directly below rather than filing them. A caller that files one --
    # `record()` accepts them, they have a kind -- would otherwise have it
    # silently dropped, which is the one thing this document must never do.
    records = (_canonically_ordered(report.opened)
               + _canonically_ordered(report.not_opened)
               + _canonically_ordered(report.still_in_tree)
               + _canonically_ordered(report.widened)
               + _canonically_ordered(getattr(report, "not_attested", [])))
    opened_paths = {r.path for r in report.opened
                    if r.path_frame == PATH_IS_TREE_RELATIVE}

    # THE WALK SKIPS ONLY WHAT IT CAN REALLY CONFRONT. A bare name cannot be
    # matched against a path in the tree: a file whose relative path happens to
    # equal it, character for character, is a DIFFERENT file, and removing it
    # from the document would be the silent amputation this document exists to
    # expose. Doubt inscribes; it never removes.
    skip = {r.path for r in records if r.path_frame == PATH_IS_TREE_RELATIVE}

    if tree is not None:
        for relative, digest, anomaly in _walk_the_tree(Path(tree), skip):
            item = _entry(relative)
            item["digest"] = digest
            item["frame"] = PATH_IS_TREE_RELATIVE
            if anomaly is not None:
                item["codes"].append(anomaly)

    for record in records:
        item = _entry(record.path)
        if record.code not in item["codes"]:
            item["codes"].append(record.code)
        # A digest already taken by the walk is the digest of the file that is
        # ACTUALLY at that path. It wins over one carried by a record whose
        # path could not be confronted -- the collision case above.
        if item["digest"] is None and record.digest:
            item["digest"] = record.digest
        if item["frame"] is None:
            item["frame"] = record.path_frame
        # Only DESTINATION_ALREADY_OCCUPIED is measurably a directory: it is
        # the one report code no call site ever passes a digest for, BY
        # DESIGN, because its recorded path names the destination directory
        # itself (`extraction.py`, "NO DIGEST: destination is a DIRECTORY").
        if record.code == DESTINATION_ALREADY_OCCUPIED:
            item["names_a_directory"] = True

    # THE INVARIANT, APPLIED ONCE AND FOR ALL: a component carries either a
    # digest or an anomaly saying why it has none. `hashes` has no way to say
    # "not computed", and a component silent on both would be the one thing a
    # document of evidence cannot be. It replaces the `digestState` property,
    # which said this on every component including the ones it was true of.
    #
    # ANY ANOMALY SATISFIES IT, NOT A DEDICATED ONE, and that is the whole
    # difference with the property it replaces. A container refused by the tar
    # filter has no digest BECAUSE it was refused: the refusal is already on
    # the component and already explains the absence. Appending `read_failed`
    # beside it -- which is what `digestState` used to say for exactly these
    # components, invisibly, in a field of its own -- would now show up in the
    # anomaly list and assert a read that failed, an event that never
    # happened. Measured against the suite in implementation: three tests
    # caught it.
    #
    # So the fallback fires only for a path with NO anomaly at all and no
    # digest. AND `OPENED` DOES NOT COUNT AS ONE, which is the case that makes
    # this guard necessary rather than decorative: a nested container whose
    # digest could not be taken carries `nested_container_opened` and nothing
    # else, that code writes no property, and the component would come out
    # with neither a digest nor a word about why -- silent on the one thing
    # this document exists to attest. Caught by the suite in implementation.
    for item in entries.values():
        if item["digest"] is not None:
            continue
        if any(CAUSE_KINDS.get(code) != OPENED for code in item["codes"]):
            continue
        item["codes"].append(READ_FAILED)

    # THE INPUT CONTAINER IS NOT LISTED TWICE. `metadata.component` already
    # names it, with its digest; a second entry saying the same thing under a
    # `bom-ref` was pure duplication once its `input_container_opened` property
    # stopped being written.
    #
    # BY IDENTITY OF THE PATH, NEVER BY RANK. The components are sorted, and
    # the input container lands first only when its name happens to sort first
    # -- `paquet.zip` before `paquet/...` because `.` precedes `/` in ASCII,
    # which is a coincidence of that pair and not a rule. A collision is
    # excluded by the naming rule itself: an archive is flattened into a
    # directory carrying its own name, so nothing INSIDE the tree can have a
    # relative path equal to the archive's own bare name.
    subject_name = _bare_name(source)
    subject_codes = []
    if source is not None and subject_name in entries:
        subject_codes = [code for code in entries[subject_name]["codes"]
                         if CAUSE_KINDS.get(code) != OPENED]

    components = []
    listed = [path for path in sorted(order)
              if not (source is not None and path == subject_name)]
    for rank, path in enumerate(listed, start=1):
        item = entries[path]
        # OPENING A CONTAINER IS NOT AN ANOMALY, so its codes produce no
        # property -- but the COMPONENT stays, and with it the digest. A nested
        # archive is destroyed by the flattening: the instant it was recorded
        # is the only one it could ever be hashed at, and dropping the
        # component here would erase that digest from the only document that
        # will ever hold it.
        codes = [code for code in item["codes"]
                 if CAUSE_KINDS.get(code) != OPENED]
        component = {
            # DERIVED FROM THE SORTED RANK, NEVER FROM THE PATH -- a path
            # would need escaping wherever a `bom-ref` is placed after a `#`
            # in a BOM-Link URN. A rank RENUMBERS every time a file enters or
            # leaves the corpus, which is why `is_bom_link_to_a_document`
            # refuses the element shape outright.
            "bom-ref": "unboxr-component-%d" % rank,
            # TWO WAYS TO BE A NON-FILE, and they come from different places:
            # the walk says so with `not_regular_file`, and a record says so by
            # being a destination directory -- the one code no call site ever
            # passes a digest for, by design. Both must type the component
            # `data`: calling a directory a `file` would be a false statement
            # in a document meant as evidence.
            "type": (TYPE_NOT_A_FILE
                     if NOT_REGULAR_FILE in codes or item["names_a_directory"]
                     else TYPE_FILE),
            # THE FULL RELATIVE PATH, not the base name: `name` is one of the
            # two required fields, and two files of the same name in two
            # directories would otherwise be indistinguishable to a reader.
            "name": path,
        }
        pairs = _anomaly_pairs(codes)
        # WRITTEN ONLY WHEN THE PREFIXES CANNOT BE READ. Everywhere else the
        # path states its own ancestry and this property would repeat it; here
        # a consumer walking prefixes would find no parent and conclude there
        # is none, turning "unknown" into a favourable answer.
        if _parent_container(path, item["frame"],
                             opened_paths) == NOT_DETERMINABLE:
            pairs.append((PARENT_CONTAINER, NOT_DETERMINABLE))
        if pairs:
            component["properties"] = _properties(pairs)
        hashes = _hashes(item["digest"])
        if hashes is not None:
            component["hashes"] = hashes
        components.append(component)

    subject = {
        "type": TYPE_FILE if source_digest else TYPE_NOT_A_FILE,
        "name": subject_name,
    }
    # THE SUBJECT CARRIES ITS OWN ANOMALIES, since it no longer appears among
    # the components. An input container that failed to open is the case this
    # exists for, and it is the one where the document matters most.
    subject_pairs = _anomaly_pairs(subject_codes)
    if subject_pairs:
        subject["properties"] = _properties(subject_pairs)
    subject_hashes = _hashes(source_digest)
    if subject_hashes is not None:
        subject["hashes"] = subject_hashes

    # WHICH TOOLS, AND WHICH VERSIONS. What the document holds depends on them:
    # which formats this version of `unboxr` can open, and -- when an external
    # 7-Zip was actually run -- which fork did the opening. A document silent
    # on its producers cannot be diagnosed when two corpora diverge.
    tools = [{"type": TYPE_TOOL, "name": "unboxr", "version": _tool_version()}]
    seven_zip = _seven_zip_tool(report)
    if seven_zip is not None:
        tools.append(seven_zip)

    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        # NEITHER OF THESE IS DECORATION. A BOM is addressable by a BOM-Link of
        # the shape `urn:cdx:<uuid>/<version>`: leaving them out would validate
        # and make linking this document to another impossible without coming
        # back to change it.
        "serialNumber": serial_number or ("urn:uuid:%s" % uuid.uuid4()),
        "version": 1,
        "metadata": {
            "timestamp": timestamp or _now_to_the_second(),
            "tools": {"components": tools},
            # WHAT THIS DOCUMENT IS THE DOCUMENT OF. Without it, a list of
            # thousands of files never names its own subject.
            "component": subject,
            "properties": _properties((
                (EXTRACTION_OUTCOME,
                 OUTCOME_FAILED if tree is None else OUTCOME_COMPLETE),
            )),
        },
        "components": components,
    }

    # AT THE ROOT, AND NOWHERE ELSE. Read from the schema on 13 September
    # 2026: `externalReferences` exists at the root of a BOM and on a
    # component, and does NOT exist on `metadata` -- writing it there, which
    # is where everything else this package adds goes, would make the document
    # invalid. THREE KEYS AND NO MORE: `externalReference` is
    # `additionalProperties: false`.
    #
    # THE KEY IS ABSENT WHEN THERE IS NO LINK, and an empty array is not an
    # alternative: it would read as "we looked, there is none", a negative
    # drawn from an absence. The schema accepts an empty array perfectly well
    # -- measured, zero errors -- so this is a rule of this package, not a
    # restatement of the format, and relaxing it as redundant would be a
    # mistake.
    if linked_bom is not None:
        # WRITTEN IN THE SCHEMA'S ORDER, not merely serialised into it.
        document["externalReferences"] = [{
            "url": linked_bom,
            "comment": LINKED_BOM_COMMENT,
            "type": "bom",
        }]
    return document


# --- The shape of the bytes ---------------------------------------------------
#
# WHY ANY OF THIS EXISTS. Until now the document came out with its keys in
# alphabetical order, because `json.dumps` was asked to sort them. That was
# never a conformance requirement and never could be: a JSON object is an
# UNORDERED collection, no JSON schema constrains the order of its keys, and
# the document validated perfectly well. It was a presentation choice that
# three places in this repository described without one of them saying why it
# was switched on.
#
# WHAT SORTING ACTUALLY BOUGHT, AND WHY IT IS KEPT. It made the bytes
# independent of the order `build_document` happens to write its dictionaries
# in: reordering two assignments there could not change the output. That
# property is worth keeping, and the table below keeps it -- the order comes
# from a declaration, not from the code's shape. What replaces the safety net
# is the test that fails when a key this package produces is missing from the
# table.
#
# WHY A TOTAL ORDER AND NOT A LOOKUP BY TYPE. `serialise` is public and takes
# an ARBITRARY document; nothing in a bare JSON object says which CycloneDX
# type it is, so a sort that had to recognise the type at run time would be
# guessing. The per-type tables are the transcription, and the order actually
# applied is DERIVED from them by topological sort -- one source of truth, not
# two. The derivation is only possible because the tables agree with one
# another, which is a measured fact about today's tables and a test of its own.
SCHEMA_KEY_ORDER_SOURCE = (
    "bom-1.7.schema.json, tag 1.7 "
    "(http://cyclonedx.org/schema/bom-1.7.schema.json), "
    "key declaration order read on 15 September 2026"
)

# RESTRICTED TO THE KEYS THIS PACKAGE PRODUCES, deliberately. Transcribing all
# 19 root keys and all 36 component keys would give a new native field a place
# without anyone deciding it deserved one -- and the guard that catches an
# undeclared key is the whole replacement for `sort_keys`. A shorter table
# makes that guard fire.
#
# `version` SITS IN THE COMPONENT TABLE and not only in the root one: the tool
# inside `metadata.tools.components` is a component carrying `type`, `name` and
# `version`, and without the entry here nothing would hold `version` after
# `name`. Measured during implementation; the story's table omitted it.
SCHEMA_KEY_ORDER = {
    "bom": ("bomFormat", "specVersion", "serialNumber", "version", "metadata",
            "components", "externalReferences"),
    "metadata": ("timestamp", "tools", "component", "properties"),
    "component": ("type", "bom-ref", "name", "version", "hashes", "properties"),
    "property": ("name", "value"),
    "hash": ("alg", "content"),
    "externalReference": ("url", "comment", "type"),
}


def _derive_total_key_order(tables) -> tuple:
    """One order over every key name, honouring each per-type order.

    A topological sort, with the ties broken ALPHABETICALLY so that two runs
    on the same tables give the same order -- an arbitrary tie-break would
    make the bytes depend on dictionary iteration, which is the very thing
    this table exists to remove.

    RAISES rather than inventing an order when the tables contradict one
    another. They agree today; a key added tomorrow could put two of them in
    conflict, and an order silently invented there would be a presentation
    nobody chose.

    AND IT RAISES AT IMPORT, WHICH IS DELIBERATE. `KEY_ORDER` is derived at
    module level, so a contradiction makes `import unboxr` fail -- the
    extractor and the command line included, for a fault in a table that only
    governs presentation. That reads like a wide blast radius and is not one:
    `SCHEMA_KEY_ORDER` is a literal of this source, never anything a caller
    supplies, so the contradiction can exist only in a working tree where
    someone has just mistyped it, and the test suite is red at the same
    instant. It cannot reach an installed package. Deferring the derivation
    to the first `serialise` would move the failure later than its cause for
    no case that can actually happen.
    """
    successors = {}
    remaining = {}
    for kind, order in tables.items():
        # A TABLE IS A SEQUENCE OF KEY NAMES, AND A BARE STRING IS NOT ONE.
        # `("alg")` instead of `("alg",)` is a missing comma, and Python reads
        # it as the string "alg" -- which iterates into three one-letter keys
        # and leaves `alg` undeclared. These tables are transcribed by hand
        # from a schema, which is exactly where that typo lives.
        if isinstance(order, str):
            raise TypeError(
                "the key order table for %r must be a sequence of key names, "
                "not a string: %r (a missing comma?)" % (kind, order))
        for key in order:
            successors.setdefault(key, set())
            remaining.setdefault(key, 0)
        for earlier, later in zip(order, order[1:]):
            if later not in successors[earlier]:
                successors[earlier].add(later)
                remaining[later] += 1

    ready = sorted(key for key, count in remaining.items() if count == 0)
    ordered = []
    while ready:
        key = ready.pop(0)
        ordered.append(key)
        for following in sorted(successors[key]):
            remaining[following] -= 1
            if remaining[following] == 0:
                ready.append(following)
        ready.sort()

    if len(ordered) != len(remaining):
        raise ValueError(
            "no key order satisfies every table; the keys in conflict are: "
            + " -> ".join(_first_cycle(successors, set(remaining) - set(ordered))))
    return tuple(ordered)


def _first_cycle(successors, stuck) -> list:
    """One cycle among the stuck keys, as the path that closes it.

    NAMING EVERY STUCK KEY WOULD BE NAMING MOSTLY INNOCENTS. The keys left
    unplaced are the cycle AND everything merely downstream of it: on a real
    mistranscription that is ten keys, of which two are in conflict. The
    maintainer this message exists for would be handed eight bystanders to
    check. Walking the successors from a stuck key finds the cycle itself.
    """
    for start in sorted(stuck):
        path = [start]
        seen = {start}
        while True:
            following = sorted(k for k in successors[path[-1]] if k in stuck)
            if not following:
                break
            step = following[0]
            if step in seen:
                return path[path.index(step):] + [step]
            path.append(step)
            seen.add(step)
    return sorted(stuck)


# READ-ONLY ON PURPOSE. `KEY_ORDER` is computed once, here, so mutating the
# tables afterwards would change nothing at all -- in silence. A mapping that
# cannot be written says "this is the transcription, not a knob" instead of
# merely intending it.
SCHEMA_KEY_ORDER = MappingProxyType(SCHEMA_KEY_ORDER)
KEY_ORDER = _derive_total_key_order(SCHEMA_KEY_ORDER)
_KEY_RANK = {key: index for index, key in enumerate(KEY_ORDER)}

# The two objects that make up the tissue of the document. Together they are a
# third of its lines, four each, for two short strings. Folded onto one line
# they stay valid, stay readable, and the document loses half its height.
#
# THE CRITERION IS THE EXACT SET OF KEYS, never a resemblance of shape: an
# object that merely happens to have two keys is left alone, because widening
# this to "any small object" opens a question of threshold that nothing here
# settles.
FOLDED_KEY_SETS = (frozenset(("name", "value")), frozenset(("alg", "content")))


def _in_key_order(value, _enclosing=()):
    """The same document, every object's keys in the declared order.

    A key no table declares is NEVER lost: it comes out after the declared
    ones, alphabetically. This function is handed documents from outside as
    well as the one this package builds, and refusing a key it does not
    recognise would be judging a document it has no business judging.

    TUPLES ARE WALKED, NOT LEFT ALONE. `json.dumps` encodes a tuple as an
    array exactly as it encodes a list, so a dictionary held in a tuple IS
    written -- and skipping it here would leave its keys in the order the
    caller built them in, which is the ONE property this whole table exists
    to remove. Descending turns it into a list, which changes nothing in the
    output: both encode to the same array.

    A CIRCULAR DOCUMENT RAISES THE ERROR IT ALWAYS RAISED. Before this pass
    existed, `json.dumps` detected the cycle itself and raised
    `ValueError("Circular reference detected")`. Walking the document first
    would instead exhaust the stack and hand a caller a `RecursionError` --
    a different exception, uncatchable by the code that used to catch the
    first, and a message that never names the cycle. `_enclosing` carries
    the identities on the current path, so the diagnosis survives.

    DEPTH CEILING, AND IT IS LOWER THAN IT WAS. This pass spends a Python
    frame per level before the C encoder runs, so the deepest document
    `serialise` accepts is roughly a THIRD of what 2.0.1 accepted -- about
    994 levels against 2998 at the default recursion limit. No extraction
    document comes close: a file tree is wide, not deep. It is written down
    rather than fixed because an iterative rewrite would cost the legibility
    that makes the escaping argument in `_folded_window` checkable at all.
    """
    if isinstance(value, (dict, list, tuple)):
        if id(value) in _enclosing:
            raise ValueError("Circular reference detected")
        _enclosing = _enclosing + (id(value),)
    if isinstance(value, dict):
        declared = sorted((key for key in value if key in _KEY_RANK),
                          key=_KEY_RANK.__getitem__)
        rest = sorted(key for key in value if key not in _KEY_RANK)
        return {key: _in_key_order(value[key], _enclosing)
                for key in declared + rest}
    if isinstance(value, (list, tuple)):
        return [_in_key_order(item, _enclosing) for item in value]
    return value


def _not_json(constant):
    """`NaN`, `Infinity` and `-Infinity` are not JSON, whatever `json` allows."""
    raise ValueError("not a JSON value: " + constant)


def _folded_window(lines, index):
    """The one-line form of the object starting at `index`, or nothing.

    WHY A PASS OVER THE TEXT AND NOT AN ENCODER OF OUR OWN. Escaping is where
    a hand-written encoder dies, and this package depends on the standard
    one's escaping precisely (`ensure_ascii=True` exists so that a file name
    carrying lone surrogates cannot cost the whole document). The fold
    therefore runs on the text `json.dumps` has ALREADY produced.

    WHY THAT IS SAFE HERE, and it is not safe in general: after `json.dumps`,
    a LITERAL newline can never appear inside a string -- it is escaped to
    `\\n` -- so a line-by-line pass cannot mistake a value for structure.

    THE SET OF KEYS IS NOT ENOUGH ON ITS OWN. Both values must be scalar and
    complete on their own line, which is checked by reading the two lines back
    as JSON. A caller can hand `serialise` an object whose two keys carry a
    nested list, and a four-line window applied on the key names alone would
    fold it into broken text.

    AND "READ BACK AS JSON" MEANS JSON, not what `json.loads` happens to
    tolerate. It accepts `NaN`, `Infinity` and `-Infinity` by default, which
    `json.dumps` emits and no strict reader accepts. That invalidity is older
    than this pass and is not this pass's to fix; what would be new, and
    wrong, is a guard that ANNOUNCES it verified JSON and then folded one of
    them onto a line. `parse_constant` refuses them, so such an object is left
    expanded, exactly as visibly broken as it was before.
    """
    # THE CHEAP TEST FIRST. This runs once per line of the document, and
    # slicing before it allocated a four-element list for every line, the
    # overwhelming majority of which open nothing.
    if index + 3 >= len(lines) or not lines[index].rstrip().endswith("{"):
        return None
    opening, first, second, closing = lines[index:index + 4]
    if not closing.lstrip().startswith("}"):
        return None
    body = first.strip() + " " + second.strip()
    try:
        pair = json.loads("{" + body + "}", parse_constant=_not_json)
    except ValueError:
        return None
    if len(pair) != 2 or frozenset(pair) not in FOLDED_KEY_SETS:
        return None
    if any(isinstance(item, (dict, list)) for item in pair.values()):
        return None
    return opening.rstrip() + " " + body + " " + closing.lstrip()


def _fold_two_key_objects(text: str) -> str:
    """Every property and every hash on one line, the rest untouched."""
    lines = text.split("\n")
    folded = []
    index = 0
    while index < len(lines):
        window = _folded_window(lines, index)
        if window is None:
            folded.append(lines[index])
            index += 1
        else:
            folded.append(window)
            index += 4
    return "\n".join(folded)


def _now_to_the_second() -> str:
    """The moment the document is built, to the second it actually measures.

    THE COMPLAINT THIS ANSWERS, and the one it does not. `isoformat()` offers
    six decimals that nothing in an extraction measures: that is a precision
    with no measurement behind it, and dropping it is the fix. It does NOT
    make the timestamp the moment the document was written -- it is still the
    moment it was built, merely no longer pretending to microseconds about it.
    Those are two distinct defects and only the first is addressed here.

    RFC 3339 makes the fraction optional, so the shorter form is just as
    valid. NOT a string truncation: that works until the shape moves, then
    writes a false date.

    TWO DOCUMENTS BUILT IN THE SAME SECOND NOW CARRY THE SAME TIMESTAMP,
    where they used to differ by microseconds. Nothing in this package uses
    the field to tell two documents apart -- `serialNumber` does that, and
    both are declared volatile -- but a consumer that leaned on the timestamp
    for identity would lose a factor of a million, so it is said here rather
    than found out.
    """
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def serialise(document) -> str:
    """The document as text, with every parameter that affects the bytes fixed.

    `indent` is stated rather than defaulted, because a default that changed
    would change the bytes. `ensure_ascii` is TRUE, and that is a decision with
    a consequence worth naming: a file name carrying lone surrogates -- which a
    POSIX file system can produce and which no encoder can represent -- is
    escaped rather than raising, so one undecodable name cannot cost the whole
    document. The price is that non-ASCII names are escaped in the output; they
    remain exact, and they round-trip.

    `sort_keys` IS NOT PASSED, AND MUST NOT BE. The order of the keys is
    imposed by `_in_key_order` from a declared table; asking `json.dumps` to
    sort as well would throw that order away and put the keys back in
    alphabetical order, silently. What sorting used to guarantee -- bytes
    independent of the order `build_document` writes its dictionaries in -- the
    table guarantees instead.
    """
    text = json.dumps(_in_key_order(document), ensure_ascii=True, indent=2)
    return _fold_two_key_objects(text)


def write_document(document, destination) -> None:
    """Write the document, with the line ending stated.

    `newline="\\n"` is NOT a detail: on Windows, text mode translates every
    `\\n` into `\\r\\n`, so the same document would come out as different bytes
    on two machines -- a divergence nothing in the document would declare.
    """
    destination = Path(destination)
    text = serialise(document)
    with destination.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(text)
        stream.write("\n")
