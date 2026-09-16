# unboxr

Deterministic recursive archive extraction. Standard library only.

`unboxr` opens a container, then the containers it finds inside it, and hands
you back a directory. Given a `.zip`, a `.tar.gz`, a `.whl`, an `.apk`, a
`.deb`, a URL pointing at one of those, or a directory that already contains
some, it produces one flat, fully-expanded tree.

## What unboxr is not

- **It renders no verdict.** It does not classify, score, rate or judge
  anything it extracts. It has no notion of risk, quality or compliance.
- **It says nothing about cryptography.** There is no analysis of the extracted
  content at all. What you do with the tree is entirely your business.
- **It has nothing to do with export control**, licensing, or any regulatory
  regime.
- **It is not a security scanner.** It applies the standard library's tar
  security filter because extracting an archive should not write outside the
  destination, and that is the whole of its ambition on that front.

## Install

Requires **Python 3.12 or later** and nothing else. Version 3.12 is the floor
because `TarFile.extractall(filter=...)`, which `unboxr` always passes, is only
guaranteed from that release onwards. Requiring it removes every conditional
code path: no capability probing, no degraded mode, one extraction behaviour.

```sh
pip install .
```

### Installing offline

`pip install .` applies **build isolation** by default: it downloads
`setuptools` from the package index even when a copy is already installed
locally. On an air-gapped machine that fails, and `unboxr` cannot be installed
at all. Use:

```sh
pip install --no-build-isolation .
```

`setuptools` is a **build** dependency. `unboxr` itself has **no runtime
dependencies**: it imports nothing outside the Python standard library.

## Use it from the command line

```sh
unboxr ARCHIVE DESTINATION
```

Three modes, and one contract: the extracted tree is always named after the
archive, never after a fixed word `unboxr` made up.

**Default.** The tree is created at `DESTINATION/<archive name>`, verbatim:

```sh
unboxr package-1.2.3.tar.gz ./unpacked
# -> ./unpacked/package-1.2.3.tar.gz/...
```

DESTINATION may hold other things -- `unboxr` claims a *name* inside it, not
the whole directory. It refuses to write into a path that is already taken by
something other than the archive itself, and says which path.

**`--replace`.** The archive is extracted *in place* and replaced by its own
content -- no DESTINATION is given at all:

```sh
unboxr --replace package-1.2.3.tar.gz
# -> ./package-1.2.3.tar.gz/... (the archive file is gone)
```

The archive is removed only after a successful extraction. Refused on a URL
(there is no local file to replace) and when the source is already a
directory.

**`--no-archive-dir`.** No directory named after the archive is created; the
content is unpacked straight into DESTINATION, which must then be empty or
absent -- the older rule, kept for this mode alone:

```sh
unboxr --no-archive-dir package-1.2.3.tar.gz ./unpacked
# -> ./unpacked/...
```

Here the extracted tree *is* DESTINATION, so no `--sbom` path under
DESTINATION is acceptable any more: the document would list every file
present when the extraction finished, itself included. Refused when the
source is already a directory.

`--replace` and `--no-archive-dir` are mutually exclusive.

| Option | Effect |
|---|---|
| `--replace` | extract the archive in place and replace it (see above) |
| `--no-archive-dir` | unpack straight into DESTINATION, no wrapper directory (see above) |
| `-v`, `--verbose` | show debug records as well |
| `-q`, `--quiet` | warnings only -- **plus every announced amputation** |
| `--sbom FILE` | also write the extraction document to FILE (see below) |
| `--linked-bom URN` | record which other BOM that document belongs to (see below) |
| `--list-formats` | print what *this machine* does with every recognised extension, and exit (see below) |
| `--json` | print that listing as JSON; requires `--list-formats` |
| `--version` | print the version and exit |
| `--help` | the full usage |

Exit codes: `0` success, `1` the run failed -- at extraction, **or** at writing
the document, `2` usage error.

`--sbom` is refused before anything is extracted when the path it names would
fall **inside the tree that is about to be inventoried**: that document claims
to list every file present when the extraction finished, and writing it there
makes the claim false at the moment it is written. `DESTINATION/sbom.json`,
beside the tree, is fine in the default and `--replace` modes; under
`--no-archive-dir` the tree *is* DESTINATION, so nothing beside it is left.
The same refusal applies to writing inside a source directory you handed
over, or over the source archive itself.

`--linked-bom` is refused, before anything is extracted and with nothing
created, in two cases. Without `--sbom` there is no document to record the link
in, and an option quietly ignored would let you believe something was recorded
when nothing was written at all. And a URN whose shape `unboxr` does not
recognise is refused rather than written: see below for what the shape is and
why nothing else checks it.

`--list-formats` is the one invocation that takes no ARCHIVE at all: it prints
what this installation can open and exits, extracting nothing. It is refused
when combined with an ARCHIVE, a DESTINATION, `--replace`, `--no-archive-dir`,
`--sbom` or `--linked-bom` -- an option quietly ignored would let you believe
an extraction took place. `-v` and `-q` are accepted and do nothing here. See
*7-Zip is optional* below.

Adding `--list-formats` cost two abbreviations: `--l` and `--li` used to reach
`--linked-bom` and are now ambiguous, refused with code 2. `--lin` and
anything longer are unaffected.

This command line is deliberately a **floor**. It writes no document unless you
ask for one, and it has no self-check gate, no strict mode and no verdict of
any kind.

## Use it as a library

```python
from pathlib import Path
import unboxr

prepared = unboxr.prepare_source("package-1.2.3.whl",
                                 workspace=Path("./unpacked"))
# prepared.tree   -> Path to the fully flattened extracted tree
# prepared.nature -> "source" | "built" | "undetermined" | "directory"
# prepared.digest -> bare hexadecimal SHA-256 of the input, None for a directory
# prepared.report -> what was opened, and what was not

for entry in prepared.report.not_opened:
    print(entry.path, unboxr.report.text_for(entry.code))
```

The report can also be **passed in**, which is what makes it survive the
exception that ends a run -- an office container given as the source is refused,
and *then* the run fails with nothing to return:

```python
held = unboxr.new_report()
try:
    prepared = unboxr.prepare_source("manual.docx", workspace=Path("./unpacked"),
                                     report=held)
except ValueError:
    print(held.amputation_count(), "container(s) were not opened")
```

Lower-level entry points -- `categorize_archive`, `is_archive`, `is_url`,
`extract_archive`, `flatten_nested_archives` -- are all exported. See
`unboxr/__init__.py` for the full list.

**The library is silent.** It never configures logging, never calls
`basicConfig`, and installs nothing but a `NullHandler` on its own root logger.
Importing `unboxr` and running a full extraction writes nothing to stdout and
nothing to stderr. To see what it is doing, configure logging yourself:

```python
import logging
logging.basicConfig(level=logging.INFO)
```

## What could not be opened

`unboxr` will refuse, skip or fail on some containers. Every one of those
**amputates** the tree you get back, and every one is in
`prepared.report.not_opened`, with a stable cause **code**:

| Code | What happened |
|---|---|
| `office_container_excluded` | an office container was set aside by policy (they are zips, and their content is markup) |
| `several_tars_only_first_extracted` | a `.7z` envelope held several `.tar` files and only the first was opened |
| `extraction_failed` | a container was recognised but could not be read |
| `maximum_depth_reached` | a container was still closed when flattening stopped |
| `tar_refused_by_security_filter` | a tar archive was refused whole by the filter |
| `tar_content_partly_moved` | a tar archive reached its destination only in part |
| `zstd_not_supported` | a Zstandard container was recognised and refused |
| `seven_zip_binary_missing` | a container needs a 7-Zip binary this machine has not got |

Translate the **code**, not the text: the text is derived from the code by one
table inside `unboxr`, so it can be reworded and the code cannot. A code your
version does not know is a code from a later one -- keep it distinct from
"nothing to report" rather than reading it as nothing.

Two other lists sit beside it, and neither is an amputation:
`report.still_in_tree`, where the content *is* in the tree but not where you
would look for it, and `report.widened`, where an archive was recognised by its
first bytes rather than by its extension -- a corpus that grows without a trace
is no better than one that shrinks without a trace.

**What could not be opened cannot be reported on: absence of a finding is never
evidence of absence.** The command line says the same thing out loud, and
`--quiet` never hides any of it: the most frequent amputation, the office
container, is announced at the informational level, so quiet mode keeps that one
too rather than raising the threshold blindly.

Zstandard is a special case: it is **recognised** and then **refused out loud**,
with an exception carrying the reason. Recognising it is the point -- an
unrecognised `.tar.zst` would cross the chain in silence.

## The extraction document

`unboxr --sbom FILE` writes a **CycloneDX 1.7** inventory of the corpus, so that
what was extracted stops being an assertion and becomes a record you can keep.
It holds one component per path:

- every file left in the tree, with its **SHA-256** digest -- no exception of
  extension, of size or of location;
- every container the flattening **destroyed**, with the digest taken while it
  still existed. A nested archive is removed once it is opened, so no walk of
  the finished tree could ever produce this;
- every container that was **not opened**, with its cause -- code and English
  text, as two separate properties.

It attests the presence and the digest of what it lists. It renders no verdict
of any kind.

**On the corpus, the oracle is positive only**: the document says nothing about
what was inside a container nobody opened.

**On the anomalies, it promises the opposite** -- every abnormal event this
package can observe is written, so a component with no properties is not a
silence: it says nothing abnormal happened to that path. That promise is what
makes the omissions above readable, and the two are one decision.

**The promise is bounded by what can be observed at a boundary this package
crosses**, and the bound is named here rather than left to be assumed. Three
things fall outside it: an archive whose library reads it "successfully" while
silently returning fewer members than it holds; an encrypted entry an external
7-Zip skips while returning success; a file name the operating system refuses
to materialise. The gap is narrow and nameable, which is what makes the promise
worth making -- a detector's gap is neither.

**No exclusion policy.** `unboxr` has none -- not `__pycache__`, not `.git`, not
`node_modules`. Whether those belong in an analysed corpus is the consumer's
policy, applied after extraction. Until 3.0 the document repeated that in a
property of its own, on every document, always with the same value; a constant
says nothing per document and belongs here.

The library form returns a structure and writes nothing:

```python
document = unboxr.build_document(prepared.report, prepared.tree,
                                 source="pkg-1.2.3.tar.gz",
                                 source_digest=prepared.digest,
                                 source_kind="archive")
unboxr.write_document(document, Path("sbom.json"))
```

### The properties it carries

**A property is written only when something abnormal happened.** A component to
which nothing happened carries none at all, and the `properties` key is absent
rather than empty.

That rule REVERSED in 3.0, and the reversal is the whole release. Until then
every property was emitted on every component -- a cause code reading
`no_entry`, seven hundred times over an ordinary archive -- because an omission would have
read as *not applicable* rather than *not determined*. That reasoning holds
under a positive-only oracle, where a silence cannot be told apart from an
unasked question. It stops holding the moment the document promises that every
anomaly it can observe is written: the omission then asserts something precise,
*nothing abnormal happened to this path*, and writing it out adds nothing.

Native CycloneDX fields -- `hashes`, `type`, `name`, `metadata.tools` -- are
used as they are and never wrapped in a property.

On `metadata.properties`, one name, and it is on every document:

| Name | Value |
|---|---|
| `unboxr:extractionOutcome` | `complete` / `failed` |

It is the flag that says whether the promise above **holds for this document**.
A run that died partway could not observe the anomalies it never reached, and
without it a truncated document would be indistinguishable from a clean one --
its silence reading as *nothing abnormal*.

On a component, when something abnormal is true of it:

| Name | Value |
|---|---|
| `unboxr:anomalyCode` | the anomaly code or codes, comma-separated |
| `unboxr:anomalyText` | their English texts, in the same order |
| `unboxr:parentContainer` | `not_determinable`, and no other value -- see below |

Translate the **code**, never the text: the text comes from one table and is
allowed to be reworded.

**One invariant holds the place of a property that used to state it.** Every
component carries either a digest, or an anomaly saying why it has none, or the
type `data` for a path that is not file content. A digest-state property said
this on every component until 3.0, including the ones whose digest was taken;
what had to survive is that a component can never go silent about a missing
digest.

**`unboxr:parentContainer` is written in one case only.** A nested archive is
flattened into a directory carrying its own name, so `outer.zip/inner.zip/a.c`
states its own ancestry and each container it names is itself a component: a
consumer reads the ancestry off the paths. Three cases defeat that reading --
a bare name, an unknown frame, and a path through a provisional extraction
directory, whose name is a digest. There a consumer walking prefixes would find
no parent and conclude there is **none**, turning *unknown* into a favourable
answer. The property says `not_determinable` exactly there, and nowhere else.

**Adding a property to the document is an addition to the contract** and raises
the minor version. **Removing one raises the major**, which is what 3.0 did to
fourteen of them.

### Which BOM this document belongs to

An extraction document is evidence for something else: the inventory of a
corpus that some other BOM draws a conclusion about. Rather than leaving the
two to be matched up by hand, on a file name or a timestamp, the document
records the link itself.

```sh
unboxr pkg-1.2.3.tar.gz ./unpacked \
    --sbom sbom.json \
    --linked-bom urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1
```

It lands at the **root** of the document, as a native `externalReferences`
entry of type `bom` -- never as a property of `unboxr`'s own, the schema
already providing the field:

```json
"externalReferences": [
  {
    "url": "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1",
    "comment": "The BOM this document belongs to, as supplied ...",
    "type": "bom"
  }
]
```

(Keys above are in the order the tool actually writes them. `serialise()`
emits each object's keys in the order `bom-1.7.schema.json` declares them --
which for an external reference is `url`, `comment`, `type` -- rather than
alphabetically. No JSON schema constrains the order of keys, so this is a
choice of readability and not a point of conformance; what it does guarantee
is that the bytes do not depend on the order the code happens to build its
dictionaries in. A `property` and a `hash` are each folded onto **one line**,
which is what keeps a document of a few thousand files readable:
`{ "name": "unboxr:extractionOutcome", "value": "complete" }`.

`serialise()` is public and will take a document it did not build. A key no
table declares is never dropped and never refused -- it comes out **after**
the declared keys, in alphabetical order -- so "the order the schema declares"
is exact for the documents this package produces and a best effort for
anything else.)

**The URN is handed over, never composed here.** How you number your own
documents is not `unboxr`'s business. The shape is `urn:cdx:<uuid>/<version>`,
where the UUID is the one inside the other document's `serialNumber` -- **bare,
with no `urn:uuid:` prefix** -- in **lowercase** hexadecimal, and the version is
that document's own, `1` or more.

From the library, the same link is a keyword argument of `build_document`:

```python
document = unboxr.build_document(prepared.report, prepared.tree,
                                 source="pkg-1.2.3.tar.gz",
                                 source_digest=prepared.digest,
                                 source_kind="archive",
                                 linked_bom="urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1")
```

A link it does not recognise raises `unboxr.InvalidBomLinkError` rather than
being dropped: writing no link would make the attachment you asked for vanish
into a document that looks exactly like one nobody wanted linked. The pattern
and the check are public -- `unboxr.BOM_LINK_DOCUMENT_PATTERN` and
`unboxr.is_bom_link_to_a_document` -- so a caller forming such a URN in the
other direction reads them from here instead of transcribing them again.

**What the link does not attest**, and the document says so in the entry's
`comment`: `unboxr` does not open the document you point at and does not
resolve it. It cannot know that it exists, and it cannot know that it describes
this extraction.

**No link, no key.** A document produced without the option carries no
`externalReferences` at all -- never an empty array, which would read as *we
looked, there is none*. The document's own scope warning states the rule for
reading that absence, so it cannot be mistaken for *this extraction belongs to
nothing*.

**Why `unboxr` checks the shape at all.** The published schema does not. An
external reference's `url` accepts a plain string, so a document carrying a
link that leads nowhere validates with zero errors -- measured against the
official 1.7 schema. A piece of evidence asserting a false attachment is worse
than one asserting none, so the check lives here: the URN is confronted with
the pattern the schema declares for a BOM-Link to a document, and anything it
does not recognise is refused rather than written.

**Two runs of the same upstream chain carry two different URNs.** The document
you point at is given a fresh serial number every time it is generated, so a
link recorded today and a link recorded tomorrow differ even when nothing else
did. That does not weaken this document's own determinism: the URN is an
*input*, and for one input the bytes are unchanged.

### `bom-ref` only means something against this document

Each component's `bom-ref` is derived from its rank in the sorted order, not
from its path -- a path would need escaping wherever a `bom-ref` is placed
after a `#` in a BOM-Link URN. **The consequence**: a rank renumbers every
time a file enters or leaves the corpus, so a link of the shape
`...#unboxr-component-7` is valid against *this exact document* and not
against "the extraction inventory of this package" in general -- a
regeneration would break it without saying so, and no validator would see it.

**That is why `--linked-bom` refuses that shape.** The only link `unboxr`
writes points at a **document**, never into one of its elements. The refusal
is this package's decision and not the format's, which admits both; it is
reversible, and nothing in the format would stop a later version from
accepting the element shape with the caveat above stated out loud.

### What it does not do

`unboxr` applies **no exclusion policy at all** -- not `__pycache__`, not
`.git`, not `node_modules`. Whether those belong in an analysed corpus is your
policy, applied after extraction. On a source that is already a directory, the
document therefore hashes everything under it, tooling directories included.

## 7-Zip is optional

Some formats are delegated to an external 7-Zip binary (`7z`, `7zz`, `7za` on
the PATH, or the default install location on Windows). Without it, those
formats fail to extract -- announced, never silent. `unboxr` does not bundle,
download or install it.

Every report says which binary was found, if any, and how many of the
recognised extensions depend on it -- measured on the machine that ran, not
supposed. Ask your own installation rather than trusting a number in a README:

```sh
unboxr --list-formats
```

From an unpacked clone, with nothing installed and no console script on the
PATH -- which is how a vendored copy and an air-gapped install both start out
-- the same listing comes out of:

```sh
python -m unboxr.cli --list-formats
```

Every figure it prints is counted from the extension tables at the moment you
run it, and the binary is looked for at the moment you run it. Nothing is
extracted, no ARCHIVE is taken, and nothing is written anywhere.

It sorts every extension `unboxr` knows by name into **four states**, because
two would be a lie:

| State | What it means |
|---|---|
| **Opened by the standard library** | opened here and on every machine: no binary, no dependency |
| **Delegated to an external 7-Zip binary** | opened *if* a binary was found -- the one state whose answer depends on the machine |
| **Recognised and refused** | recognised so the chain refuses them out loud rather than passing over them in silence. No machine opens these, and no installation adds the capability -- run the command to see which extensions are in this state on your copy |
| **Recognised and deliberately not opened** | office containers: ZIPs `unboxr` knows how to open and chooses not to |

On a machine **without** 7-Zip, the delegated extensions are still listed, and
marked not openable here. They are not dropped: removing them would say
`unboxr` does not recognise them, which is a different claim and a false one.

```sh
unboxr --list-formats --json
```

prints the same projection -- same four states, same totals -- for something
other than a human. `--json` requires `--list-formats` and is refused without
it, and `--list-formats` is refused together with anything that describes an
extraction: it would print a listing while extracting nothing, and let you
believe an extraction happened.

`-v`/`--verbose` and `-q`/`--quiet` are the exception to that refusal: they are
**accepted and have no effect** here. They govern the logging stream, and this
mode does not use it -- it prints its listing on stdout and emits no record at
all. Neither of them can make you believe an extraction took place, which is
the reason the others are refused.

## Network

One code path in the whole package touches the network: passing an `http(s)`
URL as the source, which downloads it before extracting. Everything else is
strictly local. There is no telemetry, no update check, and no index lookup.

## Determinism contract

`unboxr` guarantees these four properties. Everything else belongs to you.

1. **Traversal order.** Flattening, and the selection of the single `.tar`
   inside a `.7z` envelope, both iterate in the order of the POSIX relative
   path. The result does not depend on the order in which your file system
   happens to enumerate directory entries.
2. **Extraction directory names.** Two names, and they are not the same
   promise.
   - The **final** name: *every* archive -- at any nesting level, level 0
     included: the one you hand to `unboxr` directly, or the one downloaded
     from a URL -- is flattened into a directory carrying that archive's own
     name, in full and verbatim -- extension included, no case folding, no
     stripping. `toto.jar` yields `toto.jar/`. The name is *inherited* from
     the input rather than built here, so two archives that differ by a
     single character can no longer land in one directory and merge their
     content. Level 0 has two other modes besides this default one -- see
     "Use it from the command line".
   - The **provisional** name: that final path is held by the archive itself
     until it is removed, so the extraction is first written under a name
     derived from the SHA-256 digest of the archive's POSIX relative path --
     never from `hash()`, never from a rank, never from an absolute path. It is
     therefore invariant across interpreter runs, invariant across the nesting
     level at which the archive is met, and independent of every other archive
     in the tree. It has to be: it can stop being provisional (see below).

   One name, and one only, is **fabricated** here: the `_decompressed` suffix a
   single-file decompression falls back on when stripping the matched
   extension leaves no name at all
   -- one named literally `.gz`, `.pack.gz`, `.lzma`, `.xz`, `.bz2` or `.bz`,
   where no natural name exists to give the payload. It is required to match no
   recognised extension, failing which the payload would be re-detected as an
   archive at the next level and reported as an amputation that never happened.
3. **POSIX paths.** Every path used as a sort key or as a component of a
   produced name goes through `.as_posix()`. The provisional and fabricated
   names above are valid path components on Windows and on Linux alike. The
   final name is not this package's to promise: it is the name the input
   already carries on the file system it came from.

4. **The corpus report.** Every amputation of the corpus -- a container refused
   by policy, one recognised and not opened for want of a capability, one that
   failed to be read, one still closed when flattening stopped -- is in the
   report `prepare_source` *returns*, and the report is returned on every way
   out, the one that extracts nothing included. A report may also be passed in,
   and one that was survives the exception that ends a run. Each entry carries
   a stable cause **code**; its English text is derived from that code by one
   table, in `unboxr.report`, and never written a second time.

### The extraction document is not a fifth guarantee

`unboxr --sbom` produces the same bytes for the same tree, the serial number
and the timestamp aside -- which the document names itself, in a field of its
own. That is an **observation**, and it is deliberately not a fifth guarantee:
the document carries what *this* machine can open, so one archive yields two
different documents on two machines whose 7-Zip availability differs.
Promising byte-identity would make this contract false the first time that
happened. Compare two documents on one machine, under one version of `unboxr`.

### What the contract does not guarantee

- **No symbolic-link containment** in flattening. Links inside an extracted tree
  are left exactly as the archive wrote them.
- **No exclusion of tooling directories** such as `__pycache__`, `.git` or
  `.venv`. That is your policy, applied after extraction.
- **No guarantee on any document** you build downstream from the tree.
- **No guarantee on the corpus when the 7-Zip binary is absent.**
- **No guarantee that the tree matches what earlier versions produced**: the tar
  security filter refuses archives they extracted. In exchange, the behaviour is
  now stable from one Python release to the next.
- **No guarantee on what the report says about content.** It names containers,
  what became of them, and the SHA-256 digest of each one that could still be
  read when it was filed. It opens nothing to look inside, it says nothing
  about what any of it *means*, and *an absent entry establishes nothing* --
  the oracle is positive only **on the corpus**: an absent entry establishes
  nothing about what was inside a container nobody opened. It is NOT positive
  only on the anomalies, where guarantee 4 above promises the reverse, within
  the bound named under "The extraction document".
- **No guarantee that the provisional extraction name stays provisional.** It is
  normally transitory -- the directory is renamed as soon as the archive is gone
  -- but it becomes the *definitive* name of that directory whenever the rename
  fails, and a failed extraction leaves it behind too. It is deterministic in
  both cases, which is the whole reason it is a digest rather than a temporary
  directory.
- **No guarantee that the extraction root is a valid path component.** Its
  name is *inherited* from the input -- the archive's own name as given, or
  the last segment of its URL -- exactly as the final name of a nested
  archive already only inherits, never validates, its own name; this extends
  that same non-guarantee down to level 0, the root the whole tree grows
  from.

## Development

```sh
python -m unittest discover -s tests -t tests
```

The suite runs offline, with no network, no git, no 7-Zip binary and no
versioned fixture: every archive it needs is built on the spot.

`transport/` holds a separate suite that proves this code equivalent to the
block it was carved out of. It needs a checkout of that project and disappears
once the original is removed; see `transport/test_equivalence.py`.

## Licence

MIT. See [LICENSE.md](LICENSE.md).
