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

It attests the presence and the digest of what it lists, and **nothing about
what is absent from it**. It renders no verdict of any kind.

The library form returns a structure and writes nothing:

```python
document = unboxr.build_document(prepared.report, prepared.tree,
                                 source="pkg-1.2.3.tar.gz",
                                 source_digest=prepared.digest,
                                 source_kind="archive")
unboxr.write_document(document, Path("sbom.json"))
```

### The properties it carries

Every one of them is emitted on **every** document, including when the value is
not computable -- in which case the non-computable state is written out. A
property that appeared only in the favourable case would read, by its absence,
as *not applicable* rather than *not determined*.

Native CycloneDX fields -- `hashes`, `type`, `name`, `metadata.tools` -- are
used as they are and never wrapped in a property.

On `metadata.properties`, what is true of the run:

| Name | Value |
|---|---|
| `unboxr:documentScope` | what this document does and does not attest |
| `unboxr:oracleReminder` | absence of a finding is never evidence of absence |
| `unboxr:volatileFields` | the fields not promised from one run to the next |
| `unboxr:exclusionPolicy` | `none` -- see below |
| `unboxr:sourceKind` | `archive` / `directory` / `undetermined` |
| `unboxr:extractionOutcome` | `complete` / `failed` |
| `unboxr:sevenZipAvailable` | `true` / `false` |
| `unboxr:recognisedExtensions` | how many extensions this version recognises |
| `unboxr:extensionsNeedingSevenZip` | how many of those need the binary |
| `unboxr:depthReached` / `unboxr:depthLimit` | two numbers, or `not_applicable` |
| `unboxr:containersNotOpened` | the size of the amputation |
| `unboxr:filesWithoutDigest` | components whose digest state is not `computed` |

On each component, what is true of one path:

| Name | Value |
|---|---|
| `unboxr:causeCode` | the cause code or codes, or `no_entry` |
| `unboxr:causeText` | their English texts, in the same order |
| `unboxr:digestState` | `computed` / `read_failed` / `not_a_file` / `symlink_not_followed` |
| `unboxr:nestingLevel` | `0`..`n`, or `unknown` |
| `unboxr:parentContainer` | the container it came out of, `none`, or `not_determinable` |

Translate the **code**, never the text: the text comes from one table and is
allowed to be reworded.

**Adding a property to the document is an addition to the contract**, and
raises the minor version. Every property is emitted systematically, so every
consumer sees a new one on the first document produced after the change.

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
`{ "name": "unboxr:digestState", "value": "computed" }`.)

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
supposed. Count them yourself rather than trusting a number in a README:

```sh
python -c "import unboxr; t=unboxr.CATEGORY_BY_EXT; \
print(len(t), 'extensions,', \
sum(v in ('external_7zip','tar_7z') for v in t.values()), 'need 7-Zip')"
```

```sh
python -c "import unboxr; print(len(unboxr.NOT_EXTRACTED_EXTENSIONS), 'excluded')"
```

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
  the oracle is positive only, here as everywhere else.
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
