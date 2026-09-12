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

```sh
unboxr package-1.2.3.tar.gz ./unpacked
# -> ./unpacked/extracted/...
```

The destination must be empty or absent: `unboxr` refuses to write into a
directory that already holds something rather than merge into it. The extracted
tree is created in `DESTINATION/extracted`, and its path is printed on stdout so
you can pipe it.

| Option | Effect |
|---|---|
| `-v`, `--verbose` | show debug records as well |
| `-q`, `--quiet` | warnings only -- **plus every announced amputation** |
| `--version` | print the version and exit |
| `--help` | the full usage |

Exit codes: `0` success, `1` extraction failure, `2` usage error.

This command line is deliberately a **floor**. It reports nothing structured and
writes no document; later versions will.

## Use it as a library

```python
from pathlib import Path
import unboxr

tree, nature, digest = unboxr.prepare_source("package-1.2.3.whl",
                                             workspace=Path("./unpacked"))
# tree   -> Path to the fully flattened extracted tree
# nature -> "source" | "built" | "undetermined" | "directory"
# digest -> bare hexadecimal SHA-256 of the input, or None for a directory
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
**amputates** the tree you get back, and every one is announced through the
logging system, at the informational level or above:

- an office container is refused (they are zips, and their content is markup);
- a `.7z` envelope holds several `.tar` files and only the first is extracted;
- a nested archive fails to extract;
- the maximum nesting depth is reached;
- a tar archive is refused by the security filter.

**What could not be opened cannot be reported on: absence of a finding is never
evidence of absence.** `--quiet` never hides any of the six: the most frequent
of them, the office container, is announced at the informational level, so quiet
mode keeps that one too rather than raising the threshold blindly.

Zstandard is a special case: it is **recognised** and then **refused out loud**,
with an exception carrying the reason. Recognising it is the point -- an
unrecognised `.tar.zst` would cross the chain in silence.

## 7-Zip is optional

Some formats are delegated to an external 7-Zip binary (`7z`, `7zz`, `7za` on
the PATH, or the default install location on Windows). Without it, those
formats fail to extract -- announced, never silent. `unboxr` does not bundle,
download or install it.

Count them yourself rather than trusting a number in a README:

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

`unboxr` guarantees these three properties. Everything else belongs to you.

1. **Traversal order.** Flattening, and the selection of the single `.tar`
   inside a `.7z` envelope, both iterate in the order of the POSIX relative
   path. The result does not depend on the order in which your file system
   happens to enumerate directory entries.
2. **Extraction directory names.** Two names, and they are not the same
   promise.
   - The **final** name: a nested archive is flattened into a directory
     carrying that archive's own name, in full and verbatim -- extension
     included, no case folding, no stripping. `toto.jar` yields `toto.jar/`.
     The name is *inherited* from the input rather than built here, so two
     archives that differ by a single character can no longer land in one
     directory and merge their content.
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
- **No guarantee that the provisional extraction name stays provisional.** It is
  normally transitory -- the directory is renamed as soon as the archive is gone
  -- but it becomes the *definitive* name of that directory whenever the rename
  fails, and a failed extraction leaves it behind too. It is deterministic in
  both cases, which is the whole reason it is a digest rather than a temporary
  directory.

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
