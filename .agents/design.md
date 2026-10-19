# RFC 0040: `zumime`, what a file is, from its bytes and its name

Adopted from [RFC 0040](https://github.com/pedrobtz/packages/blob/main/rfcs/started/0040-zumime-media-type-detection.md) on 2026-10-18. From here on this file is authoritative; the RFC is history.

- **Status:** Proposed. Merging this file adopts the design as the starting
  point for the package's own `.agents/design.md`; each decision in section
  13 stays the maintainer's until the package repository records it. Every
  decision here is **(C)**: the maintainer asked for the RFC to be written
  from the sketch without a design conversation, so none is marked **(M)**
  and D3 (confidence levels), D6 (host-independent output) and D9 (the
  incremental sniffer's shape) are the ones most worth a second look.
- **Date:** 2026-10-18.
- **Packages:** `zumime` (repository `pedrobtz/zumime` created 2026-10-18
  from the `create-pkg.sh` scaffold; the name was free on crandb on
  2026-10-17 per `base-layer-candidates.md`). No `Imports`. No
  `LinkingTo`. `Suggests: testthat, zukomp, zuutf, zucsv, zujson, zutoml`.
  One shared object; vendors no code (D7); ships two generated tables
  (D8). MIT.
- **Source:** this repository's `rfcs/base-layer-candidates.md` §5.1 as of
  commit `074b398` (2026-10-18), which this RFC promotes and whose five
  open questions it settles; the WHATWG MIME Sniffing Standard (living
  standard, read 2026-10-18) for the algorithm, its signature table, the
  text-or-binary rule and the MIME type record grammar; the WHATWG
  Encoding Standard's `<meta>` prescan; Go's `net/http/sniff.go` and
  `sniff_test.go` (BSD-3) as a second implementation of the WHATWG table;
  `sindresorhus/file-type` 22.2.0 and `h2non/filetype` 1.2.0 (both MIT)
  for container inspection and the fixture corpus; `gabriel-vasile/mimetype`
  1.4.16 (MIT) for the type hierarchy, aliases, the OLE2 reader after
  libmagic's `readcdf.c`, and the configurable read limit; IANA's media
  types registry and Apache httpd's `mime.types` (Apache-2.0) as table
  sources; CRAN's correspondence on `zukomp`, `zucrypt` and `zuxml` in
  October 2026 on copyright holders of generated data. Nothing has been
  built.

## 1. What zumime is

`zumime` says what a file is. It answers from two signals, the bytes and
the name, in one call that reports both answers and whether they agree.
The byte answer is the WHATWG MIME Sniffing algorithm, which is what a
browser runs on a response, extended with the container inspection that
`file-type` and `mimetype` do (ZIP entry names, ISO base media brands,
RIFF, EBML, Ogg, OLE2 directories, the tar checksum) and with the data
formats R users hold (RDS, RData, Parquet, Arrow, SQLite, HDF5, Stata,
SPSS, SAS). The name answer is a generated extension table. Every type
has a parent, ending at `application/octet-stream`, so an unknown
ZIP-based format is still `application/zip`. Nothing is read from the
host: no `mime.types`, no registry, no libmagic, so the answer is the
same on every machine.

The one-line statement that governs every decision below:

> **The browser's sniffing algorithm, the Go sniffers' hierarchy and
> containers, R's own data formats, vectorised over paths, with no
> dependency and no system library.**

### 1.1 What zumime is not

- **Not a metadata extractor.** Image dimensions, durations, page
  counts, EXIF and document authors need a parser per format and read
  past the header. A metadata package, if wanted, builds on `zumime`'s
  answer and is its own RFC.
- **Not a multipart or mail parser.** `parse_multipart()` is HTTP body
  parsing and belongs to `zuhttp` or `zusocks`; RFC 2047 encoded words
  belong to whatever handles mail.
- **Not a filesystem tool.** Size, times, permissions and links are
  `file.info()` and `fs`. `zumime` reads bytes, not inodes.
- **Not a hasher.** Content hashes are `zufast`'s and `zucrypt`'s.
- **Not a charset detector for unlabelled legacy text.** Declared and
  structural charsets (BOM, XML declaration, HTML `<meta>`, valid UTF-8)
  are `zumime`'s; statistical detection is `zuutf`'s.

### 1.2 Where it sits among existing packages

R's `mime` package (GPL) maps extensions to types from a copy of Apache's
table and is what rmarkdown and shiny import; it cannot look at content.
`wand` wraps libmagic, a system dependency that varies by host and
version. Python's `mimetypes` and npm's `mime` are extension tables too;
the sniffers people trust there are `filetype` and `file-type`, pure
signature tables with container inspection and no dependencies. Go ships
the WHATWG algorithm in its standard library, and `gabriel-vasile/mimetype`
is the most complete pure sniffer in any language, with a type hierarchy
and about two hundred formats. No package in any language implements the
whole WHATWG algorithm with its supplied type, no-sniff flag and context;
browsers do. None knows R's own files.

`zumime`'s claim: all of that in one R package with no `Imports`, a
vectorised C loop over paths that reads headers only, and the questions a
consumer asks next ("is it compressed, encrypted, truncated, which line
endings") answered from the same bytes.

## 2. Scope

**In v0.1.0:**

- **The WHATWG algorithm** (§6.1): `mime_sniff()` over a raw vector or a
  path, with a supplied type, a no-sniff flag and a sniffing context,
  returning the computed type as the standard defines it.
- **The signature table and containers** (§6.2): the WHATWG table, the
  offset signatures (tar at 257, ISO 9660 at 32769), and the container
  readers that tell docx from zip, mp4 from m4a, mkv from webm.
- **The type hierarchy** (§6.3): parent links, aliases, categories,
  `mime_parent()`, `mime_is()`, `mime_check()`.
- **Structured text by its root** (§6.4): XML by root element and
  namespace, JSON by top-level keys, line-oriented formats and scripts
  by first line, at the `probable` level.
- **Charset** (§6.5): BOM, UTF-8 validity, the C1 rule, XML declaration,
  HTML `<meta>` prescan, supplied type wins.
- **The extension table** (§6.6): `mime_guess()`, `mime_extensions()`,
  `mime_types()`, generated from IANA and Apache (D8).
- **`mime_type()` over paths** (§6.7): vectorised, both signals, the
  `agree` flag, and the how-to-open columns: wrapping layer, encryption,
  completeness, newline style, interpreter.
- **The MIME type record** (§6.8): `mime_parse()` and `mime_format()` per
  the WHATWG grammar.
- **User-registered detectors** (§6.9): a data-driven rule run in C, or
  an R function, attached under a parent for the session.
- **An incremental sniffer** (§6.10): push chunks, get `NULL` or a result.
- A README and one article, "Checking an upload before you open it".

**Not in v0.1.0, and why:**

- **A C API.** `zuhttp` and `zusocks` would want `zumime_sniff()` from C
  without the R call. The header needs the type registry visible from C
  and a stable result struct, which the first version should settle in R
  first (§14).
- **Statistical charset detection.** `zuutf`'s (§1.1).
- **Decompressing to sniff the inner type by default.** It needs `zukomp`
  and makes the default answer depend on what is installed (D6). It is
  available on request (§6.7).
- **Metadata of any kind** (§1.1).
- **Reading connections.** Paths and raw vectors in v0.1.0; the
  incremental sniffer covers streams the caller reads.

## 3. Position in the `zu*` family

| | zumime |
| --- | --- |
| Role | R API; later a provider (§14) |
| R prefix | `mime_` |
| Info function | `zumime_info()` |
| Root condition class | `zumime_error` |
| Internal C prefix | `zumime_` |
| From C | no (§14) |
| Hides symbols | yes (R3) |
| Vendored code | none (D7); generated tables (D8) |
| `Depends: R` | 4.1 (R2) |
| Language | en-GB (R2) |

**Relationships:**

- **`zukomp`**: `Suggests`. Decompresses the first block of a gzip, zstd,
  xz or bzip2 stream when `inner = "decompress"` is asked (§6.7).
- **`zuutf`**: `Suggests`. Statistical charset detection when
  `charset = "detect"` is asked (§6.5).
- **`zucsv`, `zujson`, `zutoml`**: `Suggests`. Their sniffers refine a
  `text/plain` answer when `text = "family"` is asked (§6.4).
- **`zurds`** (RFC 0015): a consumer. Recognises RDS and RData through the
  compression wrapper to the serialisation header and its version, which
  `zurds` wants before it opens a file.
- **`zuhttp`, `zusocks`**: consumers. `Content-Type` on uploads, checking
  a response against its declared type, the incremental sniffer on the
  first chunk.
- **`zupdf`, `zuxlsx`**: consumers. Refuse an encrypted or truncated file
  before their parsers start.
- **`dastash`, `zudedup`, `zuarchive`, `anydoc`**: consumers. Tree scans,
  manifests, archive entries, choosing a converter.

## 4. Architecture

Four layers, two of them generated:

1. **The type registry** (generated, D8). `tools/generate-tables.R`
   reads IANA's media types registry (the CSV files per top-level type)
   and Apache httpd's `mime.types`, and the hand-maintained
   `tools/types.yaml` that adds what neither has: parents, aliases, the R
   and analytic data formats, and the canonical extension where Apache
   lists several. It emits `R/sysdata.rda` (the data frame behind
   `mime_types()`) and `src/zumime_types.h` (an enum of type ids and a
   string table), so R and C name the same types by the same ids and the
   two can never drift. `tools/table-sources.yaml` records each upstream
   file's URL, retrieval date and SHA-256; a scheduled workflow
   regenerates and opens a pull request when a checksum changes.
2. **The sniffer** (`src/zumime_sniff.c`, `src/zumime_table.c`). The
   WHATWG algorithm as the standard writes it: resource header of 1445
   bytes, the pattern-matching algorithm with byte masks and ignored
   leading bytes, the image, audio-or-video, font and archive tables,
   text-or-binary, the Apache bug check. The signature table is data: rows
   of `{offset, pattern, mask, type id, parent id, flags}` in C, the
   WHATWG rows first and in the standard's order so its tests pass
   unchanged, then the offset signatures and the R data formats. A row
   whose type has a parent runs only after the parent matched.
3. **The container readers** (`src/zumime_zip.c`, `_ole2.c`, `_bmff.c`,
   `_riff.c`, `_ebml.c`, `_ogg.c`, `_tar.c`, `_text.c`). Each refines
   one parent type: ZIP by central-directory entry names read
   uncompressed; OLE2 by the directory's class id and stream names,
   permissive of truncation; BMFF by `ftyp` brands; RIFF, EBML and Ogg
   by their subtype fields; tar by its checksum; text by root element,
   top-level keys, first line or shebang. They share one bounded reader
   over the bytes already in hand and never allocate on the R heap.
4. **The R surface** (`R/`). Vectorisation over paths happens in C
   (`src/zumime_path.c`): one loop opens each file, reads `limit` bytes,
   runs layers 2 and 3, does the deep probes a result asks for (the ISO
   9660 seek, the ZIP tail, the completeness check), and fills the
   columns of §6.7. R builds the data frame from parallel vectors once.

Layers 2 and 3 compile as C11 without R under `ZUMIME_STANDALONE`, which
is how the fuzz target builds them. The only place a `CHARSXP` is made
from a type id is one function in `src/zumime_r.c`.

## 5. Public R API (v0.1.0 shape)

```r
# from bytes: the WHATWG algorithm
mime_sniff(x, type = NULL, no_sniff = FALSE,
           context = c("none", "browsing", "image", "audio_video", "font"),
           limit = 4096L)
# from the name
mime_guess(path)                        # type or NA, by extension
mime_extensions(type)                   # list; canonical extension first
# both, with how-to-open columns
mime_type(path, limit = 4096L, complete = FALSE,
          inner = c("name", "decompress"), text = c("whatwg", "family"),
          charset = c("declared", "detect"), strict = FALSE)
# the hierarchy
mime_parent(type)                       # lineage up to application/octet-stream
mime_is(x, what)                        # type, alias or category; descendants count
mime_check(x, allowed)                  # the upload question, vectorised
mime_types()                            # the registry as a data frame
# the MIME type record (WHATWG)
mime_parse("text/html; charset=UTF-8")  # list(type, subtype, parameters)
mime_format(record)                     # serialised, parameters quoted as needed
# detectors for the session
mime_register(type, parent, extensions = NULL,
              rule = list(offset, bytes, mask = NULL) | function(raw) ...)
mime_unregister(type)
# incremental
s <- mime_sniffer(type = NULL, no_sniff = FALSE, context = "none", limit = 4096L)
mime_push(s, chunk)                     # NULL while undecided, else a result row
mime_finish(s)                          # a result from what has been seen
zumime_info()
```

### Results

`mime_sniff()` on a raw vector returns one row; on paths, one row per
path. `mime_type()` returns the same frame with the name columns added.
The frame is a plain `data.frame` with a `zumime_result` class for
printing only.

| Column | Type | Meaning |
| --- | --- | --- |
| `path` | character | the input, `NA` for a raw vector |
| `type` | character | canonical essence, e.g. `application/zip` |
| `confidence` | factor | `definite`, `probable`, `extension`, `none` (D3) |
| `charset` | character | the charset parameter, or `NA` |
| `by_name` | character | `mime_guess(path)`; `mime_type()` only |
| `agree` | logical | `type` equals or descends from `by_name`; else `NA` |
| `inner` | character | type inside a compression wrapper, or `NA` |
| `encrypted` | logical | `TRUE`, `FALSE`, or `NA` when the format has no flag |
| `complete` | logical | `NA` unless `complete = TRUE`; §6.7 |
| `newline` | character | `lf`, `crlf`, `cr`, `mixed`, or `NA` for binary |
| `interpreter` | character | the shebang's program, or `NA` |

`type` is never `NA` for readable input: the floor is
`application/octet-stream` at `confidence = "none"`, or `text/plain` when
the text-or-binary rule says text. The lineage is one `mime_parent()`
call away and is not a column.

## 6. Semantics

### 6.1 The WHATWG algorithm

`mime_sniff()` implements the MIME Sniffing Standard's "MIME type
sniffing algorithm" with its three inputs: the supplied MIME type (the
`Content-Type` header, or `NULL`), the no-sniff flag, and the sniffing
context. The resource header is the first 1445 bytes of the input, or
all of it when shorter. The outcome is the computed MIME type, as the
standard defines it for each case: a supplied type that is not sniffable
is returned as is; `text/plain` with the Apache bug check set is sniffed;
an unknown or absent supplied type runs the identification of an unknown
type; an image, audio-or-video or font context runs the matching
specific algorithm and returns the supplied type when no pattern matches;
`browsing` is the navigation case. The context `none` is "no supplied
type, no context", the plain file question.

The standard's tables are implemented as it lists them, in its order,
with its byte masks and its leading-bytes-to-ignore rule for HTML, so a
test written against the standard passes. Beyond the standard, when the
result is `application/octet-stream` or a parent type with a container
reader, layers 2 and 3 of §4 refine it (§6.2); this is the one place
`zumime` is more specific than a browser, and the result row says so by
its `confidence`.

### 6.2 Signatures and containers

A signature row matches when the bytes at its offset, masked, equal its
pattern, and its parent (if any) matched already. Rows are tried in table
order within a parent, so the first match wins and the table encodes the
priority, as the standard's does. Offsets beyond the first read (ISO 9660
at 32769) are satisfied by a seek when the input is a path and are
skipped for a raw vector shorter than the offset.

Container readers run after their parent matched and only on the bytes
in hand plus, for paths, one bounded tail read:

- **ZIP**: the end-of-central-directory record from the last 66 KiB
  (the record plus the largest comment), then the central directory
  entry names, read uncompressed. `[Content_Types].xml` plus a `word/`,
  `xl/` or `ppt/` folder is Office; a `mimetype` entry is EPUB or
  OpenDocument by its content; `META-INF/MANIFEST.MF` is JAR;
  `AndroidManifest.xml` is APK. The general-purpose flag and the AES
  extra field on any entry set `encrypted`.
- **OLE2**: the directory stream, read as `readcdf.c` does and tolerant
  of truncation; class id and the presence of `WordDocument`, `Workbook`,
  `PowerPoint Document`, `__properties_version1.0` or `EncryptionInfo`
  streams decide `.doc`, `.xls`, `.ppt`, `.msg`, `.msi` and encrypted
  Office.
- **ISO base media**: the `ftyp` box's major and compatible brands decide
  mp4, m4a, m4v, mov, 3gp, heic, heif, avif, cr3.
- **RIFF**: the form type at offset 8 decides wav, avi, webp.
- **EBML**: the `DocType` element decides mkv against webm.
- **Ogg**: the first page's codec header decides opus, vorbis, flac,
  theora, speex.
- **tar**: the header checksum at 148 must verify; a bare `ustar` magic
  is not enough.
- **Compression wrappers**: gzip, zstd, xz and bzip2 are types in their
  own right and set `inner` (§6.7).
- **R and analytic data**: RDS and RData by their compression wrapper
  (gzip, bzip2, xz, zstd, or none) to the `X\n` or `RDX2\n`/`RDX3\n`
  header and the serialisation version; Parquet (`PAR1`, both ends),
  Arrow IPC and Feather (`ARROW1`, `FEA1`), fst, qs2, SQLite, DuckDB,
  HDF5 (at 0, 512, 1024, …), NetCDF classic, Stata `.dta`, SPSS `.sav`
  and `.por`, SAS `.sas7bdat` and `.xpt`.

A match from a signature or a container is `confidence = "definite"`.

### 6.3 The hierarchy

Every type in the registry has one parent, the root being
`application/octet-stream`; text types descend from `text/plain`, XML
dialects from `application/xml`, JSON dialects from `application/json`,
ZIP-based formats from `application/zip`, and so on. `mime_parent(type)`
returns the lineage as a character vector, nearest first, empty for the
root. `mime_is(x, what)` is `TRUE` when `x`'s canonical type equals
`what`, descends from it, or has `what` as its top-level type
(`"image"`); aliases, parameters and case are ignored on both sides, so
`mime_is("application/x-sqlite3", "application/vnd.sqlite3")` is `TRUE`.
`mime_check(x, allowed)` vectorises `mime_is()` over paths against a set
and, when sniffing a path, runs only the detectors for the allowed types
and their ancestors, so an allowlist of three types costs three probes.

Canonical names are the registry's and are versioned with the table:
`zumime_info()$table_version` is the date of the table sources, and a
canonical name changes only with a `NEWS.md` entry. Aliases are the
names other tools emit for the same format, taken from `mimetype`'s list
and IANA's deprecated entries.

### 6.4 Structured text

When the WHATWG result is `text/plain`, `text/xml`-like or `text/html`,
the text reader looks further, at the `probable` level because the
evidence is grammar, not magic:

- **XML**: the root element's local name and namespace decide SVG, RSS,
  Atom, KML, GPX, X3D, XLIFF, COLLADA, XHTML, DocBook and OpenDocument
  flat XML, after the declaration, comments and processing instructions.
- **JSON**: the top-level object's first keys, read without a full parse,
  decide GeoJSON (`type` plus `features` or `geometry`), glTF (`asset`),
  HAR (`log`), CycloneDX (`bomFormat`), and NDJSON by a newline-separated
  sequence of objects.
- **Line-oriented**: the first line decides vCard, iCalendar, SubRip,
  WebVTT, WARC, PGP armour, PEM, and the shebang's interpreter decides
  shell, Python, Perl, PHP, Lua, Tcl, Node scripts.

With `text = "family"`, a `text/plain` result that is still generic is
offered to the family's sniffers when they are installed: `zucsv`'s for
delimited text, `zujson`'s and `zutoml`'s plausibility checks. Their
answers are `probable` too, and `zumime_info()` lists which were used.
The default `"whatwg"` never consults them (D6).

### 6.5 Charset

A text result carries `charset`, decided in this order and stopping at
the first that answers: the supplied type's `charset` parameter; a
byte-order mark (UTF-8, UTF-16 LE and BE); for XML, the declaration's
`encoding`; for HTML, the `<meta>` prescan of the Encoding Standard over
the first 1024 bytes; valid UTF-8 over the bytes read, ignoring a code
point cut by the read limit; the C1 rule, where a byte in 0x80–0x9F among
otherwise single-byte text means `windows-1252` and none means
`iso-8859-1`, both reported as `probable`. `NA` when nothing answers.
With `charset = "detect"` and `zuutf` installed, `zuutf`'s statistical
detection runs where this chain gives `NA` or the C1 guess.

### 6.6 The extension table

`mime_guess(path)` takes the longest known suffix after the last
directory separator, case-insensitively, so `.tar.gz` is known as a
compound and `report.FINAL.PDF` is PDF. It returns the canonical type or
`NA`. `mime_extensions(type)` is the reverse, a list of character vectors
with the canonical extension first, where canonical is Apache's first
listed extension unless `tools/types.yaml` overrides it (`.jpg` over
`.jpeg`, `.yaml` over `.yml`). `mime_types()` returns the whole registry:
type, parent, aliases, extensions, category, and `detected_by`, one of
`signature`, `container`, `text`, `extension`, `registered`.

### 6.7 `mime_type()` over paths

One C loop over the paths: open, read `limit` bytes (default 4096, D4;
`0` reads the whole file), sniff, probe, close. Every 256 files it checks
for a user interrupt. Unreadable or missing paths give a row with `type`
`NA` and `confidence = "none"`, and raise `zumime_io_error` only with
`strict = TRUE`, so one bad entry does not abort a tree scan. Directories
are `inode/directory` at `definite`, after libmagic's convention, and
nothing is read from them.

The how-to-open columns come from the same bytes:

- **`inner`.** For gzip, zstd, xz and bzip2, the type inside. The default
  `inner = "name"` takes it from the remaining extension (`.tar` of
  `.tar.gz`, `.csv` of `.csv.gz`) at `confidence = "extension"`;
  `inner = "decompress"` decompresses the first block through `zukomp`
  and sniffs it, erroring with `zumime_dependency_error` if `zukomp` is
  not installed. With `inner = "name"` the default answer never depends on
  what is installed (D6).
- **`encrypted`.** ZIP entries with the general-purpose encryption flag or
  the AES extra field; PDFs whose trailer names an `/Encrypt` dictionary
  (read from the tail along with `complete`, so `NA` unless the tail was
  read); OLE2 files with an `EncryptionInfo` stream. `NA` for formats with
  no encryption flag.
- **`complete`.** Opt-in by `complete = TRUE` (D5), because it reads the
  file's end as well as its start: a ZIP without its end-of-central-
  directory record, a PDF without `%%EOF` in its last 1 KiB, a gzip
  without its 8-byte trailer, a Parquet file without its trailing `PAR1`,
  an RDS stream whose compression wrapper is cut. `TRUE`, `FALSE`, or
  `NA` where the format has no end marker.
- **`newline`** and **`interpreter`.** For text results, the line-ending
  style seen in the bytes read and the program named by a shebang.

`agree` is `TRUE` when the byte answer equals the name answer or
descends from it, `FALSE` when both are known and differ, `NA` when
either is unknown. A disagreement is a finding, not an error; the caller
decides.

### 6.8 The MIME type record

`mime_parse()` is the standard's "parse a MIME type": type and subtype
as HTTP token code points, lower-cased; parameters as an ordered named
list with quoted-string values unescaped, duplicates dropped keeping the
first, names lower-cased and values as given; `NULL` for input that
fails to parse. `mime_format()` is "serialize a MIME type", quoting a
value when it is not a token. Both are vectorised over character
vectors and are pure R-callable C.

### 6.9 Registered detectors

`mime_register(type, parent, extensions, rule)` adds a type for the
session under a parent in the hierarchy. A data rule
`list(offset, bytes, mask)` is appended to the parent's table in C and
costs the same as a built-in row. A function rule is called from R with
the bytes read and must return `TRUE` or `FALSE`; it runs last, only
when the parent matched, and is the slow path. A registered type
appears in `mime_types()` with `detected_by = "registered"` and is
reported at `definite` for a data rule and `probable` for a function.
Registration is per session and is not saved; a package that wants its
format recognised registers in `.onLoad()`.

### 6.10 The incremental sniffer

`mime_sniffer()` returns an external pointer (D9) whose protected field
is an R raw vector of `limit` bytes that owns the buffer, so nothing is
leaked across a longjmp and the object serialises as "undecided".
`mime_push(s, chunk)` appends and returns `NULL` while the bytes seen
cannot yet decide the type at `definite`, or the result row once they
can, after which further pushes are ignored. "Can decide" means: the
WHATWG algorithm has a match that no longer row could override, or the
container reader has what it needs, or `limit` bytes have arrived.
`mime_finish(s)` forces an answer from what has been seen, as the end of
a short stream would. Deep probes and the tail-reading columns are `NA`
for a stream.

### 6.11 Determinism and limits

The same bytes give the same row on every platform and R version with
the same table version (D6). Inputs are bytes; no path or content is
re-encoded. The read limit is at most `.Machine$integer.max`; a raw
vector longer than `limit` is sniffed on its first `limit` bytes. A path
is opened in binary mode and never written.

## 7. The oracles

Three implementations of the same rules stand in for a conformance
suite, none of them a dependency:

1. **The standard's own tests.** web-platform-tests' `mimesniff/` holds
   the parse-and-serialize fixtures (`mime-types.json`,
   `generated-mime-types.json`) that `mime_parse()` and `mime_format()`
   must pass unchanged.
2. **Go's `net/http`.** `sniff_test.go`'s cases are the WHATWG table in
   use; `mime_sniff()` with no context must agree on every one.
3. **`file-type`'s fixtures.** One file per format under the repository's
   `fixture/` directory at a pinned commit. `mime_type()`
   must name the type `file-type` names (through the alias list where
   the canonical strings differ) for every fixture whose format `zumime`
   claims, and the test lists the ones it does not claim so the gap is
   explicit.

The fixtures are fetched by `tools/fetch-fixtures` at the pinned commit
into `tests/testthat/fixtures/`, which `.Rbuildignore` and `.gitignore`
exclude; the tests skip with a message when the directory is absent, and
the CI test job runs the fetch first.

## 8. Errors

Every condition inherits from `zumime_error`; tests assert on class.

| Class | Raised when |
| --- | --- |
| `zumime_type_error` | an argument is not a path, raw, type or rule |
| `zumime_io_error` | a path cannot be read and `strict = TRUE` |
| `zumime_parse_error` | `mime_parse()` is asked to error on invalid input |
| `zumime_registry_error` | `mime_register()`: unknown parent or existing type |
| `zumime_dependency_error` | a suggested package is asked for and absent |
| `zumime_state_error` | `mime_push()` on a finished sniffer |

`mime_sniff()`, `mime_type()` with `strict = FALSE`, `mime_guess()`,
`mime_is()` and `mime_check()` never raise on input.

## 9. Testing

`testthat` 3e. One file per subsection of §6. The WHATWG algorithm is
tested first on hand-built inputs, one per table row, generated from the
table itself (pattern bytes under the mask, padded to the resource header
length) so that every row is exercised, then against the oracles of §7.
Each container reader has fixtures built in the test from bytes, not
files: a minimal ZIP with named entries, an OLE2 directory with the
stream names, a `ftyp` box per brand, so the tests need no corpus to
run. The extension table has a round-trip property: for every type,
every extension in `mime_extensions(type)` maps back by `mime_guess()`
to that type or a descendant. The hierarchy test walks every type to the
root and finds no cycle. Charset has a table of inputs per rule in §6.5.
The incremental sniffer is tested by feeding every fixture one byte at a
time and checking it decides at the same type as the whole, and never
later than `limit`. Snapshot tests cover printing and the `agree` column
on a small tree under `tempdir()`. A fuzz target under
`ZUMIME_STANDALONE` runs random and mutated-fixture bytes through layers
2 and 3 and checks: no crash, no read past the buffer, every type id is
in the registry, and the result for a prefix is the whole's type or one
of its ancestors. From the family (R3): `test-abi.R`, that the shared
object exports `R_init_zumime` only.

## 10. Performance targets

Measured by `tools/run-benchmarks`, recorded in `.agents/benchmarks.md`,
with the baseline run in Stage 0 before any `zumime` code exists.

| Operation | Target |
| --- | --- |
| `mime_sniff()` on a 4 KiB raw vector | under 5 µs |
| `mime_type()`, 10⁵ files, warm cache | under 2 s; within 2× of `file` |
| `mime_type()` on the §7.3 corpus | within 3× of `mimetype`'s Go CLI |
| `mime_guess()` over 10⁶ paths | under 1 s |
| `mime_parse()` over 10⁶ headers | under 2 s |
| `mime_check()`, 3 allowed types | at least 3× faster than `mime_type()` |
| `mime_push()` per chunk | under 1 µs when undecided |

The honest ceiling is libmagic, which has three decades of tuned tables
and reads about the same bytes; a signature table in C should sit beside
it, not behind it. `mime` (extension only) is the floor for
`mime_guess()` and should be matched by a vectorised lookup.

## 11. Roadmap

Stages run the quick CI profile unless marked `full`. Each is one pull
request, merged on green. Riskiest first: the generated registry and the
WHATWG core before the long tail of containers.

| Stage | Delivers | Exit criterion |
| --- | --- | --- |
| 0 | repository, CI, table generator, baseline | tables generated; §10 bar |
| 1 | registry functions, parse and format | §6.3, §6.6, §6.8; §7.1 |
| 2 (`full`) | `mime_sniff()`: WHATWG algorithm, charset | §6.1, §6.5; §7.2 |
| 3 | containers, R and analytic formats, structured text | §6.2, §6.4; §7.3 |
| 4 | `mime_type()` over paths, `mime_check()`, `mime_register()` | §6.7, §6.9 |
| 5 | incremental sniffer, fuzz target, benchmarks | §6.10, §9, §10 |
| 6 (`full`) | README, article, release preparation | §12 |

Stage 0 writes `tools/table-sources.yaml`, generates `R/sysdata.rda` and
`src/zumime_types.h`, and times `file --mime-type`, `mime::guess_type()`
and `mimetype`'s CLI on the §10 inputs so the bar is on record. Stage 2
is `full` as the first compiled code of substance. Stage 6 writes
`cran-comments.md`, adds the Apache Software Foundation to `Authors@R`
with `role = "cph"` and the IANA registry's terms to `inst/COPYRIGHTS`,
runs the full profile and records the dates.

## 12. Acceptance criteria for v0.1.0

- Every behaviour in §6 and §8 has a passing test.
- The three oracles of §7 pass: every WPT parse fixture, every Go sniff
  case, and every `file-type` fixture whose format §6.2 claims, with the
  unclaimed ones listed.
- The fuzz target runs one hour clean under `ZUMIME_STANDALONE` with
  sanitizers.
- `mime_type()` over the same tree gives byte-identical frames on the
  Linux, macOS and Windows CI legs.
- `R CMD check --as-cran` is clean on all r-actions legs; no `Imports`;
  `DESCRIPTION` names the Apache Software Foundation as a copyright
  holder and `inst/COPYRIGHTS` states the table sources.
- `.agents/benchmarks.md` holds a number for every row of §10, met or not.
- Seven stages. A stage that needs a second pull request moves scope to
  §14, not the release.

## 13. Decisions

All are **(C)**: this RFC decides them and the maintainer may overturn
them. None was discussed before writing; the sketch's open questions are
Q1 to Q5 of `base-layer-candidates.md` §5.1 as of commit `074b398`, in
the order that sketch listed them.

- **D1 (C).** Both halves in one package: sniffing and the extension
  table, so a consumer takes no `Imports` and one call answers from two
  signals. (The sketch's shape.)
- **D2 (C).** The byte answer is the whole WHATWG algorithm with supplied
  type, no-sniff flag and context, not only its signature table, because
  `zuhttp` and `zusocks` need the computed type a browser would compute.
- **D3 (C).** Confidence is four ordered levels, not a number:
  `definite` (signature or container), `probable` (grammar of text, C1
  charset guess, function detectors, family sniffers), `extension` (name
  only), `none`. A number would be invented; the levels name the kind of
  evidence, which is what a caller branches on. (Sketch Q1, which offered
  three; container evidence is as definite as a signature, so it joins
  that level, and `none` is needed for the floor.)
- **D4 (C).** `mime_type()` reads 4096 bytes by default, as `mimetype`
  does, because the WHATWG resource header is 1445 bytes and the ZIP,
  OLE2 and BMFF readers want a little more; containers do not opt in to
  a longer read. `limit = 0` reads everything. (Sketch Q2.)
- **D5 (C).** The completeness check is opt-in, `complete = TRUE`, and
  stays opt-in for paths too, because it is a second read at the end of
  every file and a tree scan should not pay for it unasked. (Sketch Q5.)
- **D6 (C).** The default answer depends on nothing outside the package:
  no host tables, and no suggested package is consulted unless an
  argument asks (`inner = "decompress"`, `text = "family"`,
  `charset = "detect"`). Two machines with `zumime` installed give the
  same frame for the same bytes.
- **D7 (C).** No vendored code. The sniffer, the readers and the
  algorithm are written for this package against the standard and the
  three reference implementations; the pieces are small and the oracles
  make divergence visible.
- **D8 (C).** The registry is generated from IANA's registry and Apache's
  `mime.types`, with a hand-maintained `tools/types.yaml` for what neither
  has, and emitted as both `R/sysdata.rda` and a C header so R and C
  share one set of ids. Nothing is taken from the GPL `mime` package.
  IANA alone does not suffice today because its registry carries few
  extensions; Apache's file is kept until it does, and §15 Q2 records the
  question. (Sketch Q3.)
- **D9 (C).** The incremental sniffer is an external pointer whose
  protected field is an R raw vector holding the buffer, following the
  family's rule that heap state across a longjmp is owned by R. A closure
  would copy the buffer on every push. (Sketch Q4.)
- **D10 (C).** The result is a plain `data.frame` with a printing class,
  one row per input, the lineage reachable by `mime_parent()` rather
  than a list column, so it drops into `dplyr`, `data.table` and
  `write.csv()` unchanged.
- **D11 (C).** The R prefix is `mime_`, the condition root `zumime_error`,
  the internal C prefix `zumime_`. No public C prefix until §14's header.
- **D12 (C).** Unreadable paths are `NA` rows by default and an error only
  with `strict = TRUE`, because the main consumer is a tree scan.
- **D13 (C).** Registered detectors are session-scoped and attach under a
  parent; there is no persistent user table, so D6 holds within a
  session's own additions only.
- **D14 (C).** Performance targets (§10) are measured and recorded but do
  not gate v0.1.0; the API and the oracles do.

## 14. Later versions, in the order they are expected

- **A C API**: `inst/include/zumime.h` with `zumime_sniff(const unsigned
  char *, size_t, zumime_result *)` and the registry's ids, for `zuhttp`
  and `zusocks` to call without an R round trip, with a consumer fixture
  per R10.
- **Connections** as input to `mime_type()`, reading through R's
  connection API with the incremental sniffer underneath.
- **A persistent user registry** if a package or a site asks for one;
  until then `.onLoad()` registration.
- **More formats** as consumers ask: fonts beyond the WHATWG four,
  geospatial (Shapefile, GeoPackage, FlatGeobuf), scientific (FITS, DICOM,
  Zarr chunks), and the formats `anydoc` meets.
- **Statistical charset detection** moved in, only if `zuutf` does not
  take it.

## 15. Open questions

- **Q1.** Should `mime_type()` on a path run the completeness check by
  default once Stage 4 has measured its cost on a cold cache? D5 says no
  until measured.
- **Q2.** When does IANA's registry alone suffice for extensions, so the
  Apache file and its copyright line can be dropped? Revisit at each
  regeneration; a table diff that shows Apache adding nothing for a year
  is the signal.
- **Q3.** Should `mime_check()`'s partial detection be observable, for
  example a `checked` attribute listing the types probed, or stay an
  optimisation?
- **Q4.** Is v0.1.0 a CRAN submission or a GitHub release? The board's
  `CRAN intent` field records the answer; this RFC assumes `Planned`.

## 16. What this RFC does not decide

The exact list of formats §6.2 claims beyond the ones named, which Stage 3
fixes against the `file-type` corpus; the printing format of a
`zumime_result`; whether `mime_types()` includes registered types by
default or behind an argument; the wording of condition messages beyond
their classes; and the article's second example.
