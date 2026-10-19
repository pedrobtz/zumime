# zumime: roadmap

Status: draft 2026-10-18. Implements [design.md](design.md).
Target: v0.1.0, the first CRAN release.
Tracking: [v0.1.0 (#1)](https://github.com/pedrobtz/zumime/issues/1), with one
sub-issue per stage;
[CRAN-submission (#10)](https://github.com/pedrobtz/zumime/issues/10).

The design's §11 has seven stages. This roadmap keeps its stages 0 to 5
and splits its stage 6 into the three the portfolio template requires:
documentation, `Full CI`, and `v0.1.0 readiness`. The acceptance criterion
"seven stages" in design §12 is read as "nine stages, each one pull
request". Design §11 put the Apache copyright line in stage 6; here it
lands in Stage 1 with the tables it covers.

## Stages

| Stage | Title | CI | Issue | Pull request | Done |
| --- | --- | --- | --- | --- | --- |
| 0 | [Package identity](#stage-0--package-identity) | quick | [#2](https://github.com/pedrobtz/zumime/issues/2) | [#13](https://github.com/pedrobtz/zumime/pull/13) | 2026-10-19 |
| 1 | [Registry and tables](#stage-1--registry-and-tables) | quick | [#3](https://github.com/pedrobtz/zumime/issues/3) | [#14](https://github.com/pedrobtz/zumime/pull/14) | 2026-10-19 |
| 2 | [WHATWG sniffer](#stage-2--whatwg-sniffer) | full | [#4](https://github.com/pedrobtz/zumime/issues/4) | [#15](https://github.com/pedrobtz/zumime/pull/15) | 2026-10-19 |
| 3 | [Containers and formats](#stage-3--containers-and-formats) | quick | [#5](https://github.com/pedrobtz/zumime/issues/5) | [#16](https://github.com/pedrobtz/zumime/pull/16) | 2026-10-19 |
| 4 | [Paths and how to open them](#stage-4--paths-and-how-to-open-them) | quick | [#6](https://github.com/pedrobtz/zumime/issues/6) | [#17](https://github.com/pedrobtz/zumime/pull/17) | 2026-10-19 |
| 5 | [Incremental sniffer, fuzz, benchmarks](#stage-5--incremental-sniffer-fuzz-benchmarks) | full | [#7](https://github.com/pedrobtz/zumime/issues/7) | [#18](https://github.com/pedrobtz/zumime/pull/18) | 2026-10-19 |
| 6 | [README and article](#stage-6--readme-and-article) | quick | [#8](https://github.com/pedrobtz/zumime/issues/8) | | 2026-10-19 |
| 7 | [Full CI](#stage-7--full-ci) | full | [#9](https://github.com/pedrobtz/zumime/issues/9) | | |
| 8 | [v0.1.0 readiness](#stage-8--v010-readiness) | full | [#11](https://github.com/pedrobtz/zumime/issues/11) | | |

## Stage 0 — Package identity

**Issue.** [#2](https://github.com/pedrobtz/zumime/issues/2), sub-issue of
[v0.1.0](https://github.com/pedrobtz/zumime/issues/1).

**CI.** `quick`. See the CI policy in `CLAUDE.md`.

**Goal.** The scaffold becomes a package someone can read: a real
`DESCRIPTION`, the family's conventions in place, CI that finishes fast,
and the benchmark harness with the incumbents' numbers on record before
any `zumime` code exists.

**Work.**

- `DESCRIPTION`: Title "Media Type Detection from Bytes and File Names",
  a Description paragraph from design §1, `Authors@R` with the maintainer
  as `aut`, `cre` and `cph`, `Depends: R (>= 4.1)`, `Language: en-GB`,
  `Config/roxygen2/version: 8.1.0` (alignment R2), `Suggests: testthat,
  zukomp, zuutf, zucsv, zujson, zutoml`, `BugReports`.
- `src/Makevars` with `PKG_CFLAGS = $(C_VISIBILITY)` and
  `tests/testthat/test-abi.R` asserting the shared object exports
  `R_init_zumime` only (alignment R3).
- `R-CMD-check.yaml`: add `{"os": "windows-latest", "r": "devel"}` to
  `runners` so the Windows R-devel combination CRAN checks is covered; the
  row runs in the full profile only.
- `coverage.yaml` pinned to a commit of `pedrobtz/r-actions` with the tag
  in a comment, as the template requires for workflows holding a write
  token.
- `tools/run-benchmarks` and `.agents/benchmarks.md`: time
  `file --mime-type` and `mime::guess_type()` on the design §10 inputs
  where the tools are installed, and record the numbers; `mimetype`'s Go
  CLI only if it is already available on the runner.
- `inst/WORDLIST` for `spelling`; `zumime_info()` returning the package
  version and the table version (`NA` until Stage 1).
- `.Rbuildignore` checked against the template's "Working with skills"
  list; `.gitignore` for `tests/testthat/fixtures/`.

**Exit criteria.**

- `R CMD check` passes on the quick r-actions profile with 0 errors, 0
  warnings, 0 notes other than "New submission".
- Every check in the quick-profile pull request run finished in under
  five minutes; anything tuned (`quick-step`, `quick-containers`) is
  recorded here.
- `test-abi.R` passes.
- `.agents/benchmarks.md` holds a number for the incumbents on each §10
  row that an installed tool can answer.

**Deviations (2026-10-19).**

- `Suggests` lists `zukomp`, `zucsv` and `zujson` only. `zuutf` and
  `zutoml` are not on CRAN, and a suggested package outside the mainstream
  repositories is a NOTE under `--as-cran`. They are added when they reach
  CRAN; until then `charset = "detect"` and the `zutoml` hook of
  `text = "family"` find them absent and degrade as D6 says.
- `NEWS.md` is headed `# zumime 0.0.0.9000`, not `(development version)`:
  R 4.5's news parser skips a heading without a version, and `R CMD check`
  then notes "No news entries found".
- `native-checks.yaml` (valgrind, LTO, gctorture, rchk, analyzers,
  cran-special) is added here rather than in Stage 2, so Stage 2's full run
  has it from its first push. `sanitizers.yml` joins in Stage 1: its
  instrumentation check looks for `__ubsan` symbols, and `init.c` alone
  gives UBSan nothing to instrument.
- Quick-profile timings on #13: every check under five minutes (the
  longest, UBSan before it was deferred, 4m22s); nothing tuned.
- The coverage badge goes to `gh-pages`: the `main` ruleset requires pull
  requests and rejected the badge commit on every push.

**Design.** §3, §10 (baseline), §11 stage 0.

## Stage 1 — Registry and tables

**Issue.** [#3](https://github.com/pedrobtz/zumime/issues/3), sub-issue of
[v0.1.0](https://github.com/pedrobtz/zumime/issues/1).

**CI.** `quick`. `mime_parse()` is the first C in the package but it is a
few hundred lines over a short header string; Stage 2, which follows at
once, runs the full profile over it.

**Goal.** The type registry exists as generated data shared by R and C,
and every function that needs only the registry works: names, extensions,
lineage, categories, and the WHATWG MIME type record.

**Work.**

- `tools/generate-tables.R` reading IANA's media types registry and
  Apache httpd's `mime.types`, plus `tools/types.yaml` (parents, aliases,
  the R and analytic data formats, canonical-extension overrides);
  `tools/table-sources.yaml` with URL, retrieval date and SHA-256 per
  upstream file.
- Generated `R/sysdata.rda` and `src/zumime_types.h`; a test that
  regenerating from the recorded sources reproduces both byte for byte.
- `mime_guess()`, `mime_extensions()`, `mime_parent()`, `mime_is()`,
  `mime_types()` (design §6.3, §6.6), vectorised, with the round-trip
  property test and the no-cycle test of §9.
- `mime_parse()` and `mime_format()` in C (design §6.8) against the
  web-platform-tests `mimesniff/` fixtures, fetched by
  `tools/fetch-fixtures` at a pinned commit.
- `Authors@R` gains the Apache Software Foundation as `cph`;
  `inst/COPYRIGHTS` states the table sources and their terms.
- Decide whether `r-actions`' `vendor-upstream.yml` can drive the
  regeneration workflow; if not, a small scheduled workflow that opens a
  pull request when a checksum changes.

**Exit criteria.**

- Every WPT parse and serialize fixture passes.
- For every type, every extension in `mime_extensions(type)` maps back by
  `mime_guess()` to that type or a descendant; `mime_parent()` reaches
  the root from every type.
- `mime_is("application/x-sqlite3", "application/vnd.sqlite3")` and
  `mime_is("image/png", "image")` are `TRUE`.
- The regeneration test passes; `zumime_info()$table_version` is the
  sources' date.
- Quick profile green.

**Decisions and deviations (2026-10-19).**

- `mime_parent()` returns a list of character vectors, one per input, as
  `mime_extensions()` does: design §6.3 describes one type's lineage as a
  character vector, and the roadmap asks for the function vectorised. An
  unknown type gives `NA`, the root `character(0)`.
- `mime_parse()` returns a list of records, one per input, and takes
  `strict = FALSE`; `strict = TRUE` is how §8's `zumime_parse_error` is
  asked for. `mime_format()` takes one record or a list of them.
- The regeneration test compares `src/zumime_types.h` byte for byte and
  the objects in `R/sysdata.rda` with `identical()`: an `.rda` file carries
  the writing R's version in its header, so its bytes differ between R
  versions for the same data.
- `vendor-upstream.yml` does not fit: it compares a vendored library's
  GitHub releases, and IANA's and Apache's files have none. A small
  `tables-upstream.yaml` downloads the sources weekly and opens or updates
  an issue when a checksum changes. It cannot open a pull request, because
  the repository does not let workflows create them.
- `oracles.yaml` runs what R CMD check cannot: the regeneration check
  (`tools/` is not in the tarball) and the suite with the fixtures fetched,
  in shuffled order.
- `jsonlite` joins `Suggests`, for reading the WPT fixtures in a test
  helper; `R CMD check` warns about a `::` call to an undeclared package.
- The `sanitizers` job deferred from Stage 0 is added here.

**Design.** §4 layer 1, §6.3, §6.6, §6.8, §7.1, D8, D10, D11.

## Stage 2 — WHATWG sniffer

**Issue.** [#4](https://github.com/pedrobtz/zumime/issues/4), sub-issue of
[v0.1.0](https://github.com/pedrobtz/zumime/issues/1).

**CI.** `full — first compiled code of substance and a decoder of untrusted
bytes: gctorture at step 20, valgrind, ASan over the sniffer before
Stages 3 to 5 build on it.`

**Goal.** `mime_sniff()` over a raw vector computes the type the WHATWG
MIME Sniffing Standard defines, for every combination of supplied type,
no-sniff flag and context, and carries the charset where the bytes
declare one.

**Work.**

- `src/zumime_sniff.c`: the sniffing algorithm with its three inputs, the
  1445-byte resource header, the pattern matcher with masks and ignored
  leading bytes, the image, audio-or-video, font and archive tables, the
  text-or-binary rule, the Apache bug check (design §6.1).
- `src/zumime_table.c`: the signature table as data rows, WHATWG rows
  first in the standard's order, then the offset signatures (tar at 257,
  ISO 9660 at 32769, skipped for a short raw vector) and the compression
  wrappers.
- `src/zumime_text.c` charset chain of §6.5: supplied parameter, BOM, XML
  declaration, HTML `<meta>` prescan, UTF-8 validity ignoring a cut code
  point, the C1 rule.
- `mime_sniff(x, type, no_sniff, context, limit)` on raw vectors; the
  result frame of §5 with `confidence` per D3.
- The `ZUMIME_STANDALONE` build of the sniffer as C11 without R.
- Tests: one generated input per table row; Go's `sniff_test.go` cases as
  the oracle for the no-context path; a charset table per rule.

**Exit criteria.**

- Every Go `net/http` sniff case agrees.
- Every signature row is exercised by a test built from the row.
- Each design §6.5 rule has a passing test, including the cut code point.
- The sniffer compiles standalone with `-std=c11 -Wall -Wextra -pedantic`
  and no warnings.
- Full profile green on the pull request: gctorture, valgrind, ASan and
  every platform leg.

**Decisions (2026-10-19).**

- The `"none"` context is the standard's algorithm plus zumime's own
  signature rows (compression wrappers, tar with its checksum, ISO 9660,
  RAR 5, 7z, fonts, WebAssembly), consulted only where the standard found
  binary bytes and nothing else; Stage 3's readers attach there too.
  `"browsing"` is the standard's tables alone.
- Confidence (D3): a table or algorithm match is `definite`; text by the
  no-binary-bytes rule is `probable`; the floor `application/octet-stream`
  and a supplied type returned unverified are `none`. `confidence` is an
  ordered factor `none < extension < probable < definite`, so
  `confidence >= "probable"` works as D15 needs.
- `type` is always the canonical name: the standard's `image/x-icon`,
  `audio/wave`, `video/avi` and `application/x-gzip` come back as their
  registry names, and the Go oracle compares through `mime_is()`.
- The standard's MP3 steps have operator-precedence slips and an inverted
  rate table; the code follows Mozilla's `mp3sniff.c`, which they
  describe. Its vint parse starts at the DocType's offset, not 0.
- Declared charset labels are reported as written (the `<meta>` prescan
  lower-cases them), not resolved through the Encoding Standard's label
  table; only the prescan's own UTF-16 and `x-user-defined` remappings are
  applied.
- The registry generator sorts in byte order (`method = "radix"`), so its
  output does not depend on the locale and C can binary-search the names.
- gctorture at step 20 ran past its 120-minute limit on the first full run
  (expectations cost about 2 s each there). Property tests that loop in R
  over the registry or a corpus now skip when the job sets
  `ZUMIME_GCTORTURE=true` (`helper-skip.R`), as r-actions recommends; they
  test data, not memory paths, and run everywhere else.

**Design.** §4 layer 2, §6.1, §6.2 (signatures), §6.5, §7.2, D2, D3, D4.

## Stage 3 — Containers and formats

**Issue.** [#5](https://github.com/pedrobtz/zumime/issues/5), sub-issue of
[v0.1.0](https://github.com/pedrobtz/zumime/issues/1).

**CI.** `quick`. The readers extend the sniffer Stage 2 checked in full
and read only bytes already in hand; `Full CI` covers them with the whole
set.

**Goal.** A ZIP is a docx, an MP4 is not an M4A, an OLE2 file is a legacy
Word document, an XML file is SVG, and R's own files are known, all from
the bytes `mime_sniff()` already read.

**Work.**

- Container readers of design §6.2, one file each: ZIP central directory
  (entry names, encryption flag and AES extra field), OLE2 directory
  (class id, stream names, `EncryptionInfo`), ISO base media brands,
  RIFF, EBML, Ogg, tar checksum.
- R and analytic data formats: RDS and RData through their compression
  wrapper to the serialisation header and version; Parquet, Arrow IPC,
  Feather, fst, qs2, SQLite, DuckDB, HDF5 at its offsets, NetCDF, Stata,
  SPSS, SAS.
- Structured text of §6.4: XML root and namespace, JSON top-level keys,
  line-oriented formats, shebang interpreters, at `probable`.
- `text = "family"`: the `zucsv`, `zujson` and `zutoml` hooks behind
  `requireNamespace()`, off by default (D6).
- `tools/fetch-fixtures` extended to `file-type`'s `fixture/` directory at
  a pinned commit; the test lists the fixtures whose formats are not
  claimed.
- Tests that build each container from bytes in the test body, so the
  suite runs without the corpus.

**Exit criteria.**

- Every `file-type` fixture whose format the package claims is named as
  `file-type` names it, through the alias list; the unclaimed list is in
  the test and matches design §6.2.
- Every reader has a from-bytes test; the suite passes with the fixture
  directory absent.
- Quick profile green.

**Decisions and deviations (2026-10-19).**

- **The `text = "family"` hooks move to Stage 4.** `zucsv::sniff_csv()`
  reads a file path, not bytes, and the `text` argument belongs to
  `mime_type()`, which Stage 4 builds over paths.
- **A refinement must descend from the type it refines**, so a prefix is
  always typed as an ancestor of the whole (design §9). This fixes the
  hierarchy: `text/xml` is an alias of `application/xml`; M4A, M4V and 3GP
  sit under `video/mp4`; Ogg codecs under `application/ogg`; OOXML
  variants under their document type; PostScript and script types under
  `text/plain`. The one exception is gzip-wrapped RDS and RData, typed as
  R's formats; Stage 5's prefix property allows that step.
- **Small additions beyond the named readers**, because the corpus
  showed them cheap and exact: the OOXML variants read from
  `[Content_Types].xml` with a bounded inflater (written for zumime, as
  D7 requires), APNG, JPEG-LS, QuickTime movies without an `ftyp` box, and
  rows for executables (ELF, Mach-O, PE), TIFF, PSD, FLAC, AAC, AMR, SWF,
  FLV, CAB, RPM, deb, ar, LZ4, lzip, compress, pcap, Avro, DICOM, JPEG XL,
  Blender, ICNS, glTF binary, PST and EOT outside the font context.
- **The MP3 frame size follows MPEG**: Layer III frames are 72 × bitrate /
  rate for MPEG-2 and 2.5, where the standard and Mozilla use 144 for all.
- **The `file-type` oracle compares through `mime_is()`**: a fixture
  agrees when zumime's type equals file-type's or descends from it, as for
  OLE2 documents file-type calls `application/x-cfb`. 182 of the 267
  fixtures file-type answers agree; the 85 unclaimed ones are listed in
  `helper-file-type.R` by reason, and the test fails if one starts to
  agree. file-type's answers were dumped once with Node into that helper.
- **A charset is reported only for text bytes**: a text type whose bytes
  are binary (a DOS EPS header) has no charset unless a byte-order mark
  explains them.
- RIFF needs no reader: the standard's rows already decide WAVE, AVI and
  WebP, and the AIFF-C row joins them.

**Design.** §4 layer 3, §6.2 (containers), §6.4, §7.3, D6, D7.

## Stage 4 — Paths and how to open them

**Issue.** [#6](https://github.com/pedrobtz/zumime/issues/6), sub-issue of
[v0.1.0](https://github.com/pedrobtz/zumime/issues/1).

**CI.** `quick`. The path loop and the `Suggests` guards for `zukomp` and
`zuutf` are what the `nosuggests` leg and the platform legs check, and
`Full CI` runs them before anything depends on the answer.

**Goal.** `mime_type(paths)` answers from both signals over a tree of
files in one C loop, says whether they agree, and reports what a consumer
needs to open each file.

**Work.**

- `src/zumime_path.c`: the vectorised loop of design §6.7 (open, read
  `limit` bytes, sniff, deep probes, close), interrupt check every 256
  files, `NA` rows for unreadable paths, `zumime_io_error` under
  `strict = TRUE`, directories as `inode/directory`.
- Deep probes: the ISO 9660 seek, the ZIP tail for the central directory,
  the tail read behind `complete = TRUE`.
- The how-to-open columns: `inner` from the remaining extension by default
  and through `zukomp` with `inner = "decompress"`; `encrypted`;
  `complete`; `newline`; `interpreter`; `by_name` and `agree`.
- `charset = "detect"` through `zuutf`; `zumime_dependency_error` when a
  suggested package is asked for and absent.
- `mime_check(x, allowed, min_confidence)` as D15 fixes it: a bare logical,
  byte evidence only, running only the allowed types' detectors and their
  ancestors; an unexported `probe_count()` reading a static counter;
  `mime_register()` and `mime_unregister()` with data rules in C and function
  rules in R (design §6.9).
- `mime_sniff()` accepts paths through the same loop.

**Exit criteria.**

- `mime_type()` over a tree built under `tempdir()` gives the snapshot
  frame, with `agree` `TRUE`, `FALSE` and `NA` cases.
- Each how-to-open column has a test per format it applies to, including
  an encrypted ZIP, a truncated PDF and a `.csv.gz`.
- `mime_check(x, a, m)` equals `mime_is(t$type, a) & t$confidence >= m` with
  `t <- mime_type(x)` over every fixture and every subset of three allowed
  types (D15), and the probe counter shows three probes for three allowed
  types.
- A registered data rule is detected at `definite`, a function rule at
  `probable`; an unknown parent is `zumime_registry_error`.
- A missing path is an `NA` row by default and `zumime_io_error` with
  `strict = TRUE`.
- Quick profile green.

**Decisions (2026-10-19).**

- **`agree` is `TRUE` when the byte type and the name type lie on one
  lineage**, either descending from the other. Design §6.7 says "equals or
  descends from" the name answer, under which every CSV (bytes
  `text/plain`, name `text/csv`) and every ZIP named `.docx` read before
  its tail would disagree. `FALSE` still flags a PNG named `.txt`. Bytes
  at the floor (`application/octet-stream`, `none`) count as unknown.
- **`inner = "decompress"`** decompresses gzip whole through
  `zukomp::komp_decompress()` for files up to 16 MiB, because zukomp has no
  streaming or partial-output API; larger files, the other wrappers, and
  failures fall back to the name.
- **`complete = TRUE`** checks gzip, and RDS or RData in gzip, by
  inflating the whole stream through a 32 KiB window with zumime's own
  inflater and comparing the trailer's size; the stream is read in 64 KiB
  pieces, never whole.
- **The ZIP tail** is the last 66 KiB; when its end record points at a
  central directory that starts earlier (an archive of thousands of
  entries), the directory is read from its start, up to 8 MiB.
- **`mime_check()`'s shortcut** computes the standard's answer and the
  extra rows for every input, which exactness needs, and skips the
  readers, tail reads and the frame for an input whose answer is related
  to no allowed type. A probe is one allowed type tested for one input.
  The D15 property holds over a test tree for every subset of three of
  twelve candidate types at three confidence levels, and over the
  `file-type` corpus.
- **Registered types** live in a fixed C table of 256 entries with rules of
  at most 64 bytes, and appear in `mime_types()` by default with
  `detected_by = "registered"` (design §16 left this open).
- **`zumime_info()$family`** lists the family sniffers the session can
  use. `zuutf` and `zutoml` are reached by name at run time, since they are
  not on CRAN and so not in `Suggests` (Stage 0).

**Design.** §4 layer 4, §5 Results, §6.7, §6.9, D5, D6, D12, D13, D15.

## Stage 5 — Incremental sniffer, fuzz, benchmarks

**Issue.** [#7](https://github.com/pedrobtz/zumime/issues/7), sub-issue of
[v0.1.0](https://github.com/pedrobtz/zumime/issues/1).

**CI.** `full — an external pointer with a finalizer and an R-owned buffer
(D9): gctorture at step 20, valgrind and ASan on the push path, and the
fuzz target under sanitizers.`

**Goal.** A stream can be sniffed chunk by chunk and stops as soon as the
type is certain; random bytes never crash the sniffer; every performance
target has a measured number.

**Work.**

- `mime_sniffer()`, `mime_push()`, `mime_finish()` (design §6.10): an
  external pointer whose protected field is a raw vector of `limit`
  bytes; the "can decide" rule; `zumime_state_error` after finish.
- The fuzz target under `ZUMIME_STANDALONE` (design §9): random and
  mutated-fixture bytes, checking no crash, no over-read, every type id in
  the registry, and that a prefix's type is the whole's or an ancestor's.
- `tools/run-benchmarks` extended to `zumime`; `.agents/benchmarks.md`
  filled for every row of design §10, met or not.
- A test that feeds every fixture one byte at a time and checks the
  sniffer decides at the whole's type and never later than `limit`.

**Exit criteria.**

- The byte-at-a-time test passes over every fixture.
- The fuzz target runs one hour clean under ASan and UBSan, recorded with
  the commit and date.
- `.agents/benchmarks.md` holds a number for every §10 row.
- Full profile green on the pull request.

**Decisions and deviations (2026-10-19).**

- **The fuzz property is the incremental one.** Design §9 asks that "the
  result for a prefix is the whole's type or one of its ancestors". That
  does not hold in general: a prefix of all text bytes is `text/plain`
  while the whole may be binary, and a file that starts `MZ` is tar if
  `ustar` and a valid checksum sit at 257. What a consumer relies on, and
  what the target checks, is that the type the stream decides on, at the
  first prefix the can-decide rule accepts, is the type of the whole.
- **The can-decide rule is conservative** (`src/zumime_stream.c`): a
  signature decides once no earlier row of the consulted groups could
  still match and the type's reader is settled (JPEG at 4 bytes, PNG at
  its first IDAT or acTL, ISO base media at the end of the `ftyp` box, Ogg
  at its codec); text, ZIP, OLE2, Matroska and gzip decide at the limit or
  the finish. Every fixture and every built input decides at the type of
  the whole, byte by byte and in 512-byte chunks.
- **The sniffer's state lives in the external pointer's address** and its
  bytes in the protected raw vector, with no C allocation and so no
  finalizer: a saved sniffer comes back undecided with its bytes.
- **A long fuzz run needs the `fuzz-hour` label**, since a workflow can be
  dispatched only from the default branch.
- **The hour-long fuzz run** passed on #18 at commit `846f24e` on
  2026-10-19: libFuzzer with ASan and UBSan, 282,215 inputs in 3,601 s, no
  finding ([run 39201743167](https://github.com/pedrobtz/zumime/actions/runs/39201743167)).
- **Valgrind on #18** reported uninitialised bytes in zlib under
  `saveRDS()` of a sniffer: the buffer's unpushed tail was uninitialised R
  memory, serialised with the object. It is now zeroed on allocation and
  growth. It also reported 668 KB "possibly lost" inside R's own
  `memCompress()` (libdeflate), which a test helper called; the helper now
  writes raw DEFLATE through `gzfile()`. The same report failed the full
  run on `main` after #17.
- **Benchmarks**: four of the seven targets are missed and recorded in
  `.agents/benchmarks.md` (D14); the first run's three avoidable costs were
  fixed in this stage.

**Design.** §6.10, §9 (fuzz), §10, D9, D14.

## Stage 6 — README and article

**Issue.** [#8](https://github.com/pedrobtz/zumime/issues/8), sub-issue of
[v0.1.0](https://github.com/pedrobtz/zumime/issues/1).

**CI.** `quick`. Documentation and the pkgdown site.

**Goal.** A newcomer can tell in two minutes what the package does and
when to reach for it, and a consumer can follow one worked example.

**Work.**

- `README.Rmd` written with the `pkg-readme` skill, with a rendered
  `README.md`; the examples run against a small tree in `tempdir()`.
- `vignettes/checking-an-upload.Rmd`, "Checking an upload before you open
  it": `mime_check()` against an allowlist, `agree`, `encrypted`,
  `complete`, and the incremental sniffer on a connection's first chunk.
- `_pkgdown.yml` reference grouped by design §5's headings; every exported
  function documented with an example.
- `NEWS.md` entries for everything user-facing so far.

**Exit criteria.**

- `pkgdown::build_site()` succeeds in CI and the article renders.
- Every exported function has a roxygen example that runs.
- `README.md` is regenerated from `README.Rmd` with no diff.
- Quick profile green.

**Notes (2026-10-19).** The article lives in `vignettes/`, which
`.Rbuildignore` keeps out of the tarball, so pkgdown builds it and R CMD
check does not; `knitr` and `rmarkdown` are `Config/Needs/website`. The
README's coverage badge points at `gh-pages`, where Stage 0 moved it.

**Design.** §2 (README and article), §5.

## Stage 7 — Full CI

**Issue.** [#9](https://github.com/pedrobtz/zumime/issues/9), sub-issue of
[v0.1.0](https://github.com/pedrobtz/zumime/issues/1).

**CI.** `full`. Always.

**Goal.** No new features. The full r-actions profile runs on the default
branch's code and everything it finds is fixed.

**Work.**

- Open a pull request with the `full-ci` label from the default branch's
  head; collect every failure from gctorture at the sensitive step,
  valgrind, ASan and UBSan, every platform leg including Windows R-devel,
  `nosuggests`, `nold` and cran-special.
- Fix each in this pull request, with a test where a fix changes
  behaviour; also fold in any failure comments earlier stages left on this
  issue from the full runs their merges started.
- Confirm `mime_type()` over the test tree gives byte-identical frames on
  the Linux, macOS and Windows legs (design §12).

**Exit criteria.**

- A full-profile run green on the pull request and on its merge commit.
- The determinism check of design §12 passes on all three platforms.

**Design.** §12.

## Stage 8 — v0.1.0 readiness

**Issue.** [#11](https://github.com/pedrobtz/zumime/issues/11), sub-issue of
[v0.1.0](https://github.com/pedrobtz/zumime/issues/1).

**CI.** `full`. Always.

**Goal.** Only the submission itself is left.

**Work.**

- `Version: 0.1.0` and the matching `NEWS.md` heading.
- `cran-comments.md` listing the r-actions CI legs as the test
  environments.
- `pkg-critical-review` run, blocking and required findings fixed; then
  `pkg-cran-review` run, every finding resolved.
- `urlchecker::url_check()` and `spelling::spell_check_package()` clean.
- `DESCRIPTION` names the Apache Software Foundation as a copyright holder
  and `inst/COPYRIGHTS` states the table sources (design §12).

**Exit criteria.**

- `devtools::check()` clean with the only note "New submission".
- A full-profile r-actions run green on the release commit.
- Both review skills have run and left no open finding.
- `urlchecker` and `spelling` clean.

**Design.** §12.

## After 0.1.0

From design §14, in the order expected:

- **A C API** (`inst/include/zumime.h`) for `zuhttp` and `zusocks`, with a
  consumer fixture per alignment R10. Waits until the R surface has
  settled the result shape.
- **Connections** as input, with the incremental sniffer underneath.
- **A persistent user registry**, only if asked for.
- **More formats**: fonts beyond the WHATWG four, geospatial, scientific,
  and what `anydoc` meets.
- **Statistical charset detection**, only if `zuutf` does not take it.
- **Performance targets** missed in Stage 5 are recorded, not fixed, for
  0.1.0 (D14); they are the next version's measured work.

## Open questions

From design §15:

- **Q1** (completeness check on by default for paths): decided after Stage
  4 measures the cost on a cold cache; D5 holds until then. Blocks nothing.
- **Q2** (IANA alone for extensions): revisited at each regeneration;
  blocks nothing before 0.1.0.
- **Q3** (whether `mime_check()`'s partial detection is observable): settled
  2026-10-19 by design D15; Stage 4 implements it.
- **Q4** (CRAN submission or GitHub release): the board's `CRAN intent`
  field; this roadmap assumes `Planned`. Decides whether Stage 8 and the
  `CRAN-submission` issue apply as written.
- **Not in the design**: whether `r-actions`' `vendor-upstream.yml` fits
  table regeneration (Stage 1 finds out).
