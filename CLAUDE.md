# CLAUDE.md

<!-- markdownlint-disable-next-line MD013 -->
This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Shared conventions

The portfolio's shared rules are synced into `.claude/shared/` from
`pedrobtz/packages:claude/shared/`. Never edit them here. Where this file and
a shared file disagree, this file wins for this package.

@.claude/shared/workflow.md
@.claude/shared/r-package.md
@.claude/shared/ci.md
@.claude/shared/native-code.md
@.claude/shared/correctness.md
@.claude/shared/assurance.md

## What this is

zumime tells what a file is from its bytes and from its name, with no
system dependency: a WHATWG MIME sniffer over the first kilobytes of a
file or raw vector, container and brand inspection (ZIP entry names, ISO
base media brands, RIFF, EBML, Ogg, OLE2), a type hierarchy ending at
`application/octet-stream`, and a generated extension table. One call
answers from both signals and says whether they agree. It is a base-layer
package: `zu*` consumers such as `zuhttp`, `zupdf`, `zuxlsx`, `zurds` and
`dastash` call it to decide a `Content-Type` or to refuse a file before
their parsers see it. Zero hard runtime dependencies; the family's own
sniffers (`zukomp`, `zuutf`, `zucsv`, `zujson`) are reached through
`Suggests`. It does not parse multipart bodies, read filesystem
attributes, extract descriptive metadata (dimensions, duration, EXIF) or
hash content; those belong to other packages.

The specification is `.agents/design.md`, adopted on 2026-10-18 from
[RFC 0040](https://github.com/pedrobtz/packages/blob/main/rfcs/started/0040-zumime-media-type-detection.md)
in `pedrobtz/packages`. It outranks this file: `CLAUDE.md` orients, the
design doc decides. Every decision in the RFC's section 13 is marked
**(C)**, written without a design conversation, so each stays open to the
maintainer until a stage records it.

## Current state

All stages of `.agents/roadmap.md`, 0 to 8, are closed (verified
2026-11-11), so the design's v0.1.0 scope is implemented. Version 0.1.0 is
submitted to CRAN; the `CRAN-submission` issue, `#10`, tracks it until
acceptance. The README is `README.Rmd`; the one article is
`vignettes/checking-an-upload.Rmd`, built by pkgdown only.

**Deviation from `workflow.md` (Releasing to CRAN).** The repository has no
`cran-release.yaml` and no committed `CRAN-SUBMISSION` (checked
2026-11-11), so nothing tags the release or opens the `.9000` bump on its
own. After acceptance, `pkg-post-cran` tags the submitted commit with the
bare version, `0.1.0` (no `v`), publishes the GitHub release, bumps to
`0.1.0.9000`, closes the version's parent issue and moves the board card.

## Versions and dependents

The current version's parent issue is `#1`, `v0.1.0`. The design names
`anydoc`, `zuhttp`, `zusocks`, `zuarchive`, `dastash`, `zudedup`, `zupdf`,
`zuxlsx` and `zurds` as consumers; none depends on it yet, and no C API or
header is in v0.1.0, so the R API is the whole breaking surface.

## Commands

`air format .` reads `air.toml`. Package-specific commands:

```sh
tools/run-benchmarks                           # design §10 timings, as Markdown
ZUMIME_BENCH_FILES=10000 tools/run-benchmarks  # the same, smaller tree
```

Record each run in `.agents/benchmarks.md` with its date and machine.

```sh
Rscript tools/generate-tables.R            # rewrite sysdata.rda, zumime_types.h
Rscript tools/generate-tables.R --check    # exit 1 if they differ from their sources
Rscript tools/generate-tables.R --fetch    # download sources again, record sha256
tools/fetch-fixtures                       # fixtures, tests/testthat/fixtures/
tools/dump-file-type-answers               # answers into helper-file-type.R
tools/fuzz/run-local 60                    # fuzz harness, ASan+UBSan, 60 s
Rscript tools/fuzz/make-seeds.R            # rewrite tools/fuzz/seeds/
Rscript -e 'devtools::build_readme()'      # README.Rmd -> README.md
```

The registry is generated: edit `tools/types.yaml` (parents, aliases,
extensions, `detected_by`) and regenerate, never the outputs. The tests
that need fixtures skip without them; `oracles.yaml` fetches and runs them
in CI.

## Architecture

See `.agents/design.md` §4; this section records what has landed.

- **Registry (layer 1).** `tools/generate-tables.R` reads
  `tools/sources/` (IANA CSVs, Apache `mime.types`, checksummed in
  `tools/table-sources.yaml`) and `tools/types.yaml`, and writes
  `R/sysdata.rda` (`types_registry`, `types_ext_map`, `types_alias_map`,
  `types_table_version`) and `src/zumime_types.h` (enum
  `ZUMIME_T_<TYPE>` in sorted order, names and parent ids, defined once in
  `src/registry.c`). `R/registry.R` holds the registry functions;
  `canonical_type()` is the one place a type string is normalised.
- **Sniffer core (layer 2).** `src/zumime_sniff.h` declares it;
  `zumime_table.c` holds the signature rows (the standard's tables in its
  order, then zumime's `EXTRA` rows), `zumime_sniff.c` the algorithm,
  `zumime_charset.c` the charset chain and newline style. These files include
  no R header and must compile with `-std=c11 -Wall -Wextra -pedantic`
  (`test-standalone.R`). `src/zumime_r.c` is the R glue and the only place
  a type id becomes a `CHARSXP`.
- **Readers (layer 3).** `zumime_refine.c` runs after the standard's
  answer in the `"none"` context and hands the bytes to one reader:
  `zumime_zip.c`, `zumime_ole2.c`, `zumime_bmff.c`, `zumime_ebml.c`,
  `zumime_ogg.c`, `zumime_png.c`, `zumime_rdata.c` (gzip through
  `zumime_inflate.c`), `zumime_text.c` (structured text). A reader's answer
  is kept only when it descends from the current type; add a parent in
  `tools/types.yaml` rather than an exception.
- **Paths (layer 4).** `src/zumime_path.c` is the loop: it opens each
  path (`_wfopen` on Windows, native `fopen` elsewhere), reads the head,
  the ZIP tail and offset rows, checks completeness, and fills parallel
  vectors with no R allocation while a file is open. `R/type.R` builds the
  frame and the name columns; `R/check.R` holds `mime_check()`'s shortcut
  (`zumime_check()` in C) and `probe_count()`; `R/register.R` the session
  registry, mirrored in C by `zumime_reg[]` in `registry.c`.
- **Streams.** `src/zumime_stream.c` is the can-decide rule;
  `zumime_stream_push()` in `zumime_r.c` keeps the bytes in the external
  pointer's protected raw vector and the state in its address.
  `R/stream.R` is the API.
- **Fuzzing.** `tools/fuzz/harness.c` is the libFuzzer target over the core
  (no R), run by `.github/workflows/fuzz.yaml`; `tools/fuzz/driver.c` runs
  it without libFuzzer locally.
- **Native layer.** `src/init.c` registers every `.Call` entry point,
  declared in `src/zumime_r.h`, which also has `zumime_scalar_string()`:
  never pass a fresh `CHARSXP` to `Rf_ScalarString()` unprotected.
  `src/mime_record.c` is the WHATWG MIME type record over decoded code
  points; `src/guess.c` extracts suffixes for `mime_guess()`.
- **Conditions.** `zumime_abort(kind, message)` in `R/conditions.R` raises
  `zumime_<kind>_error`; `check_character()` raises `zumime_type_error`.
- **Results.** `new_result()` in `R/result.R` builds every result frame;
  `R/sniff.R` handles the supplied type (`supplied_type()`) and argument
  checks.

## Invariants that are easy to break

The design fixes these (RFC 0040 D6, D7, D8); add each further one when a
stage establishes it.

- **Zero hard runtime dependencies.** A `zu*` consumer takes no `Imports`
  by using zumime. Family sniffers (`zukomp` for the inner type of a
  compressed stream, `zuutf` for statistical charset detection, `zucsv`,
  `zujson`, `zutoml`) are `Suggests` and their absence degrades the answer
  to a coarser level, never to an error.
- **The answer is the same on every machine.** zumime never reads the
  system's `mime.types` or the Windows registry. A detector or table that
  consults the host makes results differ between CI legs and users.
- **Nothing is taken from the GPL `mime` package.** The extension table is
  generated from IANA's media types registry and Apache httpd's
  `mime.types` (Apache-2.0), with the Apache Software Foundation in
  `Authors@R` as copyright holder, the lesson CRAN taught `zukomp`,
  `zucrypt` and `zuxml` in October 2026. Copying from `mime` is a licence
  violation.
- **Native symbols use the `zumime_` prefix** (`ZUMIME_` for macros and the
  type enum).

## Testing

- **Conformance suites.** The design's section 7 names three:
  web-platform-tests' `mimesniff/` fixtures for parsing, Go's `net/http`
  sniff cases for the WHATWG table, and `file-type`'s fixtures for
  containers. All three are wired in: WPT and `file-type` fixtures through
  `tools/fetch-fixtures`, Go's cases in `helper-go-sniff.R`. Their notices
  are in `tests/testthat/COPYRIGHTS`.
- **Helpers.** `helper-abi.R` (symbol audit), `helper-tables.R`
  (`source_root()`), `helper-fixtures.R` (`fixture_dir()`,
  `wpt_mime_entries()`), `helper-bytes.R` (byte builders),
  `helper-go-sniff.R` (Go's sniff cases), `helper-containers.R` (ZIP, OLE2,
  ftyp, Ogg and EBML builders), `helper-file-type.R` (file-type's answers
  and the unclaimed fixtures), `helper-skip.R`.
- **Runtime.** With `NOT_CRAN=false` the whole suite, load included, took
  41 s on an Apple-silicon Mac (2026-10-26). The translated-path memory test
  (about 20 s) and the interrupt test skip on CRAN; the CI legs still run
  them.

## Continuous integration

This package calls:

- `.github/workflows/R-CMD-check.yaml` → `r-cmd-check.yml@v1`, with
  Windows R-devel added to the default runners and CRAN's NOSUGGESTS and
  NOLD flavors (`nosuggests`, `nold`, full profile only).
- `.github/workflows/native-checks.yaml` → `sanitizers.yml` (with ASan),
  `valgrind.yml`, `lto.yml`, `gctorture.yml`, `rchk.yml`, `analyzers.yml`
  and `cran-special.yml`, all `@v1` and all given the same profile.
- `.github/workflows/coverage.yaml` → `coverage.yml`, pinned to the v1.23.0
  commit, with `contents: write`. The badge goes to `gh-pages`, because the
  `main` ruleset requires pull requests and rejects a bot commit.
- `.github/workflows/fuzz.yaml` → `fuzz.yml@v1` over
  `tools/fuzz/harness.c`, built without R (`-DZUMIME_STANDALONE`, the R
  glue excluded). Two minutes on a pull request, 30 minutes nightly, an hour
  on dispatch or with the `fuzz-hour` label; the corpus is cached, so the
  runs add up to one campaign.

Its own workflows:

- `.github/workflows/oracles.yaml` runs the design §7 oracles and
  `tools/generate-tables.R --check`, which R CMD check cannot run because
  the fixtures and `tools/` are not in the tarball, plus the suite in
  shuffled order. `ZUMIME_REQUIRE_ORACLES=true` makes a missing fixture
  fail rather than skip.
- `.github/workflows/tables-upstream.yaml` checks weekly whether IANA's
  registry or Apache's `mime.types` changed against
  `tools/table-sources.yaml`, and opens or updates an issue asking for a
  regeneration pull request. r-actions' `vendor-upstream.yml` watches
  GitHub releases, which these files lack, and this repository does not let
  workflows open pull requests.
- `.github/workflows/pkgdown.yaml` is a bespoke `r-lib/actions` workflow,
  because `r-actions` has no pkgdown workflow to call. It deploys with
  `force: false` so it cannot overwrite a badge commit.

**Deviation from `ci.md`.** The R CMD check and native-check callers pass
`quick` only on a pull request without `full-ci`, and `full` otherwise,
rather than `profile: auto`. A push to `main` therefore runs the full set.
Don't wait on that run, and cancel older full runs it supersedes.

## Vendored native code

`src/zumime_inflate.c` is adapted from Mark Adler's `puff.c` version 2.3
(zlib's `contrib/puff`, zlib-style licence, Copyright 2002-2013 Mark
Adler). It is not under `src/vendor/`: it lives with the first-party
sources, keeps puff's notice in full, and is declared in
`inst/COPYRIGHTS`. Local changes, recorded in the file's header: errors
set a flag instead of `longjmp()`; input is refilled through a reader;
output goes to a 32 KiB window and only its first bytes are kept;
decoding can stop when that capture is full; the gzip member and trailer
check is new.
