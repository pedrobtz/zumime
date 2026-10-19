# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working
with code in this repository.

## What this is

zumime tells what a file is from its bytes and from its name, with no
system dependency: a WHATWG MIME sniffer over the first kilobytes of a
file or raw vector, container and brand inspection (ZIP entry names, ISO
base media brands, RIFF, EBML, Ogg, OLE2), a type hierarchy ending at
`application/octet-stream`, and a generated extension table. One call
answers from both signals and says whether they agree. It is a
base-layer package: `zu*` consumers such as `zuhttp`, `zupdf`, `zuxlsx`,
`zurds` and `dastash` call it to decide a `Content-Type` or to refuse a
file before their parsers see it. Zero hard runtime dependencies; the
family’s own sniffers (`zukomp`, `zuutf`, `zucsv`, `zujson`) are reached
through `Suggests`. It does not parse multipart bodies, read filesystem
attributes, extract descriptive metadata (dimensions, duration, EXIF) or
hash content; those belong to other packages.

The specification is `.agents/design.md`, adopted on 2026-10-18 from
[RFC
0040](https://github.com/pedrobtz/packages/blob/main/rfcs/started/0040-zumime-media-type-detection.md)
in `pedrobtz/packages`. It outranks this file: `CLAUDE.md` orients, the
design doc decides. Every decision in the RFC’s section 13 is marked
**(C)**, written without a design conversation, so each stays open to
the maintainer until a stage records it.

## Current state

Stages 0 to 6 of `.agents/roadmap.md` implement the design’s v0.1.0
scope; `Full CI` and `v0.1.0 readiness` remain. The README is
`README.Rmd`; the one article is `vignettes/checking-an-upload.Rmd`,
built by pkgdown only.

## Stage tracking

Progress toward the next version is tracked as GitHub sub-issues, so the
parent issue shows a progress bar such as “6 of 7”.

- **One parent issue per target version**, titled with the bare version,
  for example `v0.1.0`. `v0.1.0` issue: created by `pkg-roadmap`.
- **One sub-issue per roadmap stage**, titled as the roadmap titles it,
  for example `Stage 3 — R interface`, and linking to that section. The
  number of stages is whatever the roadmap has; there is no fixed scale.
- **Every tracking issue carries the `stage` label**, so it can be told
  apart from bug and feature issues and left out of open-issue counts.
- **Close a stage by merging its pull request.** Put `Closes #<n>` in
  the body of the stage’s pull request. Never close a stage whose exit
  criteria are not met; record a deviation in the roadmap first.
- **The roadmap stays authoritative.** The issues record which stages
  are done, not what a stage requires. Adding, removing or renaming a
  stage means editing the roadmap and the sub-issues in the same change.
- **Each stage has a CI tier, `quick` or `full`.** The roadmap sets it,
  and `quick` is the default. See Continuous integration for what each
  means. The second-to-last stage, `Full CI`, runs the full set and
  fixes what it finds before `v0.1.0 readiness`.
- Close the parent issue when CRAN accepts the version and it is tagged.
  Opening a parent issue implies at least one stage sub-issue; a parent
  with no sub-issues shows no progress on the board.

## Versioning

A new package develops at `0.0.0.9000` and targets `0.1.0` for its first
CRAN release. Set `Version: 0.1.0` and the matching `NEWS.md` heading
when the package enters `Pre-flight`. Bump to `0.1.0.9000` only after
CRAN accepts it, never before: a `.9000` version above an unreleased
`0.1.0` heading is wrong.

Until the first release the R API may change freely. Sibling packages
can still depend on this one before CRAN does, through `Remotes:` or
`LinkingTo:`. The design names `anydoc`, `zuhttp`, `zusocks`,
`zuarchive`, `dastash`, `zudedup`, `zupdf`, `zuxlsx` and `zurds` as
consumers; none depends on it yet, and no C API or header is in v0.1.0,
so the R API is the whole breaking surface. A package that others wait
on should reach CRAN first.

## Commands

Run from the package root.

``` sh
Rscript -e 'devtools::load_all()'                # compile src/ and load
Rscript -e 'devtools::document()'                # roxygen -> NAMESPACE, man/
Rscript -e 'devtools::test()'                    # full testthat suite
Rscript -e 'devtools::test(filter = "<name>")'   # one test file
Rscript -e 'devtools::test(shuffle = TRUE)'      # order independence
Rscript -e 'devtools::check()'                   # R CMD check
air format .                                     # format R sources (air.toml)
```

Package-specific commands:

``` sh
tools/run-benchmarks                             # design §10 timings, Markdown table
ZUMIME_BENCH_FILES=10000 tools/run-benchmarks    # the same over a smaller tree
```

Record each run in `.agents/benchmarks.md` with its date and machine.

``` sh
Rscript tools/generate-tables.R            # regenerate R/sysdata.rda, src/zumime_types.h
Rscript tools/generate-tables.R --check    # exit 1 if they differ from their sources
Rscript tools/generate-tables.R --fetch    # download the sources again, record sha256
tools/fetch-fixtures                       # oracle fixtures into tests/testthat/fixtures/
tools/dump-file-type-answers               # file-type's answers into helper-file-type.R
tools/fuzz/run-local 60                    # the fuzz harness under ASan+UBSan, 60 s
Rscript tools/fuzz/make-seeds.R            # rewrite tools/fuzz/seeds/
Rscript -e 'devtools::build_readme()'      # README.Rmd -> README.md
```

The registry is generated: edit `tools/types.yaml` (parents, aliases,
extensions, `detected_by`) and regenerate, never the outputs. The tests
that need fixtures skip without them; `oracles.yaml` fetches and runs
them in CI.

## Architecture

See `.agents/design.md` §4; this section records what has landed.

- **Registry (layer 1).** `tools/generate-tables.R` reads
  `tools/sources/` (IANA CSVs, Apache `mime.types`, checksummed in
  `tools/table-sources.yaml`) and `tools/types.yaml`, and writes
  `R/sysdata.rda` (`types_registry`, `types_ext_map`, `types_alias_map`,
  `types_table_version`) and `src/zumime_types.h` (enum
  `ZUMIME_T_<TYPE>` in sorted order, names and parent ids, defined once
  in `src/registry.c`). `R/registry.R` holds the registry functions;
  `canonical_type()` is the one place a type string is normalised.
- **Sniffer core (layer 2).** `src/zumime_sniff.h` declares it;
  `zumime_table.c` holds the signature rows (the standard’s tables in
  its order, then zumime’s `EXTRA` rows), `zumime_sniff.c` the
  algorithm, `zumime_charset.c` the charset chain and newline style.
  These files include no R header and must compile with
  `-std=c11 -Wall -Wextra -pedantic` (`test-standalone.R`).
  `src/zumime_r.c` is the R glue and the only place a type id becomes a
  `CHARSXP`.
- **Readers (layer 3).** `zumime_refine.c` runs after the standard’s
  answer in the `"none"` context and hands the bytes to one reader:
  `zumime_zip.c`, `zumime_ole2.c`, `zumime_bmff.c`, `zumime_ebml.c`,
  `zumime_ogg.c`, `zumime_png.c`, `zumime_rdata.c` (gzip through
  `zumime_inflate.c`), `zumime_text.c` (structured text). A reader’s
  answer is kept only when it descends from the current type; add a
  parent in `tools/types.yaml` rather than an exception.
- **Paths (layer 4).** `src/zumime_path.c` is the loop: it opens each
  path (`_wfopen` on Windows, native `fopen` elsewhere), reads the head,
  the ZIP tail and offset rows, checks completeness, and fills parallel
  vectors with no R allocation while a file is open. `R/type.R` builds
  the frame and the name columns; `R/check.R` holds
  [`mime_check()`](https://pedrobtz.github.io/zumime/reference/mime_check.md)’s
  shortcut (`zumime_check()` in C) and `probe_count()`; `R/register.R`
  the session registry, mirrored in C by `zumime_reg[]` in `registry.c`.
- **Streams.** `src/zumime_stream.c` is the can-decide rule;
  `zumime_stream_push()` in `zumime_r.c` keeps the bytes in the external
  pointer’s protected raw vector and the state in its address.
  `R/stream.R` is the API.
- **Fuzzing.** `tools/fuzz/harness.c` is the libFuzzer target over the
  core (no R), run by `.github/workflows/fuzz.yaml`;
  `tools/fuzz/driver.c` runs it without libFuzzer locally.
- **Native layer.** `src/init.c` registers every `.Call` entry point,
  declared in `src/zumime_r.h`, which also has `zumime_scalar_string()`:
  never pass a fresh `CHARSXP` to `Rf_ScalarString()` unprotected.
  `src/mime_record.c` is the WHATWG MIME type record over decoded code
  points; `src/guess.c` extracts suffixes for
  [`mime_guess()`](https://pedrobtz.github.io/zumime/reference/mime_guess.md).
- **Conditions.** `zumime_abort(kind, message)` in `R/conditions.R`
  raises `zumime_<kind>_error`; `check_character()` raises
  `zumime_type_error`.
- **Results.** `new_result()` in `R/result.R` builds every result frame;
  `R/sniff.R` handles the supplied type (`supplied_type()`) and argument
  checks.

## Invariants that are easy to break

The design fixes these (RFC 0040 D6, D7, D8); add each further one when
a stage establishes it.

- **Zero hard runtime dependencies.** A `zu*` consumer takes no
  `Imports` by using zumime. Family sniffers (`zukomp` for the inner
  type of a compressed stream, `zuutf` for statistical charset
  detection, `zucsv`, `zujson`, `zutoml`) are `Suggests` and their
  absence degrades the answer to a coarser level, never to an error.
- **The answer is the same on every machine.** zumime never reads the
  system’s `mime.types` or the Windows registry. A detector or table
  that consults the host makes results differ between CI legs and users.
- **Nothing is taken from the GPL `mime` package.** The extension table
  is generated from IANA’s media types registry and Apache httpd’s
  `mime.types` (Apache-2.0), with the Apache Software Foundation in
  `Authors@R` as copyright holder, the lesson CRAN taught `zukomp`,
  `zucrypt` and `zuxml` in October 2026. Copying from `mime` is a
  licence violation.

## Testing conventions

- **Self-sufficient.** Every test builds its own inputs inside the
  `test_that()` block. No file-scope objects.
- **Self-contained.** Global state goes through `withr::local_*()`,
  randomised input through
  [`withr::local_seed()`](https://withr.r-lib.org/reference/with_seed.html).
  Tests write only under
  [`tempdir()`](https://rdrr.io/r/base/tempfile.html).
- **Assert on condition classes, never message text.** Use
  `expect_error(..., class = "<pkg>_<kind>_error")`. Wording belongs in
  snapshot tests.
- **Order independence.** `devtools::test(shuffle = TRUE)` is part of
  the definition of done.
- **Borrow a conformance suite before writing one.** Mainstream
  implementations in Python, Java, Go or Node usually ship a test
  corpus. Use it as an oracle rather than inventing cases by hand. The
  design’s section 7 names three: web-platform-tests’ `mimesniff/`
  fixtures for parsing, Go’s `net/http` sniff cases for the WHATWG
  table, and `file-type`’s fixtures for containers. All three are wired
  in: WPT and `file-type` fixtures through `tools/fetch-fixtures`, Go’s
  cases in `helper-go-sniff.R`.
- **Helpers live in `tests/testthat/helper-*.R`.** `helper-abi.R`
  (symbol audit), `helper-tables.R` (`source_root()`),
  `helper-fixtures.R` (`fixture_dir()`, `wpt_mime_entries()`),
  `helper-bytes.R` (byte builders), `helper-go-sniff.R` (Go’s sniff
  cases), `helper-containers.R` (ZIP, OLE2, ftyp, Ogg and EBML
  builders), `helper-file-type.R` (file-type’s answers and the unclaimed
  fixtures).
- **Keep the suite inside the CRAN time budget.** Only the scaffold’s
  placeholder test exists; no runtime to report.

## Definition of done

`devtools::document()` and `devtools::check()` clean, meaning 0 errors,
0 warnings and 0 notes. The one allowed note is “New submission” before
the first release. `devtools::test(shuffle = TRUE)` green. CI green at
the change’s tier: the quick profile for a `quick` roadmap stage or an
ordinary pull request, the full profile for a `full` stage, `Full CI`,
and every release. A user-facing change also needs a test, roxygen
documentation and a `NEWS.md` entry.

## Releasing to CRAN

- **CI is the pre-submission check.** The `pedrobtz/r-actions` R CMD
  check runs `--as-cran` on the CRAN-like runners and containers, and it
  replaces win-builder, the macOS builder and R-hub. None of them is a
  release step, and `cran-comments.md` lists the CI legs as its test
  environments.
- **Entering `Pre-flight`.** The roadmap’s feature stages are done, the
  version is set as in Versioning, `NEWS.md` and `cran-comments.md` are
  written, and CI is green. Only submission work remains.
- **Before submitting,** run `pkg-critical-review` once the roadmap is
  implemented and fix what it files, then `pkg-cran-review`, and resolve
  every finding. Both skills are in `pedrobtz/r-skills`.
- **The pretest is automated and does not read `cran-comments.md`.** A
  NOTE that is explained but not fixed gets the upload archived. Fix the
  NOTE instead of justifying it.
- **After acceptance,** `pkg-post-cran` tags the submitted commit with
  the bare version, `0.1.0` (no `v`), publishes the GitHub release,
  bumps to `0.1.0.9000`, closes the version’s parent issue and moves the
  board card.

## Editing rules

- roxygen comments are the source. Never edit `man/` or `NAMESPACE` by
  hand.
- Edit `README.Rmd`, not the generated `README.md`.
- Keep prose simple and short. One idea per sentence.
- Wrap roxygen text at 80 characters and run `air format .` on R
  sources.
- Use `lower_snake_case`, and prefix internal native symbols with
  `<pkg>_`.
- Keep hard runtime dependencies at zero unless a recorded design
  decision says otherwise.
- Export and document public functions. Do not create roxygen topics for
  internal ones.

## Continuous integration

Workflows come from `pedrobtz/r-actions`. Call those reusable workflows
instead of writing bespoke ones, and pin a released tag rather than
`main`. Pin a workflow that holds a write token, such as `coverage.yml`,
to a commit, with the tag in a comment. The `R-CMD-check` workflow must
call `r-cmd-check.yml`, because a hand-rolled one does not count as the
pre-submission check. This package calls:

- `.github/workflows/R-CMD-check.yaml` → `r-cmd-check.yml@v1`, `quick`
  on pull requests without the `full-ci` label, `full` otherwise, with
  Windows R-devel added to the default runners.
- `.github/workflows/native-checks.yaml` → `sanitizers.yml` (with ASan),
  `valgrind.yml`, `lto.yml`, `gctorture.yml`, `rchk.yml`,
  `analyzers.yml` and `cran-special.yml`, all `@v1` and all given the
  same profile.
- `.github/workflows/coverage.yaml` → `coverage.yml`, pinned to the
  v1.23.0 commit, with `contents: write`. The badge goes to `gh-pages`,
  because the `main` ruleset requires pull requests and rejects a bot
  commit.
- `.github/workflows/pkgdown.yaml` is a bespoke `r-lib/actions`
  workflow, because `r-actions` has no pkgdown workflow to call. It
  deploys with `force: false` so it cannot overwrite a badge commit.

Small edits get a small run. The shared workflows look at the files a
pull request changes, compared with its merge base:

- **Markdown only**, such as `README.md`, `NEWS.md` or
  `cran-comments.md`, skips every check. Only coverage and the pkgdown
  site run.
- **`DESCRIPTION` or `README.Rmd` as well**, and nothing else, adds one
  R CMD check on Ubuntu R-release.
- **Any other file** runs everything.

So put a README or `DESCRIPTION` touch-up in its own pull request. Once
a pull request changes code, every later push to it runs every workflow.

### Quick by default, full by exception

The full profile is slow. gctorture at step 20 alone has taken 36 to 107
minutes on sibling packages. Waiting on it between roadmap stages was
the main thing slowing roadmaps down, so:

- **Pull requests run the quick profile.** It should finish in under
  five minutes. If it doesn’t, raise gctorture’s `quick-step` or trim
  `quick-containers` in the caller workflows; never cut the full
  profile.
- **A `full` roadmap stage takes the `full-ci` label** and merges only
  on a green full run. The roadmap gives the reason in the stage’s
  `**CI.**` line, for example first compiled code, a `PROTECT` or
  finalizer change, a vendored library, or a Windows-only path.
- **Don’t wait on the full run a merge starts** on the default branch,
  and cancel older full runs it supersedes. A failure that only the full
  set shows goes on the `Full CI` stage issue as a comment with the run
  link, and is fixed there. A failure the quick profile also shows is
  fixed now.
- **`Full CI` and `v0.1.0 readiness` wait** for a green full run on
  their merge commit, and the release commit always needs one.
- Locally, run `gctorture(TRUE)` on the code a C change touches when it
  is cheap; the full run is the authority.

## Commits and pull requests

Short, imperative, sentence-case commit subjects, optionally scoped.
Keep each commit focused and do not sweep in unrelated files. A pull
request explains the user-visible outcome and the rationale, links
related issues, lists the checks that were run and the tests that were
skipped, and flags platform-sensitive or vendored changes. Performance
claims need evidence.

Never commit or push to the default branch. Work on a branch, open a
pull request, and leave it for review. Do not merge a pull request
unless you are told to.

When you find a defect, in this package or in an upstream tool, open an
issue for it rather than only working around it.

## Working with skills

The portfolio’s workflow skills live in `pedrobtz/r-skills` (`pkg-init`,
`pkg-roadmap`, `pkg-implement`, `pkg-critical-review`,
`pkg-cran-review`, `pkg-post-cran`, `pkg-readme`); the general process
skills are [Superpowers](https://github.com/obra/superpowers).
`building-a-package.md` in `pedrobtz/packages` walks through them in
order. Both sets defer to this file where they overlap, so the
settlements are recorded here.

- **One design.** The specification is `.agents/design.md`, adopted from
  the package’s RFC in `pedrobtz/packages/rfcs`. A package with an
  adopted design is past `brainstorming`; a design change goes through
  the RFC, not a new spec. Superpowers’ default
  `docs/superpowers/specs/` is not used.
- **Plans at two levels.** `.agents/roadmap.md` holds the stages, one
  mergeable pull request each, with exit criteria and a CI tier
  (`pkg-roadmap`). Inside a stage, `writing-plans` breaks the work into
  tasks of one test cycle each, saved as `.agents/plans/stage-<n>.md`.
  The roadmap stays authoritative; a plan is scratch and is not kept in
  sync.
- **Build and merge.** `pkg-implement` runs the stage loop: branch
  `stage-<n>-<slug>` from the stage issue, implement the plan with
  `test-driven-development`
  (`Rscript -e 'devtools::test(filter = "<name>")'` is the red/green
  command), open the pull request, merge on green at the stage’s CI
  tier. The confirmation the user gives at the start of that loop is the
  “told to merge” that Commits and pull requests requires, so the
  `finishing-a-development-branch` menu is not presented for stage pull
  requests. Any other pull request still waits for review.
- **Failures and claims.** A failing check or test goes through
  `systematic-debugging` before a fix. “Green”, “done” and “ready for
  CRAN” are claimed only after `verification-before-completion`: run the
  command, read the output.
- **Review.** `requesting-code-review` gates tasks inside a stage.
  `pkg-critical-review` reviews the whole package once the roadmap is
  implemented, with Posit’s reviewers, and files issues. CRAN’s reviewer
  email and GitHub review threads go through `receiving-code-review`.
- **Keep scratch out of the tarball.** `R CMD build` reads
  `.Rbuildignore`, not `.gitignore`. It must list `^\.agents$`,
  `^\.superpowers$` (the Superpowers task ledger), `^\.worktrees$` (if
  git worktrees are kept in the package directory; a sibling directory
  avoids the question), `^\.claude$`, `^CLAUDE\.md$`, `^AGENTS\.md$`,
  `^CRAN-SUBMISSION$` and `^cran-comments\.md$`. A stray top-level file
  is a NOTE, and the pretest archives on NOTEs.
