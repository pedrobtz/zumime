# Stage 1 — Registry and tables Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The type registry exists as generated data shared by R and C, and
`mime_guess()`, `mime_extensions()`, `mime_parent()`, `mime_is()`,
`mime_types()`, `mime_parse()` and `mime_format()` work.

**Architecture:** `tools/generate-tables.R` reads stored copies of IANA's
CSVs and Apache's `mime.types` plus `tools/types.yaml`, and writes
`R/sysdata.rda` and `src/zumime_types.h`. Registry functions are vectorised
R over lookup vectors in `sysdata.rda`. `mime_parse()`/`mime_format()` are C
over code points decoded from UTF-8.

**Tech Stack:** R (>= 4.1), C99 via `.Call`, testthat 3e. `yaml`,
`jsonlite` and `digest` (SHA-256) in `tools/` and in skippable tests only.

**Spec:** `.agents/design.md` §4 layer 1, §6.3, §6.6, §6.8, §7.1, §8, D8,
D10, D11; roadmap Stage 1.

## Global Constraints

- No `Imports`. `yaml`, `jsonlite`, `digest` are used only by `tools/` and
  by tests that `skip_if_not_installed()` them; tests that need them are
  skipped where absent.
- Nothing from the GPL `mime` package. Sources: IANA CSVs (CC0) and Apache
  httpd `mime.types` (Apache-2.0).
- Every condition inherits `zumime_error`; classes `zumime_type_error`,
  `zumime_parse_error`.
- `mime_guess()`, `mime_is()` never raise on input values.
- Root type `application/octet-stream`; text types descend from
  `text/plain`; `+xml` from `application/xml`; `+json` from
  `application/json`; `+zip` from `application/zip`.
- Canonical extension: Apache's first, overridden in `types.yaml` (`jpg`
  over `jpeg`, `yaml` over `yml`).

## Review Focus

- Path with no extension, a trailing dot, or a dotfile (`.bashrc`) → `NA`
  from `mime_guess()`, not an error. Test in Task 3.
- Windows separators (`C:\dir\a.PDF`) → separator `\` counts. Test in Task 3.
- An extension Apache lists under two types (`sub`, `wmz`) → first in file
  order wins, and the losing type does not list it. Test in Task 2.
- `mime_is()` with parameters and case on both sides
  (`"Image/PNG; q=1"`, `"IMAGE"`) → `TRUE`. Test in Task 4.
- A WPT input containing U+0000 cannot be an R string → those entries are
  skipped with a counted message, not failed. Test in Task 5.

---

### Task 1: Sources and the generator

**Files:**
- Create: `tools/sources/{application,audio,font,haptics,image,message,model,multipart,text,video}.csv`, `tools/sources/mime.types`
- Create: `tools/table-sources.yaml`, `tools/types.yaml`, `tools/generate-tables.R`
- Create: `R/sysdata.rda`, `src/zumime_types.h`, `src/registry.c`
- Test: `tests/testthat/test-tables.R`

**Interfaces:**
- Produces in `sysdata.rda`: `registry` (data.frame: `type` chr,
  `parent` chr (`NA` for root), `aliases` list, `extensions` list,
  `category` chr = top-level type, `detected_by` chr), `ext_map` (named
  chr, lower-case extension without dot → type), `alias_map` (named chr,
  alias → canonical type), `table_version` (chr, `YYYY-MM-DD`, latest
  retrieval date).
- Produces in C: `enum zumime_type_id { ZUMIME_T_<NAME>, ..., ZUMIME_N_TYPES }`,
  `extern const char *const zumime_type_names[]`,
  `extern const int zumime_type_parents[]` (−1 for root), defined in
  `src/registry.c` through `#define ZUMIME_TYPES_IMPLEMENTATION`.
- CLI: `Rscript tools/generate-tables.R [--fetch] [--check]`. `--fetch`
  downloads, rewrites `table-sources.yaml` (url, retrieved, sha256);
  default verifies sha256 then writes outputs; `--check` writes to a
  tempdir and exits 1 when outputs differ.

- [ ] Test `regeneration reproduces the tables` (skip when `tools/` or
  `yaml`/`digest` absent): run generator into tempdir; header bytes
  identical; `identical()` on each sysdata object (`.rda` bytes carry the
  writer's R version, so objects are compared, not bytes).
- [ ] Test `every type reaches the root without a cycle`; `every parent is
  a registered type`; `extensions map to one type`.
- [ ] Implement. Enum names: upper-case, non-alnum → `_`, collisions get
  `_2`. IANA: `Template` column, lower-cased; `in favor of <type>` in
  `Name` makes the row an alias of `<type>`. Apache: `# type` lines are
  types without extensions. Types sorted; ids are sort order.
- [ ] Verify `Rscript tools/generate-tables.R --check` exits 0; commit.

### Task 2: Conditions and `mime_types()`, `mime_extensions()`

**Files:** Create `R/conditions.R`, `R/registry.R`; Test `tests/testthat/test-registry.R`

**Interfaces:**
- `zumime_abort(kind, message, call)` raises class
  `c("zumime_<kind>_error", "zumime_error", "error", "condition")`.
- `canonical_type(x)`: essence (parameters stripped, lower-cased,
  trimmed), aliases resolved; unknown essences returned as is; `NA` stays.
- `mime_types()` → `registry`. `mime_extensions(type)` → list of chr,
  canonical first, `character(0)` for unknown.

- [ ] Tests: `mime_extensions("image/jpeg")[[1]][1] == "jpg"`;
  `mime_extensions("application/x-sqlite3")` equals that of
  `application/vnd.sqlite3`; `sub` listed by exactly one type; non-character
  input → `zumime_type_error`.

### Task 3: `mime_guess()`

**Files:** Modify `R/registry.R`; Test `tests/testthat/test-guess.R`

- [ ] Tests: `report.FINAL.PDF` → `application/pdf`; `a.tar.gz` →
  `application/gzip` via the compound; `C:\\x\\a.csv` → `text/csv`;
  `README`, `a.`, `.bashrc`, `NA` → `NA`; round-trip property over every
  type and extension.
- [ ] Implement: basename after last `/` or `\`, lower-case, try the
  two-dot suffix before the one-dot suffix in `ext_map`.

### Task 4: `mime_parent()`, `mime_is()`

**Files:** Modify `R/registry.R`; Test `tests/testthat/test-hierarchy.R`

- `mime_parent(type)` → list of chr, nearest first, `character(0)` for the
  root, `NA_character_` for an unknown type.
- `mime_is(x, what)` → logical, length of `x`; `NA` for `NA`; `TRUE` when
  canonical `x` equals, descends from, or has top-level type equal to any
  canonical `what`. Unknown `x` descends from `application/octet-stream`.
- [ ] Tests: the two roadmap exit-criterion calls; `mime_is("Image/PNG; q=1",
  "IMAGE")`; `mime_is("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/zip")`.

### Task 5: `mime_parse()`, `mime_format()` in C

**Files:** Create `src/mime_record.c`, `R/record.R`, `tools/fetch-fixtures`; Modify `src/init.c`; Test `tests/testthat/test-record.R`

- `mime_parse(x, strict = FALSE)` → list, one per input:
  `list(type=, subtype=, parameters=<named list of chr>)` or `NULL`.
  `strict = TRUE` raises `zumime_parse_error` on the first failure.
- `mime_format(record)` → chr; accepts one record or a list of records;
  `NULL` → `NA`.
- WHATWG "parse a MIME type" and "serialize a MIME type" over code points
  (decode UTF-8 in C; token and quoted-string-token code point sets).
- `tools/fetch-fixtures` fetches WPT `mimesniff/mime-types/resources/*.json`
  at `0f195499f06d0833e768b01a1a8ce942b8622fc8` into `tests/testthat/fixtures/wpt/`.
- [ ] Hand tests (always run): the two `Basics` rows, quoted value with
  backslash, duplicate parameter keeps first, `"/html"` → `NULL`.
- [ ] Oracle test (skip without fixtures): every entry, `mime_format(mime_parse(input))`
  equals `output` (`NA` for `null`); entries with U+0000 skipped and counted.

### Task 6: Provenance and wrap-up

**Files:** `DESCRIPTION` (ASF `cph`), `inst/COPYRIGHTS`, `R/info.R`
(`table_version`), `.github/workflows/tables.yaml`, `NEWS.md`, roadmap.

- [ ] `zumime_info()$table_version == table_version`.
- [ ] `tables.yaml`: on PR runs `--check`; weekly schedule runs `--fetch`
  and opens a PR on change (`vendor-upstream.yml` watches a vendored
  library's releases, not data files, so it does not fit; recorded).
- [ ] `devtools::document()`, `check()` 0/0/0, `test(shuffle = TRUE)`.
