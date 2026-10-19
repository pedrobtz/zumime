# Stage 4 — Paths and how to open them Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `mime_type(paths)` answers from bytes and name over a tree in one
C loop and fills the how-to-open columns; `mime_sniff()` takes paths;
`mime_check()` answers the allowlist question with a hidden shortcut;
`mime_register()` adds session types.

**Spec:** design §4 layer 4, §5 Results, §6.7, §6.9, §8, D5, D6, D12, D13,
D15; roadmap Stage 4.

## Decisions

- **agree** is `TRUE` when the byte type and the name type lie on one
  lineage (either descends from the other): bytes that say `text/plain`
  and a `.csv` name agree, bytes `image/png` and `.txt` do not. `NA` when
  either is unknown; bytes are unknown at `application/octet-stream` with
  confidence `none` and for unreadable paths.
- **inner = "name"** strips the wrapper's suffix and guesses the rest
  (`a.csv.gz` → `text/csv`; `.tgz`, `.tbz2`, `.txz`, `.tzst` → tar).
  **"decompress"** needs zukomp (else `zumime_dependency_error`), which has
  no streaming input: files up to 16 MiB are decompressed whole with the
  output capped at 16 MiB and the first `limit` bytes sniffed; larger
  files, codecs zukomp lacks, and failures fall back to the name.
- **complete = TRUE** reads the end: ZIP needs its EOCD record; PDF
  `%%EOF` in the last 1 KiB (and `/Encrypt` in the last 4 KiB sets
  `encrypted`); gzip (and RDS/RData in gzip) must inflate to its end with
  an 8-byte trailer whose size matches, streamed through the inflater;
  Parquet needs `PAR1` last. Others `NA`.
- **Deep probes**: offset rows beyond the head (ISO 9660 at 32769, HDF5 at
  512..2048) are read by seeking; a ZIP head (`PK\3\4`) gets its last
  66 KiB read as the tail.
- **mime_check()**: the C loop computes the standard's answer and the
  extra rows (cheap, and needed for exactness); readers, tail reads and the
  frame are skipped unless that base type is related to an allowed type
  (ancestor, descendant, or gzip for R's formats). One probe is counted per
  allowed type per input in a static counter read by `probe_count()`.
- **Registered types** get ids after the generated ones in a fixed-size C
  table (256 types, rules up to 64 bytes); data rules run when the current
  type equals their parent; function rules run in R afterwards.
- **text = "family"**: on a generic `text/plain`, `zucsv::sniff_csv()`
  (path) decides `text/csv` when it finds two or more columns;
  `zujson`/`zutoml` are consulted when installed. `zumime_info()$family`
  lists the family sniffers this session can use.

## Tasks

1. `src/zumime_path.c`: the loop, Unicode paths on Windows, interrupts
   every 256 files, `NA` rows and `zumime_io_error` under `strict`,
   directories, deep probes, tail reads, completeness.
2. Streaming inflate for the gzip completeness check.
3. `R/type.R`: `mime_type()`, `inner`, `by_name`, `agree`, `text`,
   `charset = "detect"`; `mime_sniff()` on paths.
4. `R/check.R` + C: `mime_check()`, `probe_count()`; the D15 equivalence
   property over fixtures × subsets of three allowed types.
5. `R/register.R` + C: `mime_register()`, `mime_unregister()`; registry
   functions see registered types.
6. Snapshot of `mime_type()` over a tree under `tempdir()`.
