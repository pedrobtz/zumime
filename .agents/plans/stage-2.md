# Stage 2 — WHATWG sniffer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `mime_sniff()` over a raw vector computes the WHATWG MIME Sniffing
Standard's computed type for every combination of supplied type, no-sniff
flag and context, with the charset the bytes declare.

**Architecture:** A pure C core (`zumime_sniff.c`, `zumime_table.c`,
`zumime_text.c`, `registry.c`; no R headers) takes bytes and an input
struct and fills a result struct. `zumime_r.c` is the only R glue: it turns
the struct into R values and is the only place a type id becomes a
`CHARSXP`. `R/sniff.R` validates arguments, canonicalises the supplied
type, applies its charset parameter, and builds the result frame.

**Tech Stack:** C11 core, R glue in C99, testthat 3e; Go 1.27 only to dump
`sniff_test.go`'s cases once into a test data file.

**Spec:** `.agents/design.md` §4 layer 2, §5 Results, §6.1, §6.2
(signatures), §6.5, §7.2, D2, D3, D4; the standard (read 2026-10-19).

## Global Constraints

- Core files include no R header and compile with
  `cc -std=c11 -Wall -Wextra -pedantic -DZUMIME_STANDALONE` without
  warnings.
- Result `type` is a canonical essence (aliases resolved: `image/x-icon`
  → `image/vnd.microsoft.icon`, `application/x-gzip` → `application/gzip`).
- `confidence` is an ordered factor, levels `none < extension < probable <
  definite` (D3). Table or algorithm match: `definite`; text by the
  no-binary-bytes rule: `probable`; floor `application/octet-stream` and an
  unverified supplied type: `none`; a C1 charset guess caps at `probable`.
- `mime_sniff()` never raises on bytes; argument errors are
  `zumime_type_error`.
- Contexts: `none` = §7 plus zumime's extra rows (and Stage 3 readers);
  `browsing` = §7 with the standard's tables only; `image`, `audio_video`,
  `font` = §8.2, §8.3, §8.7.

## Review Focus

- Empty raw vector → `text/plain`, `probable`, charset `UTF-8`. Task 4.
- A raw vector longer than `limit` → only `limit` bytes used, and a UTF-8
  code point cut at the limit does not demote the charset. Task 3.
- Supplied type that fails `mime_parse()` (`"garbage"`) → treated as
  undefined, so bytes are sniffed. Task 4.
- Font context with no supplied type and no match → floor, not `NA`. Task 4.
- MP4 whose `ftyp` box is larger than the bytes in hand → not MP4 (the
  standard's length rule), so `application/octet-stream`. Task 2.

---

### Task 1: Table and matcher core

**Files:** Create `src/zumime_sniff.h`, `src/zumime_table.c`,
`src/zumime_sniff.c`; Test `tests/testthat/test-signatures.R`

**Interfaces:**
- `typedef struct { uint32_t offset; const unsigned char *pattern, *mask;
  uint8_t len; int type; int parent; unsigned flags; uint8_t group; }
  zumime_sig;` flags `ZUMIME_SIG_WS` (skip leading whitespace bytes),
  `ZUMIME_SIG_TT` (last byte is a tag-terminating byte),
  `ZUMIME_SIG_TAR` (verify the tar checksum at 148). Groups in order:
  `SCRIPTABLE, NONSCRIPTABLE, IMAGE, AUDIO_VIDEO, FONT, ARCHIVE, EXTRA`.
- `extern const zumime_sig zumime_sigs[]; extern const int zumime_n_sigs;`
- `int zumime_match_row(const zumime_sig *, const unsigned char *, size_t);`
- R-callable `zumime_signature_rows()` → list of columns (offset, pattern
  raw list, mask raw list, type, group, flags) for tests.
- [ ] Test: every row matches an input generated from it (pattern under
  mask, zero fill, padded to 1445) in its group's context, and the result
  is the row's type or a descendant; `TT` rows match with `>` too.

### Task 2: The algorithm (§7, §7.1, §7.2, §8)

**Files:** Modify `src/zumime_sniff.c`; Test `tests/testthat/test-sniff.R`

- `typedef struct { const char *supplied; int supplied_id; int apache_bug;
  int no_sniff; int context; int truncated; } zumime_input;`
- `typedef struct { int type; /* id or ZUMIME_SUPPLIED or ZUMIME_FLOOR */
  int confidence; int charset; size_t cs_off, cs_len; int newline; }
  zumime_result;`
- `void zumime_sniff(const unsigned char *buf, size_t len, const
  zumime_input *in, zumime_result *out);` resource header = first 1445.
- MP4, WebM, MP3-without-ID3 per the standard, MP3 frame size and tables
  as Mozilla's `mp3sniff.c` (the standard's precedence typos are not
  followed). WebM's vint parse starts at `iter`.
- [ ] Tests: XML/HTML supplied returned as is; `unknown/unknown`, `*/*`
  sniffed; `no_sniff` with supplied → supplied; no-sniff with no supplied
  type disables the scriptable table (`<html>` → `text/plain`); Apache bug
  strings run text-or-binary; image supplied + PNG bytes → PNG; image
  supplied + junk → supplied; contexts per §8; MP4 brand in compatible
  list; oversize `ftyp` → not MP4; WebM DocType; MP3 two frames.

### Task 3: Charset and newline (`zumime_text.c`)

- Chain for text results: BOM (`UTF-8`, `UTF-16BE`, `UTF-16LE`); XML
  declaration `encoding` for XML; HTML `<meta>` prescan over 1024 bytes
  for HTML (labels `utf-16*` → `UTF-8`, `x-user-defined` →
  `windows-1252`, others as declared); valid UTF-8 (`UTF-8`), ignoring a
  cut trailing sequence when `truncated`; C1 rule (`windows-1252` /
  `ISO-8859-1`, confidence capped at `probable`). The supplied type's
  `charset` parameter wins, applied in R.
- Declared labels are reported as written, not resolved to the Encoding
  Standard's names (recorded in the roadmap).
- `newline`: `lf`, `crlf`, `cr`, `mixed`, `NA` when none or binary.
- [ ] A test table per rule, including a cut code point.

### Task 4: `mime_sniff()` and the result frame

**Files:** Create `src/zumime_r.c`, `R/sniff.R`, `R/result.R`; Test
`tests/testthat/test-sniff.R`, `tests/testthat/test-result.R`

- `mime_sniff(x, type = NULL, no_sniff = FALSE, context = c("none",
  "browsing", "image", "audio_video", "font"), limit = 4096L)`; `x` raw in
  this stage (character → `zumime_type_error` until Stage 4).
- Frame columns: `path, type, confidence, charset, inner, encrypted,
  complete, newline, interpreter`; class `c("zumime_result",
  "data.frame")`; `print()` method; snapshot test.

### Task 5: Oracles and standalone build

- `tests/testthat/data-go-sniff.R` generated once from Go 1.27.1's
  `sniff_test.go` (BSD-3, attributed); every case agrees: canonical
  `type` equals or descends from Go's, charset equal ignoring case where Go
  gives one.
- Test: compile the core with `-std=c11 -Wall -Wextra -pedantic` and no
  warnings (skip without a compiler or source tree); `oracles.yaml` runs it.
- `full-ci` label on the PR.
