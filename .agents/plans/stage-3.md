# Stage 3 — Containers and formats Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** In the `"none"` context, refine the WHATWG answer from the bytes
already read: ZIP and OLE2 documents, ISO base media brands, EBML, Ogg
codecs, R and analytic data formats, structured text, and the
`encrypted` and `interpreter` columns.

**Architecture:** `src/zumime_refine.c` runs after the computed type and
zumime's extra rows. It hands the bytes to the reader for the current
type and accepts a reader's answer only when it descends from the current
type (one exception: gzip-wrapped RDS and RData, recorded in the roadmap).
Readers are pure C11 like the rest of the core, one file each.

**Spec:** design §4 layer 3, §6.2 (containers), §6.4, §7.3, D6, D7;
roadmap Stage 3.

## Global Constraints

- Container and signature evidence is `definite`; structured-text
  evidence is `probable`.
- A refinement must descend from the type it refines, so a prefix's type
  is always an ancestor of the whole's (design §9), except gzip → RDS/RData.
- Readers never read past `len` and allocate nothing.
- Charset and newline are computed after refinement.

## Review Focus

- A ZIP whose central directory is beyond the bytes in hand → local
  headers are walked from the start instead. Task 2.
- A ZIP entry with the data-descriptor flag and zero sizes → the walk
  stops after that name rather than misreading. Task 2.
- An OLE2 file truncated inside its directory → names read so far still
  decide. Task 3.
- `text/plain` that merely starts with `{` but is not JSON → stays
  `text/plain`. Task 6.
- A shebang with `env` and options (`#!/usr/bin/env -S python3 -u`) →
  interpreter `python3`. Task 6.

## Tasks

1. **Registry and rows.** `types.yaml`: new types (ELF, Mach-O, RPM, deb,
   ar, LZ4, lzip, Avro, Blender, ICNS, CR3, WARC, scripts, HAR, PEM, flat
   ODF), parents so every refinement descends (`text/xml` an alias of
   `application/xml`; BMFF children under `video/mp4`; Ogg codecs under
   `application/ogg`; ODF, OOXML, 3MF under `application/zip`; script and
   line-oriented text under `text/plain`), `detected_by`. EXTRA rows for
   the binary signatures, R and analytic formats included.
2. **ZIP** (`zumime_zip.c`): EOCD in the last 66 KiB in hand, else local
   headers; `mimetype` entry content; OOXML folders and `vbaProject.bin`;
   JAR, APK, 3MF; `encrypted` from flag bit 0 or the 0x9901 extra field.
3. **OLE2** (`zumime_ole2.c`): directory sectors through the FAT when in
   hand, else the first directory sector; stream names and root CLSID;
   `EncryptionInfo` → `encrypted = TRUE`.
4. **BMFF, EBML, Ogg** (`zumime_bmff.c`, `zumime_ebml.c`, `zumime_ogg.c`):
   brands major-first; DocType within the first 4 KiB; first packet's codec
   header.
5. **R formats** (`zumime_inflate.c`, `zumime_rdata.c`): a bounded raw
   inflate of the first 64 output bytes, enough to see an RDS or RData
   header inside gzip; uncompressed headers by EXTRA rows.
6. **Structured text** (`zumime_text.c`; charset moves to
   `zumime_charset.c`): XML root and namespace; JSON scan with first-level
   keys and NDJSON; first-line formats and shebang interpreters.
7. **Oracle.** `tools/fetch-fixtures` adds `file-type` v22.2.0's
   `fixture/`; `helper-file-type.R` holds file-type's own answers (dumped
   once with Node); the test asserts every claimed fixture's type equals or
   descends from file-type's, and lists the unclaimed ones.
