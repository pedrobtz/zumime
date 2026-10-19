# zumime: benchmarks

Measured by `tools/run-benchmarks` against the targets of design §10. Each
run is recorded with its date, machine and tool versions; later runs are
added below, never written over. Targets do not gate v0.1.0 (D14).

## Baseline, before any zumime code (Stage 0)

Run 2026-10-19 on macOS Sequoia 15.7.9 (Apple silicon laptop), R 4.5.2,
`file-5.41`, `mime` 0.13. The tree is 100,000 files of 4 KiB in `tempdir()`
whose first bytes cycle through PNG, PDF, ZIP, gzip, HTML, text, JSON and
JPEG. The corpus is `sindresorhus/file-type`'s `fixture/` at v22.2.0
(`11e0d64`). Times are the median of three to five runs after a warm-up.

| §10 operation | Target | Incumbent | Time | Note |
| --- | --- | --- | --- | --- |
| `mime_sniff()` on a 4 KiB raw vector | under 5 µs | `file --mime-type` | 1.1 ms | per file, in a batch of 10,000 through `-f` |
| `mime_type()`, 10⁵ files, warm cache | under 2 s; within 2× of `file` | `file --mime-type` | 139.91 s | one process, `-f` list |
| `mime_type()` on the §7.3 corpus | within 3× of `mimetype`'s Go CLI | `file --mime-type` | 100.0 ms | 273 files; `mimetype` CLI not installed |
| `mime_guess()` over 10⁶ paths | under 1 s | `mime::guess_type()` | 1.33 s | eight extensions, one unknown |
| `mime_parse()` over 10⁶ headers | under 2 s | none | n/a | no installed tool parses `Content-Type` |
| `mime_check()`, 3 allowed types | 3× faster than `mime_type()` | none | n/a | a ratio of zumime's own calls |
| `mime_push()` per chunk | under 1 µs when undecided | none | n/a | no incumbent streams |

`mimetype`'s Go CLI was not installed, so the corpus row has no Go number;
the roadmap asks for it only where it is already available.
