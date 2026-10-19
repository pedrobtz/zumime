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

## zumime against the targets (Stage 5)

Run 2026-10-19 on the same machine, R 4.5.2, zumime at the Stage 5 branch,
with `ZUMIME_BENCH_INCUMBENTS=false ZUMIME_BENCH_FILES=100000
tools/run-benchmarks`. The incumbents' numbers are the baseline above.
Targets do not gate v0.1.0 (D14); the ones missed are the next version's
measured work.

| §10 operation | Target | zumime | Met | Note |
| --- | --- | --- | --- | --- |
| `mime_sniff()` on a 4 KiB raw vector | under 5 µs | 30.2 µs | no | the C sniff is a few µs; the one-row result frame is most of it |
| `mime_type()`, 10⁵ files, warm cache | under 2 s; within 2× of `file` | 6.78 s | 2× of `file`: yes (21× faster); 2 s: no | open and read dominate |
| `mime_type()` on the §7.3 corpus | within 3× of `mimetype`'s Go CLI | 35.0 ms | not measured | `mimetype` CLI not installed; `file` takes 100 ms |
| `mime_guess()` over 10⁶ paths | under 1 s | 281 ms | yes | `mime::guess_type()` takes 1.33 s |
| `mime_parse()` over 10⁶ headers | under 2 s | 1.90 s | yes | |
| `mime_check()`, 3 allowed types | at least 3× faster than `mime_type()` | 349 ms against 577 ms | no (1.65×) | 10⁴ files; opening each file dominates both |
| `mime_push()` per chunk | under 1 µs when undecided | 6.8 µs | no | the `.Call` and argument checks; no re-sniff once nothing can decide before the limit |

Two fixes came out of the first Stage 5 run, which measured 489 µs per
`mime_sniff()` (a `data.frame()` per call, now built directly), 1.0 ms per
undecided push (a re-sniff of the whole buffer per push, now skipped past
the resource header for text and limit-bound readers), and `mime_check()`
reading related files twice (now one pass in C).
