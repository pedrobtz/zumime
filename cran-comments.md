# cran-comments

## Test environments

* local: macOS Tahoe 26.6 (arm64), R 4.6.1
* GitHub Actions (pedrobtz/r-actions): macOS, Windows and Ubuntu on
  R-release, Windows on R-devel, and Ubuntu on R-oldrel-1
* The `clang23`, `ubuntu-clang` and `ubuntu-gcc16` R-devel containers
  (pedrobtz/r-actions), compiling with `CC += -std=gnu23` and
  `CFLAGS += -pedantic`
* `nosuggests` (no suggested packages installed) and `nold` (R-devel
  without long double)
* Additional checks in CI: ASan and UBSan (clang and gcc), valgrind, LTO,
  rchk, gctorture and `-fanalyzer`

## R CMD check results

0 errors | 0 warnings | 1 note

* This is a new submission.

## Data sources and copyright

The type registry is generated from IANA's media types registry (dedicated
to the public domain under CC0 1.0) and from Apache httpd's `mime.types`
(Apache License 2.0). The Apache Software Foundation is listed in
`Authors@R` as a copyright holder, and `inst/COPYRIGHTS` states both sources
and their terms. Nothing is taken from the GPL-licensed 'mime' package.

`src/zumime_inflate.c` is adapted from Mark Adler's `puff.c` (zlib licence).
Its notice is kept in the file, and Mark Adler is listed in `Authors@R` as a
copyright holder. The tests carry Go's `net/http` sniff cases (BSD-3-Clause,
The Go Authors) and answers derived from `file-type` (MIT, Sindre Sorhus), with
their notices in `tests/testthat/COPYRIGHTS`. Both are listed in `Authors@R`.

## Optional packages not on CRAN

`zuutf` and `zutoml` are optional and not yet on CRAN. `mime_type()` uses them
only when they are installed, through `requireNamespace()`, and works fully
without them. They will be added to `Suggests` once they are published.

## Method references

The sniffing algorithm is the WHATWG MIME Sniffing Standard, a living
standard with no DOI; it is cited by URL in `Description` and under
`\references` in `?mime_sniff`.
