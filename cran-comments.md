# cran-comments

## Test environments

* local: macOS Sequoia 15.7 (x86_64), R 4.5.2
* GitHub Actions (pedrobtz/r-actions): macOS, Windows and Ubuntu on
  R-release, Windows on R-devel, and Ubuntu on R-oldrel-1
* R-hub CRAN-like containers on R-devel: `clang23`, `ubuntu-clang` and
  `ubuntu-gcc16`, compiling with `CC += -std=gnu23` and `CFLAGS += -pedantic`
* Additional checks in CI: ASan and UBSan (clang and gcc), valgrind, LTO,
  rchk, gctorture, `-fanalyzer`, and a check without Suggests

## R CMD check results

0 errors | 0 warnings | 1 note

* This is a new submission.

## Data sources and copyright

The type registry is generated from IANA's media types registry (dedicated
to the public domain under CC0 1.0) and from Apache httpd's `mime.types`
(Apache License 2.0). The Apache Software Foundation is listed in
`Authors@R` as a copyright holder, and `inst/COPYRIGHTS` states both sources
and their terms. Nothing is taken from the GPL-licensed 'mime' package.

## Method references

The sniffing algorithm is the WHATWG MIME Sniffing Standard, a living
standard with no DOI; it is cited by URL in `Description` and under
`\references` in `?mime_sniff`.
