# Type files from their bytes and their names

Reads the first bytes of each path in one C loop, types them as
[`mime_sniff()`](https://pedrobtz.github.io/zumime/reference/mime_sniff.md)
does, guesses a type from the name as
[`mime_guess()`](https://pedrobtz.github.io/zumime/reference/mime_guess.md)
does, and says whether the two agree. The other columns answer what a
consumer asks before opening a file: what a compressed file holds,
whether it is encrypted or truncated, its line endings, and a script's
interpreter.

## Usage

``` r
mime_type(
  path,
  limit = 4096L,
  complete = FALSE,
  inner = c("name", "decompress"),
  text = c("whatwg", "family"),
  charset = c("declared", "detect"),
  strict = FALSE
)
```

## Arguments

- path:

  A character vector of paths.

- limit:

  The number of bytes to read from each file; `0` reads whole files.

- complete:

  If `TRUE`, also read each file's end and fill `complete`: a ZIP needs
  its end-of-central-directory record, a PDF `%%EOF` in its last
  kilobyte, a gzip stream must inflate to its trailer, and Parquet must
  end in `PAR1`. Other formats give `NA`. A PDF is `encrypted` when its
  trailer dictionary, found in the last 4 KB, names `/Encrypt`.

- inner:

  How to find the type inside a compression wrapper (gzip, bzip2, xz,
  zstd, LZ4, lzip, compress): `"name"` takes it from the rest of the
  name, so `data.csv.gz` holds `text/csv`; `"decompress"` decompresses
  gzip with zukomp and sniffs the result, falling back to the name for
  other wrappers and for files over 16 MiB.

- text:

  `"whatwg"` keeps the standard's answer for text; `"family"` offers a
  still generic `text/plain` to the family's sniffers, which read whole
  files.

- charset:

  `"declared"` reports the charset the bytes declare; `"detect"` asks
  zuutf where they declare none, or only the C1 guess.

- strict:

  If `TRUE`, an unreadable path raises `zumime_io_error`.

## Value

A `zumime_result` data frame with one row per path and columns `path`,
`type`, `confidence`, `charset`, `by_name`, `agree`, `inner`,
`encrypted`, `complete`, `newline` and `interpreter`.

## Details

Unreadable and missing paths give a row with `type` `NA` and
`confidence` `"none"`, so one bad entry does not abort a scan of a tree;
`strict = TRUE` raises `zumime_io_error` instead. A directory is
`inode/directory`, and nothing is read from it.

`agree` is `TRUE` when the byte type and the name type lie on one
lineage, so bytes that say `text/plain` agree with a `.csv` name and a
ZIP agrees with a `.docx` name; `FALSE` when they differ, such as a PNG
named `.txt`; and `NA` when either is unknown. A disagreement is a
finding, not an error.

The default answer depends on nothing outside the package. Three
arguments ask for an optional family package. `inner = "decompress"`
uses zukomp. `charset = "detect"` uses zuutf. `text = "family"` uses
zucsv, zujson and zutoml, each when installed. zuutf and zutoml are not
yet on CRAN; install them from GitHub. An argument whose package is
absent raises `zumime_dependency_error`. `text = "family"` uses
whichever sniffers are installed, listed by `zumime_info()$family`. An
error inside an optional package leaves that answer as it was, so a
corrupt stream keeps the name's `inner`.

## See also

[`mime_sniff()`](https://pedrobtz.github.io/zumime/reference/mime_sniff.md)
for bytes and the standard's contexts,
[`mime_check()`](https://pedrobtz.github.io/zumime/reference/mime_check.md)
for an allowlist.

## Examples

``` r
dir <- tempfile()
dir.create(dir)
writeLines(c("a,b", "1,2"), file.path(dir, "data.csv"))
saveRDS(mtcars, file.path(dir, "cars.rds"))
writeBin(as.raw(c(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a)),
  file.path(dir, "logo.txt"))
mime_type(list.files(dir, full.names = TRUE))
#> <zumime_result: 3 rows>
#>                                        path              type confidence
#> 1 /tmp/RtmpI8JRzD/file194b4f8cfe18/cars.rds application/x-rds   definite
#> 2 /tmp/RtmpI8JRzD/file194b4f8cfe18/data.csv        text/plain   probable
#> 3 /tmp/RtmpI8JRzD/file194b4f8cfe18/logo.txt         image/png   definite
#>   charset           by_name agree inner encrypted complete newline interpreter
#> 1    <NA> application/x-rds  TRUE  <NA>        NA       NA    <NA>        <NA>
#> 2   UTF-8          text/csv  TRUE  <NA>        NA       NA      lf        <NA>
#> 3    <NA>        text/plain FALSE  <NA>        NA       NA    <NA>        <NA>
unlink(dir, recursive = TRUE)
```
