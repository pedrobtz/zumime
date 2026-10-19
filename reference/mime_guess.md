# Guess a type from a file name

Takes the longest known suffix after the last directory separator,
ignoring case, so `.tar.gz` is known as a compound and
`report.FINAL.PDF` is a PDF. Nothing is read from the file.

## Usage

``` r
mime_guess(path)
```

## Arguments

- path:

  A character vector of paths or file names.

## Value

A character vector of canonical types, `NA` where no suffix is known.

## See also

[`mime_extensions()`](https://pedrobtz.github.io/zumime/reference/mime_extensions.md)
for the reverse.

## Examples

``` r
mime_guess(c("report.FINAL.PDF", "data.tar.gz", "README", "x.rds"))
#> [1] "application/pdf"   "application/gzip"  NA                 
#> [4] "application/x-rds"
```
