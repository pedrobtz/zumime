# Is a file one of these types?

The upload question: `TRUE` when the bytes say the file is one of
`allowed`, or a descendant of one, at `min_confidence` or better. The
name is never consulted, since the question exists because names lie.

## Usage

``` r
mime_check(x, allowed, min_confidence = "probable")
```

## Arguments

- x:

  A character vector of paths, or one raw vector.

- allowed:

  A character vector of types, aliases or top-level types, as
  [`mime_is()`](https://pedrobtz.github.io/zumime/reference/mime_is.md)
  takes them.

- min_confidence:

  The weakest evidence accepted: `"probable"` (the default) accepts byte
  evidence of either kind; `"definite"` is for allowlists that must not
  trust a text heuristic. `"extension"` and `"none"` are accepted for
  completeness.

## Value

A logical vector, one element per path (one for a raw vector); `FALSE`
for an unreadable path unless `min_confidence` is `"none"`, where it is
`NA`.

## Details

The answer always equals
`mime_is(t$type, allowed) & t$confidence >= min_confidence` with
`t <- mime_type(x)` (or `mime_sniff(x)` for a raw vector). It is
computed with a shortcut that this equality hides: the container and
text readers, tail reads and the result frame are skipped for every
input whose first answer could not end as an allowed type. Call
[`mime_type()`](https://pedrobtz.github.io/zumime/reference/mime_type.md)
to learn why a file was refused.

## See also

[`mime_type()`](https://pedrobtz.github.io/zumime/reference/mime_type.md)
for the full answer.

## Examples

``` r
dir <- tempfile()
dir.create(dir)
png <- as.raw(c(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a))
writeBin(png, file.path(dir, "photo.pdf"))
writeLines("%PDF-1.7", file.path(dir, "real.pdf"))
paths <- file.path(dir, c("photo.pdf", "real.pdf"))
mime_check(paths, c("application/pdf", "image/jpeg"))
#> [1] FALSE  TRUE
mime_check(png, "image")
#> [1] TRUE
unlink(dir, recursive = TRUE)
```
