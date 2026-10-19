# Sniff a type from bytes

Runs the WHATWG MIME Sniffing Standard's "MIME type sniffing algorithm"
over the first bytes of a raw vector, with its three inputs: the
supplied type (a `Content-Type` value, or `NULL`), the no-sniff flag,
and the sniffing context.

## Usage

``` r
mime_sniff(
  x,
  type = NULL,
  no_sniff = FALSE,
  context = c("none", "browsing", "image", "audio_video", "font"),
  limit = 4096L
)
```

## Arguments

- x:

  A raw vector.

- type:

  The supplied type, such as a `Content-Type` header value, or `NULL`
  when there is none. A value that does not parse as a MIME type is
  treated as `NULL`.

- no_sniff:

  `TRUE` for the no-sniff flag (`X-Content-Type-Options: nosniff`): a
  supplied type is then returned as is.

- context:

  One of `"none"`, `"browsing"`, `"image"`, `"audio_video"` or `"font"`.

- limit:

  The number of bytes to read; `0` reads them all. A raw vector longer
  than `limit` is sniffed on its first `limit` bytes.

## Value

A `zumime_result` data frame with one row and columns `path` (`NA` for a
raw vector), `type` (a canonical type), `confidence` (an ordered factor:
`none < extension < probable < definite`), `charset`, `inner`,
`encrypted`, `complete`, `newline` (`"lf"`, `"crlf"`, `"cr"`, `"mixed"`,
or `NA`) and `interpreter`.

## Details

The `"browsing"` context is what a browser computes for a navigation:
the standard's tables and nothing else. The default `"none"` asks the
plain file question: the same algorithm, then zumime's own signatures
(compression wrappers, tar, ISO 9660, RAR 5, 7z, fonts, WebAssembly)
where the standard found only binary bytes. `"image"`, `"audio_video"`
and `"font"` are the standard's context-specific algorithms: they look
only for types of that kind and otherwise return the supplied type.

A text result carries `charset`, from the first rule that answers: the
supplied type's `charset` parameter, a byte-order mark, an XML
declaration, an HTML `<meta>` prescan, valid UTF-8, then the C1 rule
(`windows-1252` when a byte in 0x80 to 0x9F appears, else `ISO-8859-1`),
which lowers `confidence` to `"probable"`.

## References

<https://mimesniff.spec.whatwg.org/>

## See also

[`mime_parse()`](https://pedrobtz.github.io/zumime/reference/mime_parse.md)
for the supplied type's grammar.

## Examples

``` r
png <- as.raw(c(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a))
mime_sniff(png)
#> <zumime_result: 1 row>
#>   path      type confidence charset inner encrypted complete newline
#> 1 <NA> image/png   definite    <NA>  <NA>        NA       NA    <NA>
#>   interpreter
#> 1        <NA>
mime_sniff(charToRaw("<!DOCTYPE html><title>x</title>"))
#> <zumime_result: 1 row>
#>   path      type confidence charset inner encrypted complete newline
#> 1 <NA> text/html   definite   UTF-8  <NA>        NA       NA    <NA>
#>   interpreter
#> 1        <NA>

# A server that says text/plain about a binary file
mime_sniff(png, type = "text/plain")
#> <zumime_result: 1 row>
#>   path                     type confidence charset inner encrypted complete
#> 1 <NA> application/octet-stream       none    <NA>  <NA>        NA       NA
#>   newline interpreter
#> 1    <NA>        <NA>

# The supplied type wins under nosniff
mime_sniff(png, type = "text/csv", no_sniff = TRUE)
#> <zumime_result: 1 row>
#>   path     type confidence      charset inner encrypted complete newline
#> 1 <NA> text/csv       none windows-1252  <NA>        NA       NA   mixed
#>   interpreter
#> 1        <NA>
```
