# Parse and serialise MIME types

`mime_parse()` is the WHATWG MIME Sniffing Standard's "parse a MIME
type": type and subtype are lower-cased HTTP tokens; parameters keep
their order, names are lower-cased, quoted values are unescaped, and a
repeated name keeps its first value. `mime_format()` is "serialize a
MIME type", quoting a value that is empty or not a token.

## Usage

``` r
mime_parse(x, strict = FALSE)

mime_format(record)
```

## Arguments

- x:

  A character vector of MIME types, such as `Content-Type` header
  values.

- strict:

  If `TRUE`, an input that fails to parse raises `zumime_parse_error`
  instead of giving `NULL`.

- record:

  One record from `mime_parse()`, or a list of them.

## Value

`mime_parse()` returns a list with one record per input: a list of
`type`, `subtype` and `parameters` (a named list of strings), or `NULL`
for input that fails to parse and for `NA`.

`mime_format()` returns a character vector, `NA` for a `NULL` record.

## Details

`mime_format()` checks a record before serialising it, so an edited
record cannot carry a line break into a header. Type, subtype and
parameter names must be non-empty HTTP tokens. Values must hold only
HTTP quoted-string token code points: tab, U+0020 to U+007E and U+0080
to U+00FF. A record that breaks this raises `zumime_type_error`.

## References

<https://mimesniff.spec.whatwg.org/#parsing-a-mime-type>

## See also

[`mime_sniff()`](https://pedrobtz.github.io/zumime/reference/mime_sniff.md),
which takes a supplied type in this grammar.

## Examples

``` r
rec <- mime_parse("Text/HTML; Charset=\"UTF-8\"; charset=latin1")
str(rec)
#> List of 1
#>  $ :List of 3
#>   ..$ type      : chr "text"
#>   ..$ subtype   : chr "html"
#>   ..$ parameters:List of 1
#>   .. ..$ charset: chr "UTF-8"
mime_format(rec)
#> [1] "text/html;charset=UTF-8"
mime_format(mime_parse("text/plain;name=\"a b\""))
#> [1] "text/plain;name=\"a b\""
mime_parse("not a type")
#> [[1]]
#> NULL
#> 
```
