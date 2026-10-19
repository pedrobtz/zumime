# Is a type one of these?

`TRUE` when a type equals one of `what`, descends from it, or has it as
its top-level type (`"image"`). Aliases, parameters and case are ignored
on both sides. An unknown type descends from `application/octet-stream`
only.

## Usage

``` r
mime_is(x, what)
```

## Arguments

- x:

  A character vector of types.

- what:

  A character vector of types, aliases or top-level types.

## Value

A logical vector the length of `x`, `NA` where `x` is `NA`.

## See also

[`mime_parent()`](https://pedrobtz.github.io/zumime/reference/mime_parent.md)
for the lineage.

## Examples

``` r
mime_is("application/x-sqlite3", "application/vnd.sqlite3")
#> [1] TRUE
mime_is(c("image/png", "text/csv"), "image")
#> [1]  TRUE FALSE
mime_is("image/svg+xml", "application/xml")
#> [1] TRUE
```
