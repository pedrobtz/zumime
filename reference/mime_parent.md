# The lineage of a type

Every type has one parent, ending at `application/octet-stream`: text
types descend from `text/plain`, XML dialects from `application/xml`,
JSON dialects from `application/json`, ZIP-based formats from
`application/zip`.

## Usage

``` r
mime_parent(type)
```

## Arguments

- type:

  A character vector of types. Aliases, parameters and case are ignored.

## Value

A list with one character vector per type: its ancestors, nearest first,
empty for the root and `NA` for an unknown type.

## See also

[`mime_is()`](https://pedrobtz.github.io/zumime/reference/mime_is.md) to
test membership.

## Examples

``` r
mime_parent("image/svg+xml")
#> [[1]]
#> [1] "application/xml"          "text/plain"              
#> [3] "application/octet-stream"
#> 
mime_parent(c("application/x-sqlite3", "application/octet-stream"))
#> [[1]]
#> [1] "application/octet-stream"
#> 
#> [[2]]
#> character(0)
#> 
```
