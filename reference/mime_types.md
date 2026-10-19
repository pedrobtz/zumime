# The type registry

Every type zumime knows, with its parent, aliases, extensions and the
kind of evidence that detects it.

## Usage

``` r
mime_types()
```

## Value

A data frame with one row per canonical type and columns `type`,
`parent` (`NA` for the root, `application/octet-stream`), `aliases` and
`extensions` (list columns of character vectors, the canonical extension
first), `category` (the top-level type) and `detected_by`
(`"signature"`, `"container"`, `"text"`, `"extension"` or
`"registered"`).

## See also

[`mime_parent()`](https://pedrobtz.github.io/zumime/reference/mime_parent.md)
for one type's lineage.

## Examples

``` r
types <- mime_types()
nrow(types)
#> [1] 2613
types[types$type == "application/zip", ]
#>                 type                   parent
#> 1978 application/zip application/octet-stream
#>                                              aliases extensions    category
#> 1978 application/x-zip, application/x-zip-compressed        zip application
#>      detected_by
#> 1978   signature
```
