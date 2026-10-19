# Extensions of a type

Extensions of a type

## Usage

``` r
mime_extensions(type)
```

## Arguments

- type:

  A character vector of types. Aliases, parameters and case are ignored.

## Value

A list with one character vector per type, the canonical extension
first, without the dot. An unknown type gives `character(0)`.

## See also

[`mime_guess()`](https://pedrobtz.github.io/zumime/reference/mime_guess.md)
for the reverse.

## Examples

``` r
mime_extensions(c("image/jpeg", "application/x-sqlite3"))
#> [[1]]
#> [1] "jpg"  "jpeg" "jpe" 
#> 
#> [[2]]
#> [1] "sqlite"  "sqlite3"
#> 
```
