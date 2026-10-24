# Build information

Reports what this build of zumime contains: the package version and the
version of the generated type tables, which is the date of the upstream
sources they were built from.

## Usage

``` r
zumime_info()
```

## Value

A list with `version`, the package version as a string; `table_version`,
the date of the table sources as a string (`"YYYY-MM-DD"`); and
`family`, the optional family packages this session can offer text to
with `mime_type(text = "family")`.

## See also

[`mime_type()`](https://pedrobtz.github.io/zumime/reference/mime_type.md)
for the arguments that use the family.

## Examples

``` r
zumime_info()
#> $version
#> [1] "0.1.0"
#> 
#> $table_version
#> [1] "2026-10-19"
#> 
#> $family
#> [1] "zucsv"  "zujson"
#> 
```
