# Build information

Reports what this build of zumime contains: the package version and the
version of the generated type tables, which is the date of the upstream
sources they were built from.

## Usage

``` r
zumime_info()
```

## Value

A list with `version`, the package version as a string, and
`table_version`, the date of the table sources as a string, or `NA`
before the tables exist.

## Examples

``` r
zumime_info()
#> $version
#> [1] "0.0.0.9000"
#> 
#> $table_version
#> [1] NA
#> 
```
