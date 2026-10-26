# Register a type for the session

Adds a type under a parent in the hierarchy, so that
[`mime_sniff()`](https://pedrobtz.github.io/zumime/reference/mime_sniff.md),
[`mime_type()`](https://pedrobtz.github.io/zumime/reference/mime_type.md),
[`mime_check()`](https://pedrobtz.github.io/zumime/reference/mime_check.md)
and the registry functions know it until the session ends or
`mime_unregister()` removes it. A package that wants its format
recognised registers it in its `.onLoad()`. It unregisters it in its
`.onUnload()`, since registering a type that exists is an error.

## Usage

``` r
mime_register(type, parent, extensions = NULL, rule = NULL)

mime_unregister(type)
```

## Arguments

- type:

  The new type, such as `"application/x-myformat"`.

- parent:

  An existing type the new one descends from.

- extensions:

  File extensions for
  [`mime_guess()`](https://pedrobtz.github.io/zumime/reference/mime_guess.md),
  without the dot, or `NULL`.

- rule:

  `NULL` for a type known by name only; a list of `offset` (a whole
  number), `bytes` (a raw vector or a string, at most 64 bytes) and an
  optional `mask` (a raw vector as long as `bytes`); or a function of
  one raw vector, the bytes read.

## Value

`mime_register()` returns the type, invisibly. `mime_unregister()`
returns `NULL`, invisibly.

## Details

A data rule, `list(offset, bytes, mask)`, runs in C whenever the bytes
have been typed as the parent. It costs what a built-in signature costs.
It is reported at `"definite"`. It sees only the bytes read: a rule that
ends past 4096 bytes needs a larger `limit`. A function rule is called
from R with the bytes read and must return `TRUE` or `FALSE`. It runs
last, only when the parent matched, and is reported at `"probable"`. A
function rule that raises an error counts as `FALSE`, and the call warns
once with a `zumime_rule_warning` naming the type. A data rule cannot
sit under a type that a function rule decides, since data rules run
first.

Both kinds refine only what zumime sniffs in the `"none"` context. They
never run in another context, nor on a supplied type that stands.

## See also

[`mime_types()`](https://pedrobtz.github.io/zumime/reference/mime_types.md),
where registered types show `detected_by = "registered"`.

## Examples

``` r
mime_register(
  "application/x-zumime-demo",
  "application/octet-stream",
  extensions = "zdemo",
  rule = list(offset = 0, bytes = "ZDEMO")
)
mime_sniff(charToRaw("ZDEMO\x01\x02"))
#> <zumime_result: 1 row>
#>   path                      type confidence charset inner encrypted complete
#> 1 <NA> application/x-zumime-demo   definite    <NA>  <NA>        NA       NA
#>   newline interpreter
#> 1    <NA>        <NA>
mime_guess("file.zdemo")
#> [1] "application/x-zumime-demo"
mime_unregister("application/x-zumime-demo")
```
