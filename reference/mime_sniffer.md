# Sniff a stream chunk by chunk

`mime_sniffer()` starts an incremental sniffer; `mime_push()` hands it
the next chunk and returns `NULL` while the bytes seen cannot yet decide
the type, or the result row once they can. `mime_finish()` forces an
answer from what has been seen, as the end of a short stream would. The
answer is the one
[`mime_sniff()`](https://pedrobtz.github.io/zumime/reference/mime_sniff.md)
gives for the same first `limit` bytes.

## Usage

``` r
mime_sniffer(
  type = NULL,
  no_sniff = FALSE,
  context = c("none", "browsing", "image", "audio_video", "font"),
  limit = 4096L
)

mime_push(s, chunk)

mime_finish(s)
```

## Arguments

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

- s:

  A sniffer from `mime_sniffer()`.

- chunk:

  A raw vector, the next bytes of the stream.

## Value

`mime_sniffer()` returns a `zumime_sniffer`. `mime_push()` returns
`NULL` or a one-row `zumime_result`; `mime_finish()` always returns the
result.

## Details

Once the sniffer has decided, further pushes ignore their chunks and
return the same row. Once it has finished, a push raises a
`zumime_state_error`; `mime_finish()` can still be called and returns
the same row.

The bytes decide when no longer signature could still override the
match, the container reader for the type has what it needs, or `limit`
bytes have arrived. Text decides only at `limit` or at the finish, since
a later byte can still change it. The tail-reading columns (`complete`)
are `NA` for a stream.

The sniffer keeps its bytes in an R raw vector. A sniffer saved and
loaded again keeps those bytes but forgets its decision, and is
undecided until the next push.

## See also

[`mime_sniff()`](https://pedrobtz.github.io/zumime/reference/mime_sniff.md)
for bytes in hand.

## Examples

``` r
s <- mime_sniffer()
mime_push(s, charToRaw("GIF8"))
#> NULL
mime_push(s, charToRaw("9a"))
#> <zumime_result: 1 row>
#>   path      type confidence charset inner encrypted complete newline
#> 1 <NA> image/gif   definite    <NA>  <NA>        NA       NA    <NA>
#>   interpreter
#> 1        <NA>

# Text waits for the limit or the finish.
t <- mime_sniffer(limit = 64)
mime_push(t, charToRaw("hello, "))
#> NULL
mime_finish(t)
#> <zumime_result: 1 row>
#>   path       type confidence charset inner encrypted complete newline
#> 1 <NA> text/plain   probable   UTF-8  <NA>        NA       NA    <NA>
#>   interpreter
#> 1        <NA>
```
