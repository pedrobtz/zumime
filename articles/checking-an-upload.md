# Checking an upload before you open it

A service that accepts files has to decide what to do with each one
before any parser sees it. The name is the uploader’s claim; the bytes
are the evidence. This article walks through the decisions zumime
supports, in the order a service makes them: is the file a type we
accept, does its name agree with its bytes, can we open it at all, and,
for a stream, how soon do we know.

``` r

library(zumime)
```

## A folder of uploads

Four uploads: a report, a “photo” that is really a PDF, a PDF someone
encrypted, and one that was cut off in transit.

``` r

uploads <- tempfile("uploads")
dir.create(uploads)
pdf <- function(extra = "", eof = TRUE) {
  paste0("%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\n",
    "trailer << /Root 1 0 R", extra, " >>\n", if (eof) "%%EOF\n")
}
writeLines(pdf(), file.path(uploads, "report.pdf"))
writeLines(pdf(), file.path(uploads, "photo.jpg"))
writeLines(pdf(" /Encrypt 2 0 R"), file.path(uploads, "locked.pdf"))
writeLines(pdf(eof = FALSE), file.path(uploads, "partial.pdf"))
paths <- list.files(uploads, full.names = TRUE)
basename(paths)
#> [1] "locked.pdf"  "partial.pdf" "photo.jpg"   "report.pdf"
```

## Is it a type we accept?

[`mime_check()`](https://pedrobtz.github.io/zumime/reference/mime_check.md)
answers the allowlist question with one logical per file. It reads only
the bytes: a name is never evidence, since the question exists because
names lie. Here the service accepts PDFs and images.

``` r

ok <- mime_check(paths, c("application/pdf", "image"))
setNames(ok, basename(paths))
#>  locked.pdf partial.pdf   photo.jpg  report.pdf 
#>        TRUE        TRUE        TRUE        TRUE
```

Every file passes, because every file is a PDF. An allowlist entry can
be a type, an alias or a top-level type such as `"image"`, and a type’s
descendants count, so `"application/zip"` accepts Word and Excel
documents.

`min_confidence` says which evidence counts. The default, `"probable"`,
accepts structured text found by its grammar (JSON, SVG, a CSV through
the family’s sniffers) as well as signatures; `"definite"` accepts
signatures and container contents only.

``` r

json <- file.path(uploads, "data.json")
writeLines('{"rows": [1, 2, 3]}', json)
mime_check(json, "application/json")
#> [1] TRUE
mime_check(json, "application/json", min_confidence = "definite")
#> [1] FALSE
```

[`mime_check()`](https://pedrobtz.github.io/zumime/reference/mime_check.md)
is always equal to asking
[`mime_type()`](https://pedrobtz.github.io/zumime/reference/mime_type.md)
and testing its answer, but it skips the work that cannot change the
verdict. When a file is refused,
[`mime_type()`](https://pedrobtz.github.io/zumime/reference/mime_type.md)
says why.

## Does the name agree with the bytes?

[`mime_type()`](https://pedrobtz.github.io/zumime/reference/mime_type.md)
answers from both signals. `agree` is `FALSE` where they contradict each
other, as for the PDF named `.jpg`:

``` r

files <- mime_type(paths)
files$path <- basename(files$path)
files[c("path", "type", "by_name", "agree")]
#> <zumime_result: 4 rows>
#>          path            type         by_name agree
#> 1  locked.pdf application/pdf application/pdf  TRUE
#> 2 partial.pdf application/pdf application/pdf  TRUE
#> 3   photo.jpg application/pdf      image/jpeg FALSE
#> 4  report.pdf application/pdf application/pdf  TRUE
```

A disagreement is a finding, not an error: a service might rename the
file, store it under the type its bytes give, or refuse it.

## Can we open it?

Two columns answer whether a parser should be started at all.
`complete = TRUE` reads the end of each file as well as its start: a PDF
needs `%%EOF` in its last kilobyte, a ZIP its end-of-central-directory
record, a gzip stream its trailer. With the end read, a PDF’s trailer
also says whether it is encrypted.

``` r

files <- mime_type(paths, complete = TRUE)
files$path <- basename(files$path)
files[c("path", "type", "encrypted", "complete")]
#> <zumime_result: 4 rows>
#>          path            type encrypted complete
#> 1  locked.pdf application/pdf      TRUE     TRUE
#> 2 partial.pdf application/pdf     FALSE    FALSE
#> 3   photo.jpg application/pdf     FALSE     TRUE
#> 4  report.pdf application/pdf     FALSE     TRUE
```

`encrypted` is also read without `complete` for formats that say so near
the start: ZIP entries with the encryption flag or an AES extra field,
and OLE2 files (legacy Office, and encrypted modern Office) with an
`EncryptionInfo` stream.

A compressed file has another question: what is inside? `inner` answers
it from the rest of the name by default, or, with `inner = "decompress"`
and the zukomp package installed, from the decompressed bytes.

``` r

gz <- file.path(uploads, "export.csv.gz")
con <- gzfile(gz, "w")
writeLines(c("id,value", "1,2"), con)
close(con)
mime_type(gz)[c("type", "inner")]
#> <zumime_result: 1 row>
#>               type    inner
#> 1 application/gzip text/csv
```

## How soon do we know, on a stream?

A service reading an upload from a socket can decide before the whole
file has arrived.
[`mime_sniffer()`](https://pedrobtz.github.io/zumime/reference/mime_sniffer.md)
takes chunks as they come and answers as soon as the bytes decide the
type. Here the “socket” is a file connection read 16 bytes at a time:

``` r

s <- mime_sniffer()
con <- file(file.path(uploads, "report.pdf"), "rb")
seen <- 0
repeat {
  chunk <- readBin(con, "raw", 16)
  seen <- seen + length(chunk)
  result <- mime_push(s, chunk)
  if (!is.null(result) || length(chunk) == 0) break
}
close(con)
seen
#> [1] 16
result$type
#> [1] "application/pdf"
```

A PDF is decided in its first chunk, because no other signature could
still match those bytes. Text is decided only at the sniffer’s `limit`
or at
[`mime_finish()`](https://pedrobtz.github.io/zumime/reference/mime_sniffer.md),
since a later byte can still change it; the answer is always the one
[`mime_sniff()`](https://pedrobtz.github.io/zumime/reference/mime_sniff.md)
gives for the same first `limit` bytes.
