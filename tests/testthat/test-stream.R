test_that("a signature decides as soon as it is whole", {
  s <- mime_sniffer()
  expect_null(mime_push(s, charToRaw("%PD")))
  r <- mime_push(s, charToRaw("F-1.7"))
  expect_identical(r$type, "application/pdf")
  # Further pushes are ignored.
  expect_identical(mime_push(s, png_bytes())$type, "application/pdf")
  expect_identical(mime_finish(s)$type, "application/pdf")
})

test_that("text decides only at the limit or the finish", {
  s <- mime_sniffer(limit = 16)
  expect_null(mime_push(s, charToRaw("hello ")))
  expect_identical(mime_push(s, charToRaw("world, how are"))$type, "text/plain")
  t <- mime_sniffer()
  expect_null(mime_push(t, charToRaw("{\"a\": 1}")))
  r <- mime_finish(t)
  expect_identical(r$type, "application/json")
  expect_identical(r$complete, NA)
})

test_that("a finished sniffer refuses pushes", {
  s <- mime_sniffer()
  mime_push(s, charToRaw("abc"))
  first <- mime_finish(s)
  expect_identical(mime_finish(s), first)
  expect_error(mime_push(s, raw(1)), class = "zumime_state_error")
  expect_error(mime_push(s, raw(1)), class = "zumime_error")
})

test_that("the supplied type, no-sniff flag and context apply", {
  s <- mime_sniffer(type = "text/plain; charset=Shift_JIS", limit = 8)
  r <- mime_push(s, charToRaw("hi there, all"))
  expect_identical(r$type, "text/plain")
  expect_identical(r$charset, "Shift_JIS")
  n <- mime_sniffer(type = "image/png", no_sniff = TRUE)
  expect_identical(mime_push(n, charToRaw("GIF89a"))$type, "image/png")
  # The font table's first row reads 36 bytes, so a short font waits.
  f <- mime_sniffer(context = "font")
  expect_null(mime_push(f, charToRaw("wOF2xxxx")))
  expect_identical(mime_push(f, raw(30))$type, "font/woff2")
})

test_that("limit = 0 reads without bound until the finish", {
  s <- mime_sniffer(limit = 0)
  for (i in 1:20) expect_null(mime_push(s, charToRaw(strrep("ab ", 300))))
  expect_output(print(s), "18000 of unlimited bytes, undecided")
  expect_identical(mime_finish(s)$type, "text/plain")
})

test_that("a saved sniffer comes back undecided with its bytes", {
  s <- mime_sniffer()
  mime_push(s, charToRaw("GIF89a"))
  f <- withr::local_tempfile(fileext = ".rds")
  saveRDS(s, f)
  back <- readRDS(f)
  expect_output(print(back), "6 of 4096 bytes, undecided")
  expect_identical(mime_push(back, raw(0))$type, "image/gif")
})

test_that("each input decides at the whole's type, never past the limit", {
  for (name in names(stream_inputs())) {
    x <- stream_inputs()[[name]]
    got <- .Call(zumime_stream_bytewise, x, 4096)
    expect_identical(got[[2]], mime_sniff(x, limit = 4096)$type, info = name)
    expect_lte(got[[1]], 4096)
  }
  # Through the R API too, one byte at a time.
  for (name in c("pdf", "gif", "text", "html")) {
    x <- stream_inputs()[[name]]
    s <- mime_sniffer()
    r <- NULL
    for (b in as.list(x)) {
      r <- mime_push(s, b)
      if (!is.null(r)) break
    }
    if (is.null(r)) r <- mime_finish(s)
    expect_identical(r$type, mime_sniff(x)$type, info = name)
  }
})

test_that("early decisions happen where the bytes allow them", {
  n <- function(x) .Call(zumime_stream_bytewise, x, 4096)[[1]]
  expect_identical(n(stream_inputs()$pdf), 5)
  expect_identical(n(stream_inputs()$gif), 6)
  # "MZ" waits until the tar row at 257 can no longer match.
  expect_identical(n(c(charToRaw("MZ"), raw(400))), 258)
  expect_identical(n(stream_inputs()$text), as.numeric(length(stream_inputs()$text)))
})

test_that("every fixture decides at the whole's type", {
  skip_if_gctorture()
  dir <- fixture_dir("file-type")
  for (f in list.files(dir, full.names = TRUE)) {
    x <- readBin(f, "raw", min(file.size(f), 8192))
    want <- mime_sniff(x, limit = 4096)$type
    got <- .Call(zumime_stream_bytewise, x, 4096)
    expect_identical(got[[2]], want, info = basename(f))
    # Through mime_push() in 512-byte chunks, which may skip work once
    # nothing can decide before the limit.
    s <- mime_sniffer()
    r <- NULL
    for (k in seq(1, length(x), by = 512)) {
      r <- mime_push(s, x[k:min(k + 511, length(x))])
      if (!is.null(r)) break
    }
    if (is.null(r)) r <- mime_finish(s)
    expect_identical(r$type, want, info = paste("chunks:", basename(f)))
  }
})

test_that("mime_push() and mime_sniffer() reject malformed arguments", {
  expect_error(mime_push("not a sniffer", raw(1)), class = "zumime_type_error")
  expect_error(mime_push(mime_sniffer(), "text"), class = "zumime_type_error")
  expect_error(mime_sniffer(limit = -1), class = "zumime_type_error")
  expect_error(mime_finish(list()), class = "zumime_type_error")
})

test_that("the byte count is kept as a double", {
  # The count of an unlimited sniffer must not wrap at INT_MAX; pushing 2 GB
  # is too slow for a test, so the storage type is checked instead.
  s <- mime_sniffer(limit = 0)
  mime_push(s, raw(10))
  st <- .Call(zumime_stream_state, s)
  expect_type(st, "double")
  expect_identical(st[2], 10)
})
