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

test_that("a decided sniffer ignores further chunks", {
  s <- mime_sniffer()
  first <- mime_push(s, charToRaw("GIF89a"))
  expect_identical(mime_push(s, charToRaw("more bytes")), first)
  expect_output(print(s), "6 of 4096 bytes, decided")
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
  for (i in 1:20) {
    expect_null(mime_push(s, charToRaw(strrep("ab ", 300))))
  }
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
    # Inputs longer than 4096 bytes are read whole.
    limit <- max(4096, length(x))
    got <- stream_bytewise(x, limit)
    expect_identical(got[[2]], mime_sniff(x, limit = limit)$type, info = name)
    expect_lte(got[[1]], limit)
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
    if (is.null(r)) {
      r <- mime_finish(s)
    }
    expect_identical(r$type, mime_sniff(x)$type, info = name)
  }
})

test_that("each input decides at the whole's type through mime_push() chunks", {
  # 512-byte chunks carry the padded inputs past the resource header, where
  # text and the readers that wait for the limit stop sniffing.
  for (name in names(stream_inputs())) {
    x <- stream_inputs()[[name]]
    limit <- max(4096, length(x))
    s <- mime_sniffer(limit = limit)
    r <- NULL
    for (k in seq(1, length(x), by = 512)) {
      r <- mime_push(s, x[k:min(k + 511, length(x))])
      if (!is.null(r)) break
    }
    # A stream as long as the limit decides on the push that reaches it.
    if (length(x) >= limit) {
      expect_false(is.null(r), info = name)
    }
    if (is.null(r)) {
      r <- mime_finish(s)
    }
    expect_identical(r$type, mime_sniff(x, limit = limit)$type, info = name)
  }
})

test_that("a PNG decides at its first IDAT past the resource header", {
  x <- png_late_bytes()
  expect_identical(stream_bytewise(x)[[1]], 2553)
  s <- mime_sniffer()
  for (k in 1:4) {
    expect_null(mime_push(s, x[(512 * k - 511):(512 * k)]))
  }
  # The fifth chunk brings the IDAT's chunk header, long before the limit.
  expect_identical(mime_push(s, x[2049:2560])$type, "image/png")
  expect_identical(.Call(zumime_stream_state, s)[2], 2560)
})

test_that("readers that wait for the limit decide at the limit", {
  inputs <- stream_inputs()
  for (name in c("zip_padded", "ole_padded", "mkv_padded", "gzip_padded")) {
    x <- inputs[[name]]
    s <- mime_sniffer(limit = 2000)
    # Three chunks pass the resource header without deciding.
    for (k in 1:3) {
      expect_null(mime_push(s, x[(512 * k - 511):(512 * k)]), info = name)
    }
    r <- mime_push(s, x[1537:2048])
    expect_identical(r$type, mime_sniff(x, limit = 2000)$type, info = name)
    expect_identical(.Call(zumime_stream_state, s)[2], 2000, info = name)
  }
})

test_that("a stream waits for the bytes of a registered data rule", {
  withr::defer(try(mime_unregister("image/x-zt-streamgif"), silent = TRUE))
  mime_register(
    "image/x-zt-streamgif",
    "image/gif",
    rule = list(offset = 20, bytes = "ZT")
  )
  gif <- c(charToRaw("GIF89a"), raw(14), charToRaw("ZT"), raw(10))
  s <- mime_sniffer()
  expect_null(mime_push(s, gif[1:6]))
  expect_null(mime_push(s, gif[7:21]))
  r <- mime_push(s, gif[22])
  expect_identical(r$type, "image/x-zt-streamgif")
  expect_identical(r$type, mime_sniff(gif)$type)
  expect_identical(stream_bytewise(gif)[[1]], 22)
  # A GIF without the rule's bytes waits as long, then stays image/gif.
  plain <- c(charToRaw("GIF89a"), raw(26))
  expect_identical(stream_bytewise(plain), list(22, "image/gif", TRUE))
})

test_that("each input decides at the whole's type in every context", {
  skip_if_gctorture()
  for (context in c("browsing", "image", "audio_video", "font")) {
    for (name in names(stream_inputs())) {
      x <- stream_inputs()[[name]]
      limit <- max(4096, length(x))
      got <- stream_bytewise(x, limit, context = context)
      want <- mime_sniff(x, context = context, limit = limit)$type
      expect_identical(got[[2]], want, info = paste(context, name))
    }
  }
})

test_that("each input decides at the whole's type under a supplied type", {
  skip_if_gctorture()
  supplied <- list(
    list(type = "image/gif", no_sniff = FALSE),
    list(type = "video/mp4", no_sniff = FALSE),
    list(type = "text/plain", no_sniff = FALSE),
    list(type = "text/plain; charset=UTF-8", no_sniff = FALSE),
    list(type = "text/html", no_sniff = FALSE),
    list(type = "application/pdf", no_sniff = FALSE),
    list(type = "text/csv", no_sniff = TRUE),
    list(type = "text/x-zt-unknown", no_sniff = FALSE)
  )
  for (s in supplied) {
    for (name in names(stream_inputs())) {
      x <- stream_inputs()[[name]]
      limit <- max(4096, length(x))
      got <- stream_bytewise(x, limit, type = s$type, no_sniff = s$no_sniff)
      want <- mime_sniff(
        x,
        type = s$type,
        no_sniff = s$no_sniff,
        limit = limit
      )$type
      expect_identical(got[[2]], want, info = paste(s$type, name))
    }
  }
})

test_that("contexts and supplied types decide where the bytes allow", {
  n <- function(x, ...) stream_bytewise(x, ...)[[1]]
  png <- stream_inputs()$png
  expect_identical(n(png, context = "image"), 8)
  ogg <- build_ogg("OpusHead")
  expect_lt(n(ogg, context = "audio_video"), length(ogg))
  gif <- stream_inputs()$gif
  # A supplied image type is checked against the image table.
  expect_identical(stream_bytewise(png, type = "image/gif")[[2]], "image/png")
  # The Apache-bug rule reads a BOM's three bytes before deciding.
  bom <- c(as.raw(c(0xef, 0xbb, 0xbf)), charToRaw("x"))
  expect_gte(n(bom, type = "text/plain"), 3)
  expect_identical(n(gif, type = "image/png", no_sniff = TRUE), 1)
})

test_that("early decisions happen where the bytes allow them", {
  n <- function(x) stream_bytewise(x)[[1]]
  expect_identical(n(stream_inputs()$pdf), 5)
  expect_identical(n(stream_inputs()$gif), 6)
  expect_identical(n(stream_inputs()$jpeg), 4)
  # "MZ" waits until the tar row at 257 can no longer match.
  expect_identical(n(c(charToRaw("MZ"), raw(400))), 258)
  # Binary after "<html": the tag-terminated row no longer matches at the
  # "x", so only the HDF5 row at 2048 keeps the answer open.
  expect_identical(n(stream_inputs()$htmlx), 2049)
  expect_identical(
    n(stream_inputs()$text),
    as.numeric(length(stream_inputs()$text))
  )
})

test_that("every fixture decides at the whole's type", {
  skip_if_gctorture()
  dir <- fixture_dir("file-type")
  for (f in list.files(dir, full.names = TRUE)) {
    x <- readBin(f, "raw", min(file.size(f), 8192))
    want <- mime_sniff(x, limit = 4096)$type
    got <- stream_bytewise(x)
    expect_identical(got[[2]], want, info = basename(f))
    expect_lte(got[[1]], 4096, label = basename(f))
    # Through mime_push() in 512-byte chunks, which may skip work once
    # nothing can decide before the limit.
    s <- mime_sniffer()
    r <- NULL
    for (k in seq(1, length(x), by = 512)) {
      r <- mime_push(s, x[k:min(k + 511, length(x))])
      if (!is.null(r)) break
    }
    if (is.null(r)) {
      r <- mime_finish(s)
    }
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

test_that("a sniffer's buffer grows by need up to its limit", {
  size <- function(s) length(.Call(zumime_stream_buffer, s))
  s <- mime_sniffer(limit = 1e9)
  expect_lte(size(s), 4096)
  t <- mime_sniffer(limit = 10000)
  mime_push(t, charToRaw(strrep("words ", 1000)))
  expect_gte(size(t), 6000)
  mime_push(t, charToRaw(strrep("words ", 1000)))
  expect_identical(size(t), 10000L)
  expect_output(print(t), "10000 of 10000 bytes")
})

test_that("a sniffer stripped of its parameters is a type error", {
  s <- mime_sniffer()
  attr(s, "params") <- NULL
  expect_error(mime_push(s, raw(1)), class = "zumime_type_error")
  expect_error(mime_finish(s), class = "zumime_type_error")
  fake <- structure(list(), class = "zumime_sniffer")
  expect_error(mime_push(fake, raw(1)), class = "zumime_type_error")
  # An external pointer not made by mime_sniffer(), with a real one's
  # attributes copied over.
  forged <- zumime_stream_new$address
  attributes(forged) <- attributes(mime_sniffer())
  expect_error(mime_push(forged, raw(1)), class = "zumime_type_error")
  expect_error(mime_finish(forged), class = "zumime_type_error")
})
