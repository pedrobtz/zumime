test_that("an XML or HTML supplied type is returned as is", {
  r <- mime_sniff(png_bytes(), type = "text/html")
  expect_identical(r$type, "text/html")
  expect_identical(as.character(r$confidence), "none")
  expect_identical(
    mime_sniff(png_bytes(), type = "image/svg+xml")$type,
    "image/svg+xml"
  )
})

test_that("unknown supplied types are sniffed", {
  for (t in c("unknown/unknown", "application/unknown", "*/*", "garbage")) {
    expect_identical(
      mime_sniff(png_bytes(), type = t)$type,
      "image/png",
      info = t
    )
  }
})

test_that("no_sniff returns a supplied type and disables scriptable rows", {
  expect_identical(
    mime_sniff(png_bytes(), type = "text/csv", no_sniff = TRUE)$type,
    "text/csv"
  )
  html <- charToRaw("<html><body>hi</body></html>")
  expect_identical(mime_sniff(html)$type, "text/html")
  expect_identical(mime_sniff(html, no_sniff = TRUE)$type, "text/plain")
})

test_that("the Apache bug strings run the text-or-binary rule", {
  expect_identical(
    mime_sniff(png_bytes(), type = "text/plain")$type,
    "application/octet-stream"
  )
  expect_identical(
    mime_sniff(png_bytes(), type = "text/plain; charset=ISO-8859-1")$type,
    "application/octet-stream"
  )
  # Not one of the exact strings: the supplied type stands.
  expect_identical(
    mime_sniff(png_bytes(), type = "text/plain; charset=utf-8")$type,
    "text/plain"
  )
  bom <- as.raw(c(0xff, 0xfe, 0x68, 0x00))
  r <- mime_sniff(bom, type = "text/plain")
  expect_identical(r$type, "text/plain")
  expect_identical(as.character(r$confidence), "definite")
  expect_identical(r$charset, "UTF-16LE")
  r <- mime_sniff(
    c(as.raw(c(0xef, 0xbb, 0xbf)), charToRaw("x")),
    type = "text/plain"
  )
  expect_identical(r$type, "text/plain")
  expect_identical(as.character(r$confidence), "definite")
  expect_identical(r$charset, "UTF-8")
})

test_that("an image or media supplied type is checked against its tables", {
  expect_identical(
    mime_sniff(png_bytes(), type = "image/gif")$type,
    "image/png"
  )
  r <- mime_sniff(charToRaw("not an image"), type = "image/gif")
  expect_identical(r$type, "image/gif")
  expect_identical(as.character(r$confidence), "none")
  ogg <- c(charToRaw("OggS"), raw(30))
  expect_identical(mime_sniff(ogg, type = "video/mp4")$type, "application/ogg")
  expect_identical(mime_sniff(ogg, type = "image/png")$type, "image/png")
})

test_that("context algorithms look only for their kind", {
  expect_identical(mime_sniff(png_bytes(), context = "image")$type, "image/png")
  ttf <- as.raw(c(0, 1, 0, 0, 0, 0x17, 1, 0))
  expect_identical(
    mime_sniff(ttf, context = "image")$type,
    "application/octet-stream"
  )
  expect_identical(mime_sniff(ttf, context = "font")$type, "font/ttf")
  expect_identical(
    mime_sniff(raw(8), type = "font/woff", context = "font")$type,
    "font/woff"
  )
  expect_identical(
    mime_sniff(png_bytes(), type = "image/svg+xml", context = "image")$type,
    "image/svg+xml"
  )
  eot <- c(raw(34), charToRaw("LP"), raw(20))
  expect_identical(
    mime_sniff(eot, context = "font")$type,
    "application/vnd.ms-fontobject"
  )
  expect_identical(mime_sniff(eot)$type, "application/octet-stream")
  ogg <- c(charToRaw("OggS"), raw(30))
  expect_identical(
    mime_sniff(ogg, context = "audio_video")$type,
    "application/ogg"
  )
})

test_that("browsing uses the standard's tables only", {
  tar <- c(tar_header(), raw(1024))
  expect_identical(
    mime_sniff(tar, context = "browsing")$type,
    "application/octet-stream"
  )
  expect_identical(mime_sniff(tar)$type, "application/x-tar")
})

test_that("MP4 is found by a compatible brand within the ftyp box", {
  ftyp <- c(
    as.raw(c(0, 0, 0, 0x18)),
    charToRaw("ftypisom"),
    as.raw(c(0, 0, 2, 0)),
    charToRaw("isommp41"),
    raw(16)
  )
  expect_identical(mime_sniff(ftyp)$type, "video/mp4")
  # A box larger than the bytes in hand is not MP4 (the standard's rule),
  # nor is a box size that is not a multiple of four. In the "none" context
  # the ISO base media reader still reads the brands.
  big <- ftyp
  big[4] <- as.raw(0xf0)
  expect_identical(
    mime_sniff(big, context = "browsing")$type,
    "application/octet-stream"
  )
  expect_identical(mime_sniff(big)$type, "video/mp4")
  odd <- ftyp
  odd[4] <- as.raw(0x17)
  expect_identical(
    mime_sniff(odd, context = "browsing")$type,
    "application/octet-stream"
  )
})

test_that("WebM is found by its EBML DocType", {
  webm <- c(
    as.raw(c(
      0x1a,
      0x45,
      0xdf,
      0xa3,
      0x9f,
      0x42,
      0x86,
      0x81,
      0x01,
      0x42,
      0x82,
      0x84
    )),
    charToRaw("webm"),
    raw(20)
  )
  expect_identical(mime_sniff(webm)$type, "video/webm")
  mkv <- c(
    as.raw(c(0x1a, 0x45, 0xdf, 0xa3, 0x9f, 0x42, 0x82, 0x88)),
    charToRaw("matroska"),
    raw(20)
  )
  expect_identical(
    mime_sniff(mkv, context = "browsing")$type,
    "application/octet-stream"
  )
})

test_that("MP3 without ID3 needs two consecutive frame headers", {
  two <- c(mp3_frame(), raw(413), mp3_frame(), raw(8))
  expect_identical(mime_sniff(two)$type, "audio/mpeg")
  one <- c(mp3_frame(), raw(500))
  expect_identical(mime_sniff(one)$type, "application/octet-stream")
})

test_that("an MP3 frame header with a reserved field is refused", {
  # The second header has, in turn, sample-rate index 3, bitrate index 15
  # and layer bits 00. The frame-size code relies on these refusals.
  bad <- list(
    as.raw(c(0xff, 0xfb, 0x9c, 0x00)),
    as.raw(c(0xff, 0xfb, 0xf0, 0x00)),
    as.raw(c(0xff, 0xf9, 0x90, 0x00))
  )
  for (second in bad) {
    x <- c(mp3_frame(), raw(413), second, raw(8))
    expect_identical(mime_sniff(x)$type, "application/octet-stream")
  }
})

test_that("the floor is text/plain for text and octet-stream for binary", {
  r <- mime_sniff(raw())
  expect_identical(r$type, "text/plain")
  expect_identical(as.character(r$confidence), "probable")
  expect_identical(r$charset, "UTF-8")
  r <- mime_sniff(as.raw(1:3))
  expect_identical(r$type, "application/octet-stream")
  expect_identical(as.character(r$confidence), "none")
  expect_identical(r$charset, NA_character_)
})

test_that("only the first limit bytes are read", {
  bytes <- c(charToRaw("plain text "), png_bytes())
  expect_identical(mime_sniff(bytes, limit = 11)$type, "text/plain")
  expect_identical(mime_sniff(bytes)$type, "application/octet-stream")
  expect_identical(
    mime_sniff(bytes, limit = 0)$type,
    "application/octet-stream"
  )
})

test_that("mime_sniff() rejects malformed arguments", {
  expect_error(mime_sniff(1), class = "zumime_type_error")
  expect_error(mime_sniff(list(raw(1))), class = "zumime_type_error")
  expect_error(
    mime_sniff(png_bytes(), type = c("a/b", "c/d")),
    class = "zumime_type_error"
  )
  expect_error(mime_sniff(png_bytes(), type = 1), class = "zumime_type_error")
  expect_error(
    mime_sniff(png_bytes(), no_sniff = NA),
    class = "zumime_type_error"
  )
  expect_error(
    mime_sniff(png_bytes(), context = "audio"),
    class = "zumime_type_error"
  )
  for (lim in list(-1, 1.5, NA, "10", c(1, 2))) {
    expect_error(
      mime_sniff(png_bytes(), limit = lim),
      class = "zumime_type_error"
    )
  }
})

test_that("a missing supplied type sniffs as no type", {
  expect_identical(
    mime_sniff(charToRaw("hello"), type = NA),
    mime_sniff(charToRaw("hello"))
  )
  expect_identical(mime_is(NA, "text"), NA)
})

test_that("a lone carriage return at the end is not an ending", {
  expect_identical(mime_sniff(charToRaw("a\r"))$newline, NA_character_)
  expect_identical(mime_sniff(charToRaw("a\rb"))$newline, "cr")
})
