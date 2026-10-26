test_that("ftyp brands decide the ISO base media type", {
  expect_identical(
    sniff_type(build_ftyp("M4A ", c("M4A ", "mp42", "isom"))),
    "audio/mp4"
  )
  expect_identical(sniff_type(build_ftyp("M4V ", c("mp42"))), "video/x-m4v")
  expect_identical(sniff_type(build_ftyp("qt  ")), "video/quicktime")
  expect_identical(sniff_type(build_ftyp("3gp5", c("isom"))), "video/3gpp")
  expect_identical(sniff_type(build_ftyp("3g2a")), "video/3gpp2")
  expect_identical(
    sniff_type(build_ftyp("heic", c("mif1", "heic"))),
    "image/heic"
  )
  expect_identical(sniff_type(build_ftyp("mif1", c("heic"))), "image/heif")
  expect_identical(
    sniff_type(build_ftyp("avif", c("mif1", "avif"))),
    "image/avif"
  )
  expect_identical(
    sniff_type(build_ftyp("crx ", c("isom"))),
    "image/x-canon-cr3"
  )
  expect_identical(
    sniff_type(build_ftyp("isom", c("isom", "avc1"))),
    "video/mp4"
  )
  # A generic major brand defers to a specific compatible brand.
  expect_identical(sniff_type(build_ftyp("isom", c("M4A "))), "audio/mp4")
})

test_that("a brand never moves a file away from what the standard said", {
  # The standard says MP4 from the mp42 brand; QuickTime is not an MP4.
  expect_identical(sniff_type(build_ftyp("qt  ", c("mp42"))), "video/mp4")
  r <- mime_sniff(build_ftyp("M4A ", c("mp42")))
  expect_identical(r$type, "audio/mp4")
  expect_true(mime_is(r$type, "video/mp4"))
})

test_that("a QuickTime movie may start with another atom", {
  mov <- c(u32be(16), charToRaw("moov"), raw(8))
  expect_identical(sniff_type(mov), "video/quicktime")
})

test_that("the EBML DocType decides WebM against Matroska", {
  expect_identical(sniff_type(build_ebml("matroska")), "video/x-matroska")
  expect_identical(sniff_type(build_ebml("webm")), "video/webm")
  # Past the 38 bytes the standard's WebM signature reads.
  late <- build_ebml("webm", pad = 30)
  expect_identical(
    sniff_type(late, context = "browsing"),
    "application/octet-stream"
  )
  expect_identical(sniff_type(late), "video/webm")
})

test_that("the first Ogg packet decides the codec", {
  expect_identical(
    sniff_type(build_ogg(c(as.raw(1), charToRaw("vorbis")))),
    "audio/ogg"
  )
  expect_identical(sniff_type(build_ogg("OpusHead")), "audio/opus")
  expect_identical(
    sniff_type(build_ogg(c(as.raw(0x7f), charToRaw("FLAC")))),
    "audio/ogg"
  )
  expect_identical(sniff_type(build_ogg("Speex   ")), "audio/ogg")
  expect_identical(
    sniff_type(build_ogg(c(as.raw(0x80), charToRaw("theora")))),
    "video/ogg"
  )
  expect_identical(sniff_type(build_ogg("unknown codec")), "application/ogg")
  skeleton <- c(
    build_ogg(c(charToRaw("fishead"), as.raw(0))),
    build_ogg("OpusHead")
  )
  expect_identical(sniff_type(skeleton), "audio/opus")
})

test_that("PNG and JPEG refine to APNG and JPEG-LS", {
  ihdr <- c(u32be(13), charToRaw("IHDR"), raw(13), raw(4))
  actl <- c(u32be(8), charToRaw("acTL"), raw(8), raw(4))
  idat <- c(u32be(1), charToRaw("IDAT"), raw(1), raw(4))
  sig <- png_bytes()[1:8]
  expect_identical(sniff_type(c(sig, ihdr, actl, idat)), "image/apng")
  expect_identical(sniff_type(c(sig, ihdr, idat, actl)), "image/png")
  expect_identical(
    sniff_type(as.raw(c(0xff, 0xd8, 0xff, 0xf7, 0, 0))),
    "image/jls"
  )
  expect_identical(
    sniff_type(as.raw(c(0xff, 0xd8, 0xff, 0xe0, 0, 0))),
    "image/jpeg"
  )
})

test_that("MPEG-2 Layer III frames are 72 * bitrate / rate long", {
  # MPEG-2, Layer III, 64 kbit/s, 22.05 kHz: 72 * 64000 / 22050 = 208.
  frame <- as.raw(c(0xff, 0xf3, 0x80, 0x00))
  two <- c(frame, raw(204), frame, raw(8))
  expect_identical(sniff_type(two), "audio/mpeg")
})

test_that("MPEG-2.5 Layer III frames run at a quarter of MPEG-1's rate", {
  # MPEG-2.5, Layer III, 64 kbit/s, 11.025 kHz: 72 * 64000 / 11025 = 417.
  frame <- as.raw(c(0xff, 0xe3, 0x80, 0x00))
  expect_identical(
    sniff_type(c(frame, raw(413), frame, raw(8))),
    "audio/mpeg"
  )
  # At 44.1 kHz the frame would be 104 bytes long; it is not.
  expect_identical(
    sniff_type(c(frame, raw(100), frame, raw(8))),
    "application/octet-stream"
  )
})

test_that("rarer ftyp brands decide the ISO base media type", {
  expect_identical(
    sniff_type(build_ftyp("hevc", c("mif1", "hevc"))),
    "image/heic-sequence"
  )
  # A generic brand the standard does not see as MP4 still makes one.
  for (brand in c("mp71", "avc1", "dash", "f4v ", "F4V ", "MSNV", "NDAS")) {
    expect_identical(sniff_type(build_ftyp(brand)), "video/mp4", info = brand)
  }
  # A brand neither specific nor generic decides nothing.
  expect_identical(sniff_type(build_ftyp("abcd")), "application/octet-stream")
  expect_identical(sniff_type(build_ftyp("mp4x")), "video/mp4")
})

test_that("the Ogg reader looks at four pages at most", {
  pages <- function(n) unlist(lapply(seq_len(n), \(i) build_ogg("unknown")))
  expect_identical(sniff_type(c(pages(3), build_ogg("OpusHead"))), "audio/opus")
  expect_identical(
    sniff_type(c(pages(4), build_ogg("OpusHead"))),
    "application/ogg"
  )
})

test_that("the WebM signature reads a DocType size longer than a byte", {
  ebml <- function(size) {
    body <- c(as.raw(c(0x42, 0x82)), size, charToRaw("webm"))
    c(as.raw(c(0x1a, 0x45, 0xdf, 0xa3)), as.raw(0x80 + length(body)), body)
  }
  for (size in list(as.raw(c(0x40, 0x04)), as.raw(c(0x10, 0, 0, 0x04)))) {
    x <- c(ebml(size), raw(16))
    expect_identical(sniff_type(x, context = "browsing"), "video/webm")
  }
})
