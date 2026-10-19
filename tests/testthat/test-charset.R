cs <- function(...) mime_sniff(...)$charset

test_that("the supplied charset parameter comes first", {
  expect_identical(cs(charToRaw("hi"), type = "text/plain; charset=Shift_JIS"),
    "Shift_JIS")
  expect_identical(cs(charToRaw("hi"), type = "text/plain; charset=UTF-8"),
    "UTF-8")
  # Not for a binary result.
  expect_identical(cs(png_bytes(), type = "text/plain; charset=UTF-8"),
    NA_character_)
})

test_that("a byte-order mark decides", {
  expect_identical(cs(as.raw(c(0xef, 0xbb, 0xbf, 0x68, 0x69))), "UTF-8")
  expect_identical(cs(as.raw(c(0xff, 0xfe, 0x68, 0x00))), "UTF-16LE")
  expect_identical(cs(as.raw(c(0xfe, 0xff, 0x00, 0x68))), "UTF-16BE")
})

test_that("an XML declaration names the encoding", {
  xml <- charToRaw("<?xml version=\"1.0\" encoding='ISO-8859-2'?><a/>")
  r <- mime_sniff(xml)
  expect_identical(r$type, "text/xml")
  expect_identical(r$charset, "ISO-8859-2")
  expect_identical(cs(charToRaw("<?xml version=\"1.0\"?><a/>")), "UTF-8")
})

test_that("the HTML meta prescan finds charset and http-equiv", {
  expect_identical(
    cs(charToRaw("<html><head><meta charset=\"Windows-1251\"><title>")),
    "windows-1251"
  )
  expect_identical(
    cs(charToRaw(paste0("<html><meta http-equiv=\"Content-Type\" ",
      "content=\"text/html; charset=koi8-r\">"))),
    "koi8-r"
  )
  # content= without the pragma does not count.
  expect_identical(
    cs(charToRaw("<html><meta content=\"text/html; charset=koi8-r\">")),
    "UTF-8"
  )
  # A UTF-16 label means UTF-8 to the prescan; x-user-defined, windows-1252.
  expect_identical(cs(charToRaw("<html><meta charset=utf-16le>")), "UTF-8")
  expect_identical(cs(charToRaw("<html><meta charset=x-user-defined>")),
    "windows-1252")
  # A meta inside a comment is skipped.
  expect_identical(
    cs(charToRaw("<html><!-- <meta charset=koi8-r> --><p>")),
    "UTF-8"
  )
})

test_that("valid UTF-8 is UTF-8, ignoring a code point cut by the limit", {
  expect_identical(cs(charToRaw("café")), "UTF-8")
  cut <- c(charToRaw("aaaaaaaaa"), as.raw(c(0xc3, 0xa9)))
  r <- mime_sniff(cut, limit = 10)
  expect_identical(r$charset, "UTF-8")
  expect_identical(as.character(r$confidence), "probable")
  # Without the limit the same trailing byte is invalid UTF-8.
  expect_identical(cs(cut[1:10]), "ISO-8859-1")
})

test_that("the C1 rule guesses windows-1252 or ISO-8859-1 at probable", {
  r <- mime_sniff(c(charToRaw("caf"), as.raw(0xe9)))
  expect_identical(r$charset, "ISO-8859-1")
  expect_identical(as.character(r$confidence), "probable")
  r <- mime_sniff(c(charToRaw("a"), as.raw(0x93), charToRaw("quote")))
  expect_identical(r$charset, "windows-1252")
  html <- c(charToRaw("<html><p>caf"), as.raw(0xe9))
  r <- mime_sniff(html)
  expect_identical(r$type, "text/html")
  expect_identical(as.character(r$confidence), "probable")
})

test_that("line endings are reported for text", {
  nl <- function(s) mime_sniff(charToRaw(s))$newline
  expect_identical(nl("a\nb"), "lf")
  expect_identical(nl("a\r\nb"), "crlf")
  expect_identical(nl("a\rb"), "cr")
  expect_identical(nl("a\nb\r\nc"), "mixed")
  expect_identical(nl("ab"), NA_character_)
  expect_identical(mime_sniff(png_bytes())$newline, NA_character_)
})
