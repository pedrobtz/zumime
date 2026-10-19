test_that("the supplied charset parameter comes first", {
  expect_identical(sniff_charset(charToRaw("hi"), type = "text/plain; charset=Shift_JIS"),
    "Shift_JIS")
  expect_identical(sniff_charset(charToRaw("hi"), type = "text/plain; charset=UTF-8"),
    "UTF-8")
  # Not for a binary result.
  expect_identical(sniff_charset(png_bytes(), type = "text/plain; charset=UTF-8"),
    NA_character_)
})

test_that("a byte-order mark decides", {
  expect_identical(sniff_charset(as.raw(c(0xef, 0xbb, 0xbf, 0x68, 0x69))), "UTF-8")
  expect_identical(sniff_charset(as.raw(c(0xff, 0xfe, 0x68, 0x00))), "UTF-16LE")
  expect_identical(sniff_charset(as.raw(c(0xfe, 0xff, 0x00, 0x68))), "UTF-16BE")
})

test_that("an XML declaration names the encoding", {
  xml <- charToRaw("<?xml version=\"1.0\" encoding='ISO-8859-2'?><a/>")
  r <- mime_sniff(xml)
  expect_identical(r$type, "application/xml")
  expect_identical(r$charset, "ISO-8859-2")
  expect_identical(sniff_charset(charToRaw("<?xml version=\"1.0\"?><a/>")), "UTF-8")
})

test_that("the HTML meta prescan finds charset and http-equiv", {
  expect_identical(
    sniff_charset(charToRaw("<html><head><meta charset=\"Windows-1251\"><title>")),
    "windows-1251"
  )
  expect_identical(
    sniff_charset(charToRaw(paste0("<html><meta http-equiv=\"Content-Type\" ",
      "content=\"text/html; charset=koi8-r\">"))),
    "koi8-r"
  )
  # content= without the pragma does not count.
  expect_identical(
    sniff_charset(charToRaw("<html><meta content=\"text/html; charset=koi8-r\">")),
    "UTF-8"
  )
  # A UTF-16 label means UTF-8 to the prescan; x-user-defined, windows-1252.
  expect_identical(sniff_charset(charToRaw("<html><meta charset=utf-16le>")), "UTF-8")
  expect_identical(sniff_charset(charToRaw("<html><meta charset=x-user-defined>")),
    "windows-1252")
  # A meta inside a comment is skipped.
  expect_identical(
    sniff_charset(charToRaw("<html><!-- <meta charset=koi8-r> --><p>")),
    "UTF-8"
  )
})

test_that("valid UTF-8 is UTF-8, ignoring a code point cut by the limit", {
  expect_identical(sniff_charset(charToRaw("café")), "UTF-8")
  cut <- c(charToRaw("aaaaaaaaa"), as.raw(c(0xc3, 0xa9)))
  r <- mime_sniff(cut, limit = 10)
  expect_identical(r$charset, "UTF-8")
  expect_identical(as.character(r$confidence), "probable")
  # Without the limit the same trailing byte is invalid UTF-8.
  expect_identical(sniff_charset(cut[1:10]), "ISO-8859-1")
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

test_that("the charset rules apply in their order", {
  bom <- as.raw(c(0xef, 0xbb, 0xbf))
  # The supplied parameter beats a BOM.
  expect_identical(
    sniff_charset(c(bom, charToRaw("hi")), type = "text/plain; charset=koi8-r"),
    "koi8-r"
  )
  # A BOM beats an XML declaration.
  expect_identical(
    sniff_charset(c(bom, charToRaw(
      "<?xml version=\"1.0\" encoding=\"ISO-8859-2\"?><a/>"))),
    "UTF-8"
  )
  # The meta prescan reads only the first 1024 bytes.
  late <- paste0("<html>", strrep(" ", 1100), "<meta charset=koi8-r>")
  expect_identical(sniff_charset(charToRaw(late)), "UTF-8")
})

test_that("four-byte UTF-8 is valid and an F5 lead byte is not", {
  expect_identical(
    sniff_charset(c(charToRaw("smile "), as.raw(c(0xf0, 0x9f, 0x98, 0x80)))),
    "UTF-8"
  )
  expect_identical(sniff_charset(c(charToRaw("x"), as.raw(c(0xf5, 0x41)))),
    "ISO-8859-1")
})

test_that("the meta prescan trims labels, skips markup and keeps the first", {
  html <- function(s) charToRaw(paste0("<html>", s))
  expect_identical(sniff_charset(html("<meta charset=\" koi8-r \">")), "koi8-r")
  expect_identical(sniff_charset(html("<meta foo charset=koi8-r>")), "koi8-r")
  expect_identical(sniff_charset(html(paste0(
    "<meta http-equiv=content-type ",
    "content=\"text/html; charset='koi8-r'\">"))), "koi8-r")
  expect_identical(sniff_charset(html("<meta charset=koi8-r charset=big5>")),
    "koi8-r")
  expect_identical(sniff_charset(html(
    "<!x><?pi?></p><meta charset=koi8-r>")), "koi8-r")
})
