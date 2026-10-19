test_that("mime_parse() lower-cases type, subtype and names, not values", {
  rec <- mime_parse("TEXT/HTML;CHARSET=GBK")[[1]]
  expect_identical(rec$type, "text")
  expect_identical(rec$subtype, "html")
  expect_identical(rec$parameters, list(charset = "GBK"))
  expect_identical(mime_format(rec), "text/html;charset=GBK")
})

test_that("mime_parse() unescapes quoted values and keeps the first duplicate", {
  rec <- mime_parse("text/plain; a=\"x\\\"y\\\\z\"; A=2; b=3")[[1]]
  expect_identical(rec$parameters, list(a = "x\"y\\z", b = "3"))
  expect_identical(mime_format(rec), "text/plain;a=\"x\\\"y\\\\z\";b=3")
})

test_that("mime_format() quotes empty and non-token values", {
  rec <- list(
    type = "a",
    subtype = "b",
    parameters = list(e = "", s = "a b", t = "tok")
  )
  expect_identical(mime_format(rec), "a/b;e=\"\";s=\"a b\";t=tok")
})

test_that("mime_parse() gives NULL for invalid input and NA", {
  out <- mime_parse(c("/html", "text/", "text", "te xt/html", NA, ""))
  expect_true(all(vapply(out, is.null, logical(1))))
  expect_identical(mime_format(out), rep(NA_character_, 6))
})

test_that("mime_parse(strict = TRUE) raises zumime_parse_error", {
  expect_error(mime_parse("nope", strict = TRUE), class = "zumime_parse_error")
  expect_error(mime_parse("nope", strict = TRUE), class = "zumime_error")
  expect_length(mime_parse(c("a/b", NA), strict = TRUE), 2L)
})

test_that("mime_parse() rejects code points above U+00FF in values", {
  rec <- mime_parse("a/b;x=é;y=€")[[1]]
  expect_identical(rec$parameters, list(x = "é"))
})

test_that("mime_parse() decodes 4-byte, invalid and latin1 input", {
  # U+1F600 is above U+00FF: the value is dropped.
  rec <- mime_parse("a/b;x=\U1F600;y=z")[[1]]
  expect_identical(rec$parameters, list(y = "z"))
  # A lone lead byte decodes to U+FFFD, so the value is dropped too, and a
  # type holding one is no type. Native bytes are invalid only where the
  # native encoding cannot hold them, which Latin-1 can.
  invalid <- rawToChar(as.raw(c(0x61, 0x2f, 0x62, 0x3b, 0x78, 0x3d, 0xc3)))
  bad_type <- rawToChar(as.raw(c(0x61, 0xc3, 0x2f, 0x62)))
  marked <- c(invalid, bad_type)
  Encoding(marked) <- "UTF-8"
  inputs <- list(marked)
  if (!isTRUE(l10n_info()[["Latin-1"]])) {
    inputs <- c(inputs, list(c(invalid, bad_type)))
  }
  for (x in inputs) {
    out <- mime_parse(x)
    expect_length(out[[1]]$parameters, 0L)
    expect_null(out[[2]])
  }
  # A latin1-marked U+00E9 is within U+00FF and kept.
  latin1 <- "a/b;x=\xe9"
  Encoding(latin1) <- "latin1"
  expect_identical(mime_parse(latin1)[[1]]$parameters, list(x = "\u00e9"))
})

test_that("mime_format() rejects what is not a record", {
  expect_error(mime_format("text/html"), class = "zumime_type_error")
  expect_error(mime_format(list(list(type = "a"))), class = "zumime_type_error")
  expect_error(mime_parse(1), class = "zumime_type_error")
})

test_that("every web-platform-tests parse fixture passes", {
  skip_if_gctorture()
  dir <- fixture_dir("wpt")
  # Entries per file at WPT 0f19549, and how many hold U+0000, which an R
  # string cannot carry. An empty list would otherwise pass as a skip.
  counts <- c("mime-types.json" = 74L, "generated-mime-types.json" = 876L)
  dropped <- c("mime-types.json" = 0L, "generated-mime-types.json" = 5L)
  for (f in names(counts)) {
    entries <- wpt_mime_entries(file.path(dir, f))
    expect_identical(length(entries), counts[[f]], info = f)
    expect_identical(attr(entries, "dropped"), dropped[[f]], info = f)
    for (e in entries) {
      want <- if (is.null(e$output)) NA_character_ else e$output
      expect_identical(mime_format(mime_parse(e$input)), want, info = e$input)
    }
  }
})
