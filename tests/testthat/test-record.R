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
  rec <- list(type = "a", subtype = "b",
    parameters = list(e = "", s = "a b", t = "tok"))
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

test_that("mime_format() rejects what is not a record", {
  expect_error(mime_format("text/html"), class = "zumime_type_error")
  expect_error(mime_format(list(list(type = "a"))), class = "zumime_type_error")
  expect_error(mime_parse(1), class = "zumime_type_error")
})

test_that("every web-platform-tests parse fixture passes", {
  dir <- fixture_dir("wpt")
  for (f in c("mime-types.json", "generated-mime-types.json")) {
    entries <- wpt_mime_entries(file.path(dir, f))
    for (e in entries) {
      want <- if (is.null(e$output)) NA_character_ else e$output
      expect_identical(mime_format(mime_parse(e$input)), want, info = e$input)
    }
  }
})
