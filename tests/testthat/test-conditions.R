# One message per condition class, so a misleading wording shows in review.
# Every other test asserts on the class only.

test_that("a type error names the argument", {
  expect_snapshot(mime_sniff(1), error = TRUE)
})

test_that("an io error names the path", {
  dir <- withr::local_tempdir()
  missing <- file.path(dir, "nope.pdf")
  expect_snapshot(
    mime_type(missing, strict = TRUE),
    error = TRUE,
    # The reason is the system's own text, which varies by platform.
    transform = function(x) {
      sub(": [^:]*\\.$", ": <reason>.", gsub(dir, "<dir>", x, fixed = TRUE))
    }
  )
})

test_that("a parse error names the input", {
  expect_snapshot(mime_parse("nope", strict = TRUE), error = TRUE)
})

test_that("a registry error names the type", {
  expect_snapshot(
    mime_register("image/png", "application/octet-stream"),
    error = TRUE
  )
})

test_that("a dependency error names the package", {
  local_mocked_bindings(has_package = function(pkg) FALSE)
  dir <- withr::local_tempdir()
  path <- file.path(dir, "a.gz")
  writeBin(gzip_bytes("x"), path)
  expect_snapshot(mime_type(path, inner = "decompress"), error = TRUE)
})

test_that("a state error says to start again", {
  s <- mime_sniffer()
  mime_finish(s)
  expect_snapshot(mime_push(s, raw(1)), error = TRUE)
})
