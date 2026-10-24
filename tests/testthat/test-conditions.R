# One message per condition class, so a misleading wording shows in review.
# Every other test asserts on the class only. The snapshots share one
# test_that() block so a shuffled run writes them in the same order.

test_that("each condition class has a message that names its subject", {
  dir <- withr::local_tempdir()
  withr::defer(try(mime_unregister("text/x-zt-snap"), silent = TRUE))

  # A type error names the argument.
  expect_snapshot(mime_sniff(1), error = TRUE)

  # An io error names the path.
  missing <- file.path(dir, "nope.pdf")
  expect_snapshot(
    mime_type(missing, strict = TRUE),
    error = TRUE,
    # The reason is the system's own text, which varies by platform.
    transform = function(x) {
      sub(": [^:]*\\.$", ": <reason>.", gsub(dir, "<dir>", x, fixed = TRUE))
    }
  )

  # A parse error names the input.
  expect_snapshot(mime_parse("nope", strict = TRUE), error = TRUE)

  # A registry error names the type.
  expect_snapshot(
    mime_register("image/png", "application/octet-stream"),
    error = TRUE
  )

  # A dependency error names the package.
  path <- file.path(dir, "a.gz")
  writeBin(gzip_bytes("x"), path)
  with_mocked_bindings(
    expect_snapshot(mime_type(path, inner = "decompress"), error = TRUE),
    has_package = function(pkg) FALSE
  )

  # A state error says to start again.
  s <- mime_sniffer()
  mime_finish(s)
  expect_snapshot(mime_push(s, raw(1)), error = TRUE)

  # A rule warning names the type whose rule failed.
  mime_register("text/x-zt-snap", "text/plain", rule = function(x) {
    stop("bug in the rule")
  })
  expect_snapshot(r <- mime_sniff(charToRaw("hello")))
})
