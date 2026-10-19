test_that("the result frame has the documented columns and types", {
  r <- mime_sniff(png_bytes())
  expect_s3_class(r, c("zumime_result", "data.frame"))
  expect_named(
    r,
    c(
      "path",
      "type",
      "confidence",
      "charset",
      "inner",
      "encrypted",
      "complete",
      "newline",
      "interpreter"
    )
  )
  expect_true(is.ordered(r$confidence))
  expect_identical(
    levels(r$confidence),
    c("none", "extension", "probable", "definite")
  )
  expect_true(r$confidence >= "probable")
  expect_identical(r$path, NA_character_)
})

test_that("a result prints as a data frame with a header", {
  expect_snapshot(print(mime_sniff(png_bytes())))
  expect_snapshot(print(mime_sniff(charToRaw("hello\n"))))
})
