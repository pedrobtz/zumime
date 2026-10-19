test_that("zumime_info() reports the package version", {
  info <- zumime_info()
  expect_named(info, c("version", "table_version"))
  expect_identical(info$version, as.character(packageVersion("zumime")))
})

test_that("zumime_info() reports the table version as a date", {
  v <- zumime_info()$table_version
  expect_match(v, "^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
  expect_false(is.na(as.Date(v)))
})
