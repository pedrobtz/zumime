test_that("zumime_info() reports the package version", {
  info <- zumime_info()
  expect_named(info, c("version", "table_version"))
  expect_identical(info$version, as.character(packageVersion("zumime")))
})
