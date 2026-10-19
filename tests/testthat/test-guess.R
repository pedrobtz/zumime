test_that("mime_guess() ignores case and takes the last suffix", {
  expect_identical(mime_guess("report.FINAL.PDF"), "application/pdf")
  expect_identical(mime_guess("photo.JPG"), "image/jpeg")
})

test_that("mime_guess() knows compound suffixes", {
  expect_identical(mime_guess("a.tar.gz"), "application/gzip")
  expect_identical(mime_guess("data.csv.gz"), "application/gzip")
  expect_identical(mime_guess("a.tar"), "application/x-tar")
})

test_that("mime_guess() reads only the last path component", {
  expect_identical(mime_guess("C:\\dir.zip\\a.csv"), "text/csv")
  expect_identical(mime_guess("/srv/x.pdf/README"), NA_character_)
})

test_that("mime_guess() is NA without a known suffix", {
  expect_identical(
    mime_guess(c("README", "a.", ".bashrc", "a.unknownext", NA, "")),
    rep(NA_character_, 6)
  )
})

test_that("mime_guess() knows R and analytic data formats", {
  expect_identical(
    mime_guess(c("x.rds", "x.RData", "x.parquet", "x.dta", "x.sav",
      "x.sas7bdat", "x.sqlite", "x.h5")),
    c("application/x-rds", "application/x-rdata",
      "application/vnd.apache.parquet", "application/x-stata-dta",
      "application/x-spss-sav", "application/x-sas-data",
      "application/vnd.sqlite3", "application/x-hdf5")
  )
})

test_that("every extension of every type maps back to it or a descendant", {
  types <- mime_types()
  for (i in seq_len(nrow(types))) {
    exts <- types$extensions[[i]]
    if (!length(exts)) next
    back <- mime_guess(paste0("file.", exts))
    expect_true(all(mime_is(back, types$type[i])), info = types$type[i])
  }
})
