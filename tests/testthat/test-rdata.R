test_that("gzip-wrapped RDS and RData are R's formats", {
  dir <- withr::local_tempdir()
  df <- data.frame(a = 1:3)
  rds <- file.path(dir, "x.rds")
  saveRDS(df, rds)
  b <- readBin(rds, "raw", file.size(rds))
  expect_identical(b[1:2], as.raw(c(0x1f, 0x8b)))
  r <- mime_sniff(b)
  expect_identical(r$type, "application/x-rds")
  expect_identical(as.character(r$confidence), "definite")

  rda <- file.path(dir, "x.RData")
  save(df, file = rda)
  expect_identical(mime_sniff(readBin(rda, "raw", file.size(rda)))$type,
    "application/x-rdata")

  ascii <- file.path(dir, "a.rds")
  saveRDS(df, ascii, ascii = TRUE)
  expect_identical(mime_sniff(readBin(ascii, "raw", file.size(ascii)))$type,
    "application/x-rds")
  v2 <- file.path(dir, "v2.rds")
  saveRDS(df, v2, version = 2)
  expect_identical(mime_sniff(readBin(v2, "raw", file.size(v2)))$type,
    "application/x-rds")
})

test_that("uncompressed RDS and RData are found by their headers", {
  dir <- withr::local_tempdir()
  f <- file.path(dir, "x.rds")
  saveRDS(1:3, f, compress = FALSE)
  expect_identical(mime_sniff(readBin(f, "raw", file.size(f)))$type,
    "application/x-rds")
  g <- file.path(dir, "x.rda")
  x <- 1
  save(x, file = g, compress = FALSE)
  expect_identical(mime_sniff(readBin(g, "raw", file.size(g)))$type,
    "application/x-rdata")
})

test_that("other wrappers keep their own type", {
  dir <- withr::local_tempdir()
  for (w in c("bzip2", "xz")) {
    f <- file.path(dir, paste0("x.", w))
    saveRDS(1:3, f, compress = w)
    want <- if (w == "bzip2") "application/x-bzip2" else "application/x-xz"
    expect_identical(mime_sniff(readBin(f, "raw", file.size(f)))$type, want)
  }
  # A gzip stream of something else is gzip.
  gz <- file.path(dir, "t.gz")
  con <- gzfile(gz, "wb")
  writeLines("not R", con)
  close(con)
  expect_identical(mime_sniff(readBin(gz, "raw", file.size(gz)))$type,
    "application/gzip")
})

test_that("the bounded inflater handles stored, fixed and dynamic blocks", {
  dir <- withr::local_tempdir()
  # Random data is stored; a short text gets fixed codes; a long one
  # dynamic codes. Each is wrapped in a gzip header around an RDS.
  withr::local_seed(1)
  for (obj in list(runif(5000), "x", paste(rep("abc", 500), collapse = ""))) {
    f <- file.path(dir, "o.rds")
    saveRDS(obj, f)
    expect_identical(mime_sniff(readBin(f, "raw", file.size(f)))$type,
      "application/x-rds")
  }
})
