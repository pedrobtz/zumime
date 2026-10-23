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
  expect_identical(
    mime_sniff(readBin(rda, "raw", file.size(rda)))$type,
    "application/x-rdata"
  )

  ascii <- file.path(dir, "a.rds")
  saveRDS(df, ascii, ascii = TRUE)
  expect_identical(
    mime_sniff(readBin(ascii, "raw", file.size(ascii)))$type,
    "application/x-rds"
  )
  v2 <- file.path(dir, "v2.rds")
  saveRDS(df, v2, version = 2)
  expect_identical(
    mime_sniff(readBin(v2, "raw", file.size(v2)))$type,
    "application/x-rds"
  )
})

test_that("uncompressed RDS and RData are found by their headers", {
  dir <- withr::local_tempdir()
  f <- file.path(dir, "x.rds")
  saveRDS(1:3, f, compress = FALSE)
  expect_identical(
    mime_sniff(readBin(f, "raw", file.size(f)))$type,
    "application/x-rds"
  )
  g <- file.path(dir, "x.rda")
  x <- 1
  save(x, file = g, compress = FALSE)
  expect_identical(
    mime_sniff(readBin(g, "raw", file.size(g)))$type,
    "application/x-rdata"
  )
})

test_that("uncompressed native-format RDS is found by its header", {
  for (version in 2:3) {
    x <- serialize(1:3, NULL, xdr = FALSE, version = version)
    expect_identical(mime_sniff(x)$type, "application/x-rds", info = version)
  }
  # ASCII serialisation is text.
  expect_identical(
    mime_sniff(serialize(1:3, NULL, ascii = TRUE))$type,
    "text/plain"
  )
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
  expect_identical(
    mime_sniff(readBin(gz, "raw", file.size(gz)))$type,
    "application/gzip"
  )
})

test_that("the bounded inflater handles fixed and dynamic blocks", {
  dir <- withr::local_tempdir()
  # R's gzip writes the first block of the random doubles with dynamic
  # codes and both strings with fixed codes. Each is an RDS inside gzip.
  withr::local_seed(1)
  for (obj in list(runif(5000), "x", paste(rep("abc", 500), collapse = ""))) {
    f <- file.path(dir, "o.rds")
    saveRDS(obj, f)
    expect_identical(
      mime_sniff(readBin(f, "raw", file.size(f)))$type,
      "application/x-rds"
    )
  }
})

test_that("the bounded inflater reads a stored block", {
  # A final stored block: BFINAL = 1 and BTYPE = 0 in the first byte, then
  # LEN, its complement NLEN and LEN bytes as they are.
  stored <- function(payload) {
    n <- length(payload)
    c(as.raw(1), u16(n), u16(bitwXor(n, 0xFFFF)), payload)
  }
  rds <- c(charToRaw("X\n"), as.raw(c(0, 0, 0, 3)), raw(20))
  expect_identical(
    mime_sniff(gzip_member(stored(rds), length(rds)))$type,
    "application/x-rds"
  )

  csv <- charToRaw("a,b\n1,2\n")
  dir <- local_tree(list("s.csv.gz" = gzip_member(stored(csv), length(csv))))
  t <- mime_type(file.path(dir, "s.csv.gz"), complete = TRUE)
  expect_identical(t$type, "application/gzip")
  expect_true(t$complete)
})

test_that("native-endian RDS inside gzip is R's format", {
  # "B\n" then the format version as a little-endian 32-bit integer, as
  # serialize(xdr = FALSE) writes it on a little-endian machine.
  for (version in 2:3) {
    rds <- c(charToRaw("B\n"), u32(version), raw(20))
    expect_identical(
      mime_sniff(gzip_bytes(rds))$type,
      "application/x-rds",
      info = version
    )
  }
  # A big-endian version number is not one.
  rds <- c(charToRaw("B\n"), as.raw(c(0, 0, 0, 3)), raw(20))
  expect_identical(mime_sniff(gzip_bytes(rds))$type, "application/gzip")
})
