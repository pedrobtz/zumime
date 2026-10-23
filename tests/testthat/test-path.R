# The path loop (design section 6.7): what is read, and how much is
# allocated, for each kind of path.

test_that("a path that is not read reserves no head buffer", {
  dir <- withr::local_tempdir()
  paths <- c(dir, file.path(dir, "missing"))
  gc(reset = TRUE)
  t <- mime_type(paths, limit = 1e9)
  g <- gc()
  peak <- g["Vcells", ncol(g)]
  expect_identical(t$type, c("inode/directory", NA))
  # Megabytes: 1e9 bytes were reserved for the directory before.
  expect_lt(peak, 500)
})

test_that("a directory with a trailing separator is a directory", {
  dir <- withr::local_tempdir()
  t <- mime_type(c(paste0(dir, "/"), paste0(dir, "//")))
  expect_identical(t$type, rep("inode/directory", 2L))
  expect_identical(as.character(t$confidence), rep("definite", 2L))
})

test_that("a tar row past the head is checked with its checksum", {
  bad <- raw(1024)
  bad[258:262] <- charToRaw("ustar")
  good <- c(tar_header(), raw(512))
  dir <- local_tree(list("bad.bin" = bad, "good.tar" = good))
  paths <- file.path(dir, c("bad.bin", "good.tar"))
  want <- c("application/octet-stream", "application/x-tar")
  expect_identical(mime_type(paths)$type, want)
  for (limit in c(100, 200, 300)) {
    expect_identical(mime_type(paths, limit = limit)$type, want)
  }
})
