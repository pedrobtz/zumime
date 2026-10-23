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

test_that("a path in \"bytes\" encoding is an error row, not a condition", {
  x <- "caf\xe9.txt"
  Encoding(x) <- "bytes"
  dir <- local_tree(list("a.txt" = "hello\n"))
  paths <- c(file.path(dir, "a.txt"), x)
  t <- mime_type(paths)
  expect_identical(t$type, c("text/plain", NA))
  expect_identical(as.character(t$confidence[2]), "none")
  expect_error(mime_type(x, strict = TRUE), class = "zumime_io_error")
})

test_that("limit = 0 reads a file larger than one read chunk whole", {
  # The tail of a ZIP past 4 MiB of stored data: only a whole read sees it.
  e <- c(list("big.bin" = as.raw(rep(1:255, 20000))), ooxml_entries("word"))
  zip <- build_zip(e)
  expect_gt(length(zip), 4 * 1024^2)
  dir <- local_tree(list("r.docx" = zip))
  t <- mime_type(file.path(dir, "r.docx"), limit = 0)
  expect_identical(t$type, docx_type())
})
