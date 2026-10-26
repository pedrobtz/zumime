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

test_that("translated paths are released path by path", {
  # One latin1 path of 100 kB, 4000 times: R translates each element for
  # fopen(), so holding every copy until the call returns takes 400 MB.
  # Released copies are garbage that the next collection frees, so the
  # peak stays near the collector's trigger, at least 64 MB.
  one <- paste0("caf\xe9", strrep("x", 1e5))
  Encoding(one) <- "latin1"
  p <- rep(one, 4000)
  peak_mb <- function(f) {
    gc(reset = TRUE)
    g <- gc()
    if (g["Vcells", "gc trigger"] * 8 / 2^20 > 100) {
      skip("the collector's trigger is too high to tell")
    }
    suppressWarnings(f(p))
    (gc()["Vcells", "max used"] - g["Vcells", "used"]) * 8 / 2^20
  }
  expect_lt(peak_mb(mime_sniff), 150)
  expect_lt(peak_mb(function(p) mime_check(p, "text/plain")), 150)
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
  expect_identical(mime_check(paths, "text/plain"), c(TRUE, FALSE))
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

test_that("gzip completeness reads past 4 MiB of compressed bytes", {
  withr::local_seed(1)
  f <- withr::local_tempfile(fileext = ".bin.gz")
  con <- gzfile(f, "wb")
  writeBin(as.raw(sample.int(256L, 5 * 1024^2, replace = TRUE) - 1L), con)
  close(con)
  expect_gt(file.size(f), 4 * 1024^2)
  b <- readBin(f, "raw", file.size(f))
  cut <- withr::local_tempfile(fileext = ".bin.gz")
  writeBin(b[seq_len(length(b) - 6L)], cut)
  t <- mime_type(c(f, cut), complete = TRUE)
  expect_identical(t$type, rep("application/gzip", 2L))
  expect_identical(t$complete, c(TRUE, FALSE))
})

test_that("complete = TRUE reads the end of RData in gzip", {
  f <- withr::local_tempfile(fileext = ".RData")
  x <- seq_len(5000)
  save(x, file = f)
  b <- readBin(f, "raw", file.size(f))
  cut <- withr::local_tempfile(fileext = ".RData")
  writeBin(b[seq_len(length(b) - 6L)], cut)
  t <- mime_type(c(f, cut), complete = TRUE)
  expect_identical(t$type, rep("application/x-rdata", 2L))
  expect_identical(t$complete, c(TRUE, FALSE))
})

test_that("a PDF tail without trailer or /XRef is searched whole", {
  pdf <- function(dict) {
    charToRaw(paste0(
      "%PDF-1.7\n1 0 obj << /Type /Catalog",
      dict,
      " >> endobj\nstartxref\n0\n%%EOF\n"
    ))
  }
  dir <- local_tree(list(
    "locked.pdf" = pdf(" /Encrypt 2 0 R"),
    "open.pdf" = pdf("")
  ))
  t <- mime_type(file.path(dir, c("locked.pdf", "open.pdf")), complete = TRUE)
  expect_identical(t$type, rep("application/pdf", 2L))
  expect_identical(t$encrypted, c(TRUE, FALSE))
  expect_identical(t$complete, c(TRUE, TRUE))
})

test_that("block devices and sockets are typed without being opened", {
  skip_on_os("windows")
  # stat() alone types them, so whichever the host has is enough.
  blk <- c("/dev/disk0", "/dev/sda", "/dev/vda", "/dev/nvme0n1", "/dev/loop0")
  sock <- c("/var/run/mDNSResponder", "/run/systemd/journal/socket")
  blk <- blk[file.exists(blk)]
  sock <- sock[file.exists(sock)]
  skip_if(length(blk) + length(sock) == 0L, "no block device or socket")
  t <- mime_type(c(blk, sock))
  expect_identical(
    t$type,
    c(rep("inode/blockdevice", length(blk)), rep("inode/socket", length(sock)))
  )
})
