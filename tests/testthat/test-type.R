test_that("mime_type() answers from bytes and name, with agree", {
  dir <- local_tree(list(
    "data.csv" = "a,b\n1,2\n",
    "logo.txt" = png_bytes(),
    "report.docx" = build_zip(ooxml_entries("word")),
    "README" = "read me\n",
    "blob.bin" = as.raw(c(1, 2, 3, 0, 255))
  ))
  t <- mime_type(file.path(dir, c("data.csv", "logo.txt", "report.docx",
    "README", "blob.bin")))
  expect_s3_class(t, "zumime_result")
  expect_named(t, c("path", "type", "confidence", "charset", "by_name",
    "agree", "inner", "encrypted", "complete", "newline", "interpreter"))
  expect_identical(t$type, c("text/plain", "image/png", docx_type(),
    "text/plain", "application/octet-stream"))
  expect_identical(t$by_name, c("text/csv", "text/plain", docx_type(), NA,
    "application/octet-stream"))
  # text/plain bytes and a .csv name lie on one lineage; a PNG named .txt
  # does not; unknown name or unknown bytes give NA.
  expect_identical(t$agree, c(TRUE, FALSE, TRUE, NA, NA))
})

test_that("the frame prints and snapshots stably", {
  dir <- local_tree(list(
    "a.csv" = "x,y\n1,2\n",
    "b.txt" = png_bytes(),
    "c.sh" = "#!/bin/sh\r\necho hi\r\n"
  ))
  t <- mime_type(file.path(dir, c("a.csv", "b.txt", "c.sh")))
  t$path <- basename(t$path)
  expect_snapshot(print(t))
})

test_that("unreadable paths are NA rows, or an error with strict", {
  dir <- local_tree(list(ok.txt = "fine"))
  missing <- file.path(dir, "nope.pdf")
  t <- mime_type(c(file.path(dir, "ok.txt"), missing, NA))
  expect_identical(t$type, c("text/plain", NA, NA))
  expect_identical(as.character(t$confidence), c("probable", "none", "none"))
  expect_identical(t$agree, c(TRUE, NA, NA))
  expect_error(mime_type(missing, strict = TRUE), class = "zumime_io_error")
  expect_error(mime_type(missing, strict = TRUE), class = "zumime_error")
  expect_identical(nrow(mime_type(character())), 0L)
})

test_that("a directory is inode/directory and nothing is read", {
  dir <- local_tree(list("sub/a.txt" = "x"))
  t <- mime_type(file.path(dir, "sub"))
  expect_identical(t$type, "inode/directory")
  expect_identical(as.character(t$confidence), "definite")
})

test_that("inner comes from the rest of the name by default", {
  csv <- gzip_bytes("a,b\n1,2\n")
  dir <- local_tree(list("data.csv.gz" = csv, "x.tgz" = csv,
    "y.tar.gz" = csv, "plain.gz" = csv, "z.csv" = "a,b\n"))
  t <- mime_type(file.path(dir, c("data.csv.gz", "x.tgz", "y.tar.gz",
    "plain.gz", "z.csv")))
  expect_identical(t$type[1:4], rep("application/gzip", 4))
  expect_identical(t$inner, c("text/csv", "application/x-tar",
    "application/x-tar", NA, NA))
  expect_identical(t$agree[1:4], rep(TRUE, 4))
})

test_that("inner = \"decompress\" sniffs what zukomp inflates", {
  skip_if_not_installed("zukomp")
  dir <- local_tree(list("blob.gz" = gzip_bytes("{\"a\": [1, 2]}")))
  path <- file.path(dir, "blob.gz")
  expect_identical(mime_type(path)$inner, NA_character_)
  expect_identical(mime_type(path, inner = "decompress")$inner,
    "application/json")
})

test_that("asking for an absent suggested package is a dependency error", {
  skip_if(requireNamespace("zuutf", quietly = TRUE), "zuutf is installed")
  dir <- local_tree(list(a.txt = "caf\xe9"))
  expect_error(mime_type(file.path(dir, "a.txt"), charset = "detect"),
    class = "zumime_dependency_error")
})

test_that("encrypted is read from ZIP, OLE2 and, with complete, PDF", {
  dir <- local_tree(list(
    "locked.zip" = build_zip(list(a = "x"), flags = 1L),
    "open.zip" = build_zip(list(a = "x")),
    "locked.doc" = build_ole2(c("EncryptionInfo", "EncryptedPackage")),
    "locked.pdf" = pdf_bytes(encrypt = TRUE),
    "open.pdf" = pdf_bytes()
  ))
  paths <- file.path(dir, c("locked.zip", "open.zip", "locked.doc",
    "locked.pdf", "open.pdf"))
  expect_identical(mime_type(paths)$encrypted, c(TRUE, FALSE, TRUE, NA, NA))
  expect_identical(mime_type(paths, complete = TRUE)$encrypted,
    c(TRUE, FALSE, TRUE, TRUE, FALSE))
})

test_that("complete = TRUE reads the end of ZIP, PDF, gzip and Parquet", {
  zip <- build_zip(ooxml_entries("word"))
  gz <- gzip_bytes(strrep("abc,def\n", 2000))
  rds <- withr::local_tempfile(fileext = ".rds")
  saveRDS(1:1000, rds)
  rds_bytes <- readBin(rds, "raw", file.size(rds))
  parquet <- c(charToRaw("PAR1"), raw(40), charToRaw("PAR1"))
  dir <- local_tree(list(
    "whole.docx" = zip, "cut.docx" = zip[seq_len(length(zip) - 30)],
    "whole.pdf" = pdf_bytes(), "cut.pdf" = pdf_bytes(eof = FALSE),
    "whole.csv.gz" = gz, "cut.csv.gz" = gz[seq_len(length(gz) - 6)],
    "whole.rds" = rds_bytes, "cut.rds" = rds_bytes[1:20],
    "whole.parquet" = parquet, "cut.parquet" = parquet[1:30],
    "note.txt" = "no end marker"
  ))
  names <- c("whole.docx", "cut.docx", "whole.pdf", "cut.pdf",
    "whole.csv.gz", "cut.csv.gz", "whole.rds", "cut.rds", "whole.parquet",
    "cut.parquet", "note.txt")
  t <- mime_type(file.path(dir, names), complete = TRUE)
  expect_identical(t$complete,
    c(TRUE, FALSE, TRUE, FALSE, TRUE, FALSE, TRUE, FALSE, TRUE, FALSE, NA))
  expect_identical(mime_type(file.path(dir, names))$complete,
    rep(NA, length(names)))
})

test_that("the ZIP tail is read when the central directory is past the head", {
  e <- c(list("big.bin" = as.raw(rep(1:255, 40))), ooxml_entries("word"))
  zip <- build_zip(e)
  dir <- local_tree(list("r.docx" = zip))
  expect_identical(mime_sniff(zip)$type, "application/zip")
  expect_identical(mime_type(file.path(dir, "r.docx"))$type, docx_type())
})

test_that("a central directory larger than the tail is read from its start", {
  many <- stats::setNames(rep(list("x"), 2500),
    sprintf("assets/padding-entry-%05d.txt", 1:2500))
  e <- c(list("big.bin" = as.raw(rep(1:255, 40))), many,
    list("AndroidManifest.xml" = "m", "classes.dex" = "d"))
  zip <- build_zip(e)
  dir <- local_tree(list("app.apk" = zip))
  expect_identical(mime_type(file.path(dir, "app.apk"))$type,
    "application/vnd.android.package-archive")
})

test_that("signature rows past the head are read by seeking", {
  iso <- raw(40000)
  iso[32770:32774] <- charToRaw("CD001")
  dir <- local_tree(list("disc.iso" = iso))
  expect_identical(mime_type(file.path(dir, "disc.iso"))$type,
    "application/x-iso9660-image")
})

test_that("newline and interpreter come from the bytes", {
  dir <- local_tree(list(run = "#!/usr/bin/env python3\r\nprint(1)\r\n"))
  t <- mime_type(file.path(dir, "run"))
  expect_identical(t$type, "text/x-python")
  expect_identical(t$newline, "crlf")
  expect_identical(t$interpreter, "python3")
})

test_that("text = \"family\" offers generic text to the family's sniffers", {
  skip_if_not_installed("zucsv")
  dir <- local_tree(list(semi = "a;b;c\n1;2;3\n4;5;6\n", words = "just text\n"))
  paths <- file.path(dir, c("semi", "words"))
  expect_identical(mime_type(paths)$type, c("text/plain", "text/plain"))
  t <- mime_type(paths, text = "family")
  expect_identical(t$type, c("text/csv", "text/plain"))
  expect_identical(as.character(t$confidence), c("probable", "probable"))
  expect_true("zucsv" %in% zumime_info()$family)
})

test_that("mime_sniff() reads paths through the same loop", {
  dir <- local_tree(list(a.png = png_bytes(), b = "<html><body>x"))
  r <- mime_sniff(file.path(dir, c("a.png", "b", "missing")))
  expect_identical(r$type, c("image/png", "text/html", NA))
  expect_false("by_name" %in% names(r))
  r <- mime_sniff(file.path(dir, "a.png"), type = "text/csv", no_sniff = TRUE)
  expect_identical(r$type, "text/csv")
})

test_that("mime_type() rejects malformed arguments", {
  expect_error(mime_type(1), class = "zumime_type_error")
  expect_error(mime_type("a", inner = "zip"), class = "zumime_type_error")
  expect_error(mime_type("a", text = "x"), class = "zumime_type_error")
  expect_error(mime_type("a", charset = "x"), class = "zumime_type_error")
  expect_error(mime_type("a", complete = NA), class = "zumime_type_error")
  expect_error(mime_type("a", strict = 1), class = "zumime_type_error")
  expect_error(mime_type("a", limit = -1), class = "zumime_type_error")
})
