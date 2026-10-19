test_that("stream names decide Word, Excel, PowerPoint and Outlook", {
  expect_identical(sniff_type(build_ole2(c("WordDocument", "1Table"))),
    "application/msword")
  expect_identical(sniff_type(build_ole2("Workbook")), "application/vnd.ms-excel")
  expect_identical(sniff_type(build_ole2("Book")), "application/vnd.ms-excel")
  expect_identical(sniff_type(build_ole2("PowerPoint Document")),
    "application/vnd.ms-powerpoint")
  expect_identical(sniff_type(build_ole2("__properties_version1.0")),
    "application/vnd.ms-outlook")
  expect_identical(sniff_type(build_ole2("__substg1.0_0037001F")),
    "application/vnd.ms-outlook")
})

test_that("the root class id decides an installer", {
  expect_identical(sniff_type(build_ole2("x", clsid = msi_clsid())),
    "application/x-ms-installer")
})

test_that("an EncryptionInfo stream is encrypted Office", {
  r <- mime_sniff(build_ole2(c("EncryptionInfo", "EncryptedPackage")))
  expect_identical(r$type, "application/x-ole-storage")
  expect_true(r$encrypted)
  expect_identical(mime_sniff(build_ole2("WordDocument"))$encrypted, NA)
})

test_that("a directory longer than one sector is followed through the FAT", {
  streams <- c(paste0("s", 1:6), "Workbook")
  expect_identical(sniff_type(build_ole2(streams)), "application/vnd.ms-excel")
})

test_that("a truncated directory decides from what was read", {
  f <- build_ole2(c("WordDocument", paste0("s", 1:6)))
  expect_identical(mime_sniff(f[1:1400], limit = 0)$type, "application/msword")
  expect_identical(mime_sniff(f[1:1100], limit = 0)$type,
    "application/x-ole-storage")
})

test_that("a directory past the head is read by seeking in a path", {
  # 20 free sectors put the directory at 10.5 KiB, past the 4 KiB head.
  doc <- build_ole2(c("WordDocument", "1Table"), pad = 20L)
  locked <- build_ole2(c("EncryptionInfo", "EncryptedPackage"), pad = 20L)
  dir <- local_tree(list(a.doc = doc, b.docx = locked))
  expect_identical(mime_sniff(doc)$type, "application/x-ole-storage")
  t <- mime_type(file.path(dir, c("a.doc", "b.docx")))
  expect_identical(t$type, c("application/msword", "application/x-ole-storage"))
  expect_identical(t$encrypted, c(NA, TRUE))
  expect_identical(mime_check(file.path(dir, "a.doc"), "application/msword"),
    TRUE)
})
