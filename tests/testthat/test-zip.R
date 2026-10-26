test_that("OOXML folders decide Word, Excel and PowerPoint", {
  expect_identical(sniff_type(build_zip(ooxml_entries("word"))), docx_type())
  expect_identical(
    sniff_type(build_zip(ooxml_entries("xl"))),
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
  )
  expect_identical(
    sniff_type(build_zip(ooxml_entries("ppt"))),
    "application/vnd.openxmlformats-officedocument.presentationml.presentation"
  )
  r <- mime_sniff(build_zip(ooxml_entries("word")))
  expect_identical(as.character(r$confidence), "definite")
  expect_false(r$encrypted)
})

test_that("a vbaProject.bin part makes a macro-enabled document", {
  expect_identical(
    sniff_type(build_zip(ooxml_entries("word", vba = TRUE))),
    "application/vnd.ms-word.document.macroenabled.12"
  )
  expect_identical(
    sniff_type(build_zip(ooxml_entries("xl", vba = TRUE))),
    "application/vnd.ms-excel.sheet.macroenabled.12"
  )
})

test_that("the main part's content type decides the variant, stored or deflated", {
  ct <- paste0(
    "application/vnd.openxmlformats-officedocument.",
    "wordprocessingml.template.main+xml"
  )
  e <- ooxml_entries("word", main_ct = ct)
  dotx <- "application/vnd.openxmlformats-officedocument.wordprocessingml.template"
  expect_identical(sniff_type(build_zip(e)), dotx)
  expect_identical(sniff_type(build_zip(e, method = 8L)), dotx)
  ppsx <- ooxml_entries(
    "ppt",
    main_ct = paste0(
      "application/vnd.",
      "openxmlformats-officedocument.presentationml.slideshow.main+xml"
    )
  )
  expect_identical(
    sniff_type(build_zip(ppsx, method = 8L)),
    "application/vnd.openxmlformats-officedocument.presentationml.slideshow"
  )
})

test_that("a stored mimetype entry decides EPUB and OpenDocument", {
  odt <- list(
    mimetype = "application/vnd.oasis.opendocument.text",
    "content.xml" = "<x/>"
  )
  expect_identical(
    sniff_type(build_zip(odt)),
    "application/vnd.oasis.opendocument.text"
  )
  epub <- list(mimetype = "application/epub+zip", "OEBPS/a.xhtml" = "<x/>")
  expect_identical(sniff_type(build_zip(epub)), "application/epub+zip")
  # Trailing line ends and spaces are trimmed from the entry's content.
  epub$mimetype <- "application/epub+zip\r\n "
  expect_identical(sniff_type(build_zip(epub)), "application/epub+zip")
  # A type the registry does not know under application/zip is not taken.
  odd <- list(mimetype = "text/plain", "a" = "b")
  expect_identical(sniff_type(build_zip(odd)), "application/zip")
})

test_that("JAR, APK and 3MF are told from plain ZIP", {
  expect_identical(
    sniff_type(build_zip(list(
      "META-INF/MANIFEST.MF" = "Manifest-Version: 1.0\n",
      "a.class" = "x"
    ))),
    "application/java-archive"
  )
  expect_identical(
    sniff_type(build_zip(list(
      "AndroidManifest.xml" = "x",
      "classes.dex" = "y",
      "META-INF/MANIFEST.MF" = "z"
    ))),
    "application/vnd.android.package-archive"
  )
  expect_identical(
    sniff_type(build_zip(list(
      "[Content_Types].xml" = "<Types/>",
      "3D/3dmodel.model" = "<model/>"
    ))),
    "model/3mf"
  )
  expect_identical(
    sniff_type(build_zip(list(a.txt = "hello"))),
    "application/zip"
  )
})

test_that("the encryption flag and the AES extra field set encrypted", {
  expect_true(mime_sniff(build_zip(list(a = "x"), flags = 1L))$encrypted)
  aes <- c(u16(0x9901), u16(7), u16(2), charToRaw("AE"), as.raw(3), u16(0))
  expect_true(mime_sniff(build_zip(list(a = "x"), extra = aes))$encrypted)
  # The walk steps past an extended-timestamp field to the AES one.
  ut <- c(u16(0x5455), u16(5), as.raw(1), u32(0))
  expect_true(
    mime_sniff(build_zip(list(a = "x"), extra = c(ut, aes)))$encrypted
  )
  expect_false(mime_sniff(build_zip(list(a = "x"), extra = ut))$encrypted)
  expect_false(mime_sniff(build_zip(list(a = "x")))$encrypted)
  expect_identical(mime_sniff(png_bytes())$encrypted, NA)
})

test_that("an AES-encrypted [Content_Types].xml leaves the folder's type", {
  # Method 99 is WinZip AES: the part cannot be read, so the template
  # content type inside it is not seen and word/ decides.
  ct <- paste0(
    "application/vnd.openxmlformats-officedocument.",
    "wordprocessingml.template.main+xml"
  )
  aes <- c(u16(0x9901), u16(7), u16(2), charToRaw("AE"), as.raw(3), u16(8))
  z <- build_zip(
    ooxml_entries("word", main_ct = ct),
    method = 99L,
    flags = 1L,
    extra = aes
  )
  r <- mime_sniff(z)
  expect_identical(r$type, docx_type())
  expect_true(r$encrypted)
})

test_that("without the central directory the local headers are walked", {
  e <- ooxml_entries("word")
  e[["word/big.bin"]] <- as.raw(rep(1:255, 40))
  z <- build_zip(e)
  # The limit cuts the archive before its central directory.
  expect_identical(mime_sniff(z, limit = 600)$type, docx_type())
  # A data-descriptor entry with no sizes stops the walk after its name.
  d <- build_zip(
    list("[Content_Types].xml" = "<Types/>", "word/a.xml" = "x", "zzz" = "y"),
    descriptor = TRUE
  )
  expect_identical(mime_sniff(d, limit = 60)$type, "application/zip")
})

test_that("a Zip64 marker falls back to the local headers", {
  z <- build_zip(ooxml_entries("word"), zip64 = TRUE)
  expect_identical(sniff_type(z), docx_type())
  # A last entry past the head makes the path loop read the tail.
  big <- c(ooxml_entries("word"), list(media = strrep("x", 5000)))
  dir <- local_tree(list("a.docx" = build_zip(big, zip64 = TRUE)))
  expect_identical(mime_type(file.path(dir, "a.docx"))$type, docx_type())
})

test_that("the local walk steps over data descriptors after known sizes", {
  # The Zip64 marker forces the walk; [Content_Types].xml and word/ are
  # only reached by stepping over the earlier entries' descriptors.
  for (signature in c(TRUE, FALSE)) {
    z <- build_zip(
      ooxml_entries("word"),
      descriptor = TRUE,
      sizes = TRUE,
      signature = signature,
      zip64 = TRUE
    )
    expect_identical(sniff_type(z), docx_type(), info = signature)
  }
})

test_that("a directory in the head is read when the record is in the tail", {
  # A maximal comment puts the end record 64 KiB past the directory, which
  # stays in the 4 KiB head.
  z <- build_zip(ooxml_entries("word"), comment = raw(65535))
  dir <- local_tree(list("a.docx" = z))
  expect_identical(mime_type(file.path(dir, "a.docx"))$type, docx_type())
  expect_identical(mime_sniff(z)$type, docx_type())
})

test_that("an end record inside the archive comment is passed over", {
  # A fake record in the comment points at a directory that is not there;
  # the real record's comment reaches the end of the file.
  fake <- c(
    charToRaw("PK"),
    as.raw(c(5, 6)),
    u16(0),
    u16(0),
    u16(1),
    u16(1),
    u32(46),
    u32(9999),
    u16(0)
  )
  # Descriptors without sizes stop the local walk at the first entry, so
  # only the directory can show word/.
  z <- build_zip(
    ooxml_entries("word"),
    descriptor = TRUE,
    comment = c(fake, raw(8))
  )
  expect_identical(sniff_type(z), docx_type())
  dir <- local_tree(list("a.docx" = z))
  expect_identical(mime_type(file.path(dir, "a.docx"))$type, docx_type())
})

test_that("a directory offset past the end falls back to the local headers", {
  # The end record's offset field is the 4 bytes before its comment length.
  z <- build_zip(ooxml_entries("word"))
  n <- length(z)
  z[(n - 5):(n - 2)] <- u32(99999)
  expect_identical(sniff_type(z), docx_type())
})

test_that("a ZIP missing one marker of a format stays the coarser type", {
  # An APK needs classes.dex; without it the manifest makes a JAR.
  expect_identical(
    sniff_type(build_zip(list(
      "AndroidManifest.xml" = "x",
      "META-INF/MANIFEST.MF" = "z"
    ))),
    "application/java-archive"
  )
  # OOXML folders need [Content_Types].xml.
  expect_identical(
    sniff_type(build_zip(list("word/document.xml" = "<w/>"))),
    "application/zip"
  )
  # The mimetype entry is read only when stored: here its local header says
  # deflated while its bytes still spell the type.
  epub <- list(mimetype = "application/epub+zip", "OEBPS/a.xhtml" = "<x/>")
  x <- build_zip(epub)
  x[9] <- as.raw(8)
  expect_identical(sniff_type(x), "application/zip")
})
