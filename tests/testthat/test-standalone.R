test_that("the sniffer core compiles as C11 without R and without warnings", {
  root <- source_root()
  skip_if(is.null(root), "src/ is not available outside a source tree")
  skip_on_cran()
  cc <- Sys.which("cc")
  skip_if(!nzchar(cc), "no C compiler on the path")
  # The core is every source file that includes no R header.
  src <- list.files(
    file.path(root, "src"),
    pattern = "\\.c$",
    full.names = TRUE
  )
  uses_r <- vapply(
    src,
    function(f) {
      any(grepl("zumime_r\\.h|<R\\.h>|<Rinternals\\.h>", readLines(f)))
    },
    logical(1)
  )
  src <- src[!uses_r]
  # Every file of layers 1 to 3: one that gained an R header would
  # otherwise drop out of this check unseen.
  expect_setequal(
    basename(src),
    c(
      "registry.c",
      "zumime_bmff.c",
      "zumime_charset.c",
      "zumime_ebml.c",
      "zumime_inflate.c",
      "zumime_ogg.c",
      "zumime_ole2.c",
      "zumime_png.c",
      "zumime_rdata.c",
      "zumime_refine.c",
      "zumime_sniff.c",
      "zumime_stream.c",
      "zumime_table.c",
      "zumime_text.c",
      "zumime_zip.c"
    )
  )
  out <- withr::local_tempdir()
  for (f in src) {
    log <- suppressWarnings(system2(
      cc,
      c(
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-pedantic",
        "-DZUMIME_STANDALONE",
        "-c",
        shQuote(f),
        "-o",
        shQuote(file.path(out, sub("\\.c$", ".o", basename(f))))
      ),
      stdout = TRUE,
      stderr = TRUE
    ))
    expect_identical(log, character(), info = basename(f))
    expect_null(attr(log, "status"), info = basename(f))
  }
})
