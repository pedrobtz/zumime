test_that("the sniffer core compiles as C11 without R and without warnings", {
  root <- source_root()
  skip_if(is.null(root), "src/ is not available outside a source tree")
  skip_on_cran()
  cc <- Sys.which("cc")
  skip_if(!nzchar(cc), "no C compiler on the path")
  src <- file.path(root, "src", c("zumime_sniff.c", "zumime_table.c",
    "zumime_text.c", "registry.c"))
  out <- withr::local_tempdir()
  for (f in src) {
    log <- suppressWarnings(system2(cc, c("-std=c11", "-Wall", "-Wextra",
      "-pedantic", "-DZUMIME_STANDALONE", "-c", shQuote(f), "-o",
      shQuote(file.path(out, sub("\\.c$", ".o", basename(f))))),
      stdout = TRUE, stderr = TRUE))
    expect_identical(log, character(), info = basename(f))
    expect_null(attr(log, "status"), info = basename(f))
  }
})
