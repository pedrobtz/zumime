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
  expect_true(all(
    c("zumime_sniff.c", "zumime_table.c", "registry.c") %in%
      basename(src)
  ))
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
