# An argument error names the exported function that was called, whichever
# helper raised it and however lazily its argument was forced.

test_that("an argument error's call is the exported function", {
  caller <- function(expr) {
    e <- tryCatch(expr, zumime_error = identity)
    if (!inherits(e, "zumime_error")) {
      return("<no error>")
    }
    deparse(conditionCall(e)[[1]])
  }
  s <- mime_sniffer()
  calls <- c(
    mime_extensions = caller(mime_extensions(1)),
    mime_extensions = caller(mime_extensions(NULL)),
    mime_parent = caller(mime_parent(1)),
    mime_parent = caller(mime_parent(NULL)),
    mime_is = caller(mime_is(1, "a")),
    mime_is = caller(mime_is("a", 1)),
    mime_is = caller(mime_is("a", NULL)),
    mime_guess = caller(mime_guess(1)),
    mime_check = caller(mime_check(1, "image")),
    mime_check = caller(mime_check("a", 1)),
    mime_check = caller(mime_check("a", NULL)),
    mime_check = caller(mime_check("a", "image", "certain")),
    mime_parse = caller(mime_parse(1)),
    mime_parse = caller(mime_parse("a/b", strict = NA)),
    mime_sniff = caller(mime_sniff(1)),
    mime_sniff = caller(mime_sniff(raw(1), type = 1)),
    mime_sniff = caller(mime_sniff(raw(1), no_sniff = NA)),
    mime_sniff = caller(mime_sniff(raw(1), context = "x")),
    mime_sniff = caller(mime_sniff(raw(1), limit = -1)),
    mime_sniffer = caller(mime_sniffer(type = 1)),
    mime_sniffer = caller(mime_sniffer(no_sniff = 1)),
    mime_sniffer = caller(mime_sniffer(context = "x")),
    mime_sniffer = caller(mime_sniffer(limit = -1)),
    mime_push = caller(mime_push("x", raw(1))),
    mime_push = caller(mime_push(s, "x")),
    mime_finish = caller(mime_finish(list())),
    mime_type = caller(mime_type(1)),
    mime_type = caller(mime_type("a", limit = -1)),
    mime_type = caller(mime_type("a", complete = NA)),
    mime_type = caller(mime_type("a", strict = 1)),
    mime_type = caller(mime_type("a", inner = "zip")),
    mime_type = caller(mime_type("a", text = "x")),
    mime_type = caller(mime_type("a", charset = "x")),
    mime_register = caller(mime_register("not a type", "text/plain")),
    mime_register = caller(mime_register("application/x-zt-arg", 1)),
    mime_register = caller(
      mime_register("application/x-zt-arg", "text/plain", extensions = NA)
    ),
    mime_register = caller(
      mime_register("application/x-zt-arg", "text/plain", extensions = "")
    ),
    mime_register = caller(
      mime_register("application/x-zt-arg", "text/plain", rule = 1)
    ),
    mime_register = caller(
      mime_register("image/png", "application/octet-stream")
    ),
    mime_unregister = caller(mime_unregister(1)),
    mime_unregister = caller(mime_unregister("application/x-zt-never"))
  )
  expect_identical(unname(calls), names(calls))
  expect_false("application/x-zt-arg" %in% mime_types()$type)
})

test_that("a dependency and an io error's call is mime_type()", {
  dir <- withr::local_tempdir()
  path <- file.path(dir, "a.gz")
  writeBin(gzip_bytes("x"), path)
  local_mocked_bindings(has_package = function(pkg) FALSE)
  e <- tryCatch(
    mime_type(path, inner = "decompress"),
    zumime_dependency_error = identity
  )
  expect_identical(deparse(conditionCall(e)[[1]]), "mime_type")
  e <- tryCatch(
    mime_type(path, charset = "detect"),
    zumime_dependency_error = identity
  )
  expect_identical(deparse(conditionCall(e)[[1]]), "mime_type")
  e <- tryCatch(
    mime_type(file.path(dir, "nope"), strict = TRUE),
    zumime_io_error = identity
  )
  expect_identical(deparse(conditionCall(e)[[1]]), "mime_type")
})

test_that("NULL is not a character vector on any R version", {
  expect_error(mime_extensions(NULL), class = "zumime_type_error")
  expect_error(mime_parent(NULL), class = "zumime_type_error")
  expect_error(mime_guess(NULL), class = "zumime_type_error")
  expect_error(mime_is(NULL, "image"), class = "zumime_type_error")
  expect_error(mime_is("image/png", NULL), class = "zumime_type_error")
  expect_error(mime_check(raw(1), NULL), class = "zumime_type_error")
  expect_error(mime_parse(NULL), class = "zumime_type_error")
  # An all-NA logical is still taken as missing types.
  expect_identical(mime_is(NA, "image"), NA)
  expect_identical(mime_extensions(NA), list(character()))
})

test_that("the default limit is spelled out the same in every formal", {
  expect_identical(formals(mime_sniff)$limit, default_limit)
  expect_identical(formals(mime_type)$limit, default_limit)
  expect_identical(formals(mime_sniffer)$limit, default_limit)
})
