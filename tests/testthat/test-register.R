test_that("a data rule is detected at definite under its parent", {
  withr::defer(try(mime_unregister("application/x-zt-data"), silent = TRUE))
  mime_register(
    "application/x-zt-data",
    "application/octet-stream",
    extensions = "ztd",
    rule = list(offset = 2, bytes = "ZT")
  )
  r <- mime_sniff(as.raw(c(1, 2, 0x5a, 0x54, 0)))
  expect_identical(r$type, "application/x-zt-data")
  expect_identical(as.character(r$confidence), "definite")
  expect_identical(mime_guess("x.ZTD"), "application/x-zt-data")
  expect_identical(mime_extensions("application/x-zt-data"), list("ztd"))
  types <- mime_types()
  expect_identical(
    types$detected_by[types$type == "application/x-zt-data"],
    "registered"
  )
  expect_true(mime_is("application/x-zt-data", "application/octet-stream"))
  expect_identical(
    mime_parent("application/x-zt-data"),
    list("application/octet-stream")
  )
})

test_that("a mask and a registered parent are honoured", {
  withr::defer({
    try(mime_unregister("application/x-zt-child"), silent = TRUE)
    try(mime_unregister("application/x-zt-zip"), silent = TRUE)
  })
  mime_register(
    "application/x-zt-zip",
    "application/zip",
    rule = list(
      offset = 30,
      bytes = "mimetypf",
      mask = as.raw(c(rep(0xff, 7), 0))
    )
  )
  mime_register(
    "application/x-zt-child",
    "application/x-zt-zip",
    rule = list(offset = 0, bytes = "PK")
  )
  z <- build_zip(list(mimetype = "x", b = "y"))
  expect_identical(mime_sniff(z)$type, "application/x-zt-child")
  expect_error(
    mime_unregister("application/x-zt-zip"),
    class = "zumime_registry_error"
  )
})

test_that("a function rule runs last, at probable", {
  withr::defer(try(mime_unregister("text/x-zt-fn"), silent = TRUE))
  mime_register("text/x-zt-fn", "text/plain", rule = function(x) {
    grepl("^MAGIC", rawToChar(x))
  })
  dir <- local_tree(list(a = "MAGIC words\n", b = "other\n"))
  r <- mime_type(file.path(dir, c("a", "b")))
  expect_identical(r$type, c("text/x-zt-fn", "text/plain"))
  expect_identical(as.character(r$confidence), c("probable", "probable"))
  expect_identical(mime_sniff(charToRaw("MAGIC"))$type, "text/x-zt-fn")
  expect_check_equivalence(
    file.path(dir, c("a", "b")),
    list("text/x-zt-fn", "text/plain"),
    c("probable", "definite")
  )
})

test_that("registering checks the type and the parent", {
  # A regression that let one of these register would leak the type into
  # later tests.
  withr::defer({
    try(mime_unregister("application/x-zt-a"), silent = TRUE)
    try(mime_unregister("application/x-zt-b"), silent = TRUE)
  })
  expect_error(
    mime_register("application/x-zt-a", "foo/unknown"),
    class = "zumime_registry_error"
  )
  expect_error(
    mime_register("image/png", "application/octet-stream"),
    class = "zumime_registry_error"
  )
  expect_error(
    mime_register("application/x-sqlite3", "application/octet-stream"),
    class = "zumime_registry_error"
  )
  expect_error(
    mime_unregister("application/x-zt-never"),
    class = "zumime_registry_error"
  )
  expect_error(
    mime_register("not a type", "text/plain"),
    class = "zumime_type_error"
  )
  expect_error(
    mime_register("application/x-zt-b", "text/plain", rule = 1),
    class = "zumime_type_error"
  )
  expect_error(
    mime_register(
      "application/x-zt-b",
      "text/plain",
      rule = list(bytes = raw(65))
    ),
    class = "zumime_type_error"
  )
  expect_error(
    mime_register(
      "application/x-zt-b",
      "text/plain",
      rule = list(bytes = "ab", mask = as.raw(1))
    ),
    class = "zumime_type_error"
  )
  expect_error(
    mime_register("application/x-zt-b", "text/plain", extensions = ""),
    class = "zumime_type_error"
  )
})

test_that("registering twice fails and unregistering forgets", {
  withr::defer(try(mime_unregister("application/x-zt-twice"), silent = TRUE))
  mime_register(
    "application/x-zt-twice",
    "application/octet-stream",
    rule = list(bytes = "ZZTW")
  )
  expect_error(
    mime_register("application/x-zt-twice", "text/plain"),
    class = "zumime_registry_error"
  )
  mime_unregister("application/x-zt-twice")
  expect_identical(
    mime_sniff(c(charToRaw("ZZTW"), as.raw(0)))$type,
    "application/octet-stream"
  )
  expect_false("application/x-zt-twice" %in% mime_types()$type)
})

test_that("a data rule cannot sit under a function-rule type", {
  withr::defer(try(mime_unregister("text/x-zt-fnparent"), silent = TRUE))
  withr::defer(try(mime_unregister("text/x-zt-datachild"), silent = TRUE))
  mime_register("text/x-zt-fnparent", "text/plain", rule = function(x) TRUE)
  expect_error(
    mime_register(
      "text/x-zt-datachild",
      "text/x-zt-fnparent",
      rule = list(bytes = "hello")
    ),
    class = "zumime_registry_error"
  )
  # A function rule under it is fine.
  mime_register(
    "text/x-zt-datachild",
    "text/x-zt-fnparent",
    rule = function(x) grepl("hello", rawToChar(x))
  )
  expect_identical(
    mime_sniff(charToRaw("hello world"))$type,
    "text/x-zt-datachild"
  )
})

test_that("an over-long name and a full table are registry errors", {
  long <- paste0("application/x-", strrep("a", 130))
  expect_error(
    mime_register(long, "application/octet-stream"),
    class = "zumime_registry_error"
  )
  added <- character()
  withr::defer(
    for (t in added) {
      try(mime_unregister(t), silent = TRUE)
    }
  )
  full <- NULL
  for (i in 1:300) {
    t <- sprintf("application/x-zt-fill-%03d", i)
    full <- tryCatch(
      {
        mime_register(t, "application/octet-stream")
        NULL
      },
      zumime_registry_error = function(e) e
    )
    if (!is.null(full)) {
      break
    }
    added <- c(added, t)
  }
  expect_s3_class(full, "zumime_registry_error")
  expect_identical(length(added), 256L)
})

test_that("a function rule decides a stream at the limit", {
  withr::defer(try(mime_unregister("text/x-zt-stream"), silent = TRUE))
  mime_register("text/x-zt-stream", "text/plain", rule = function(x) {
    grepl("^MAGIC", rawToChar(x))
  })
  s <- mime_sniffer(limit = 16)
  expect_null(mime_push(s, charToRaw("MAGIC ")))
  expect_identical(
    mime_push(s, charToRaw("text and more"))$type,
    "text/x-zt-stream"
  )
})

test_that("a function rule under a binary parent holds a stream's decision", {
  gif <- c(charToRaw("GIF89a"), raw(20))
  withr::defer(try(mime_unregister("image/x-zt-gif"), silent = TRUE))
  mime_register("image/x-zt-gif", "image/gif", rule = function(x) TRUE)
  s <- mime_sniffer()
  expect_null(mime_push(s, gif))
  r <- mime_finish(s)
  expect_identical(r$type, "image/x-zt-gif")
  expect_identical(as.character(r$confidence), "probable")
  mime_unregister("image/x-zt-gif")
  expect_identical(mime_push(mime_sniffer(), gif)$type, "image/gif")
})

test_that("registration arguments are checked", {
  expect_error(
    mime_register("application/x-zt-c", 1),
    class = "zumime_type_error"
  )
  expect_error(mime_unregister(1), class = "zumime_type_error")
  expect_error(
    mime_register(
      "application/x-zt-c",
      "text/plain",
      extensions = NA_character_
    ),
    class = "zumime_type_error"
  )
  for (off in list(-1, 1.5, NA)) {
    expect_error(
      mime_register(
        "application/x-zt-c",
        "text/plain",
        rule = list(offset = off, bytes = "ab")
      ),
      class = "zumime_type_error"
    )
  }
  expect_false("application/x-zt-c" %in% mime_types()$type)
})

test_that("a namespace reload starts with an empty C registry", {
  skip_on_cran()
  pkg <- find.package("zumime")
  skip_if_not(dir.exists(file.path(pkg, "Meta")), "zumime is not installed")
  script <- withr::local_tempfile(fileext = ".R")
  writeLines(
    c(
      sprintf("library(zumime, lib.loc = %s)", deparse(dirname(pkg))),
      "b <- c(charToRaw('ZTRL'), raw(8))",
      "reg <- function() mime_register('application/x-zt-reload',",
      "  'application/octet-stream', rule = list(offset = 0, bytes = 'ZTRL'))",
      "reg()",
      "unloadNamespace('zumime')",
      sprintf("library(zumime, lib.loc = %s)", deparse(dirname(pkg))),
      "cat(mime_sniff(b)$type, '\\n')",
      "reg()",
      "mime_unregister('application/x-zt-reload')",
      "cat(mime_sniff(b)$type, '\\n')"
    ),
    script
  )
  out <- system2(
    file.path(R.home("bin"), "Rscript"),
    shQuote(script),
    stdout = TRUE
  )
  expect_identical(trimws(out), rep("application/octet-stream", 2L))
})

test_that("a built-in compound suffix beats a registered single one", {
  withr::defer(try(mime_unregister("application/x-zt-gz"), silent = TRUE))
  mime_register(
    "application/x-zt-gz",
    "application/octet-stream",
    extensions = c("gz", "zt.gz")
  )
  expect_identical(
    mime_guess(c("a.tar.gz", "a.csv.gz", "a.zt.gz", "a.gz")),
    c(
      mime_guess("a.tgz"),
      "application/x-zt-gz",
      "application/x-zt-gz",
      "application/x-zt-gz"
    )
  )
})

test_that("a failing function rule warns once and does not match", {
  withr::defer(try(mime_unregister("text/x-zt-broken"), silent = TRUE))
  mime_register("text/x-zt-broken", "text/plain", rule = function(x) {
    stop("bug in the rule")
  })
  dir <- local_tree(list(a.txt = "one\n", b.txt = "two\n", c.txt = "3\n"))
  # Counted, since expect_warning() passes on one warning of several.
  count_warnings <- function(expr) {
    n <- 0L
    value <- withCallingHandlers(
      expr,
      zumime_rule_warning = function(w) {
        n <<- n + 1L
        invokeRestart("muffleWarning")
      }
    )
    list(value = value, n = n)
  }
  t <- count_warnings(mime_type(file.path(dir, c("a.txt", "b.txt", "c.txt"))))
  expect_identical(t$n, 1L)
  expect_identical(t$value$type, rep("text/plain", 3L))
  r <- count_warnings(mime_sniff(charToRaw("hello")))
  expect_identical(r$n, 1L)
  expect_identical(r$value$type, "text/plain")
})

test_that("a rule under a directory never reads it", {
  withr::defer(try(mime_unregister("inode/x-zt-dir"), silent = TRUE))
  mime_register("inode/x-zt-dir", "inode/directory", rule = function(x) TRUE)
  dir <- withr::local_tempdir()
  t <- mime_type(dir)
  expect_identical(t$type, "inode/directory")
})

test_that("a file gone before R re-reads it gives no bytes", {
  path <- withr::local_tempfile()
  expect_null(read_bytes(path, 4096))
  writeBin(as.raw(1:10), path)
  expect_identical(read_bytes(path, 4), as.raw(1:4))
  expect_identical(read_bytes(path, 0), as.raw(1:10))
  expect_null(read_bytes(dirname(path), 4096))
})

test_that("the R-side passes skip a file gone before R re-reads it", {
  withr::defer(try(mime_unregister("text/x-zt-gone"), silent = TRUE))
  dir <- local_tree(list(
    a.txt = c(charToRaw("caf"), as.raw(0xe9), charToRaw("\n")),
    b.csv.gz = gzip_bytes("a,b\n1,2\n")
  ))
  p <- file.path(dir, c("a.txt", "b.csv.gz"))
  # A rule called on NULL would fail and warn: the #30 regression.
  mime_register("text/x-zt-gone", "text/plain", rule = function(x) {
    stopifnot(is.raw(x))
    TRUE
  })
  local_mocked_bindings(
    read_bytes = function(...) NULL,
    has_package = function(pkg) TRUE,
    suggested_fun = function(pkg, name) {
      switch(
        name,
        utf_detect = function(x) "Shift_JIS",
        komp_decompress = function(x, codec, max_output) png_bytes()
      )
    }
  )
  expect_no_warning(
    expect_no_error(
      t <- mime_type(p, inner = "decompress", charset = "detect")
    )
  )
  # Each pass keeps the C pass's answer: no rule, no zuutf, the name's inner.
  expect_identical(t$type, c("text/plain", "application/gzip"))
  expect_identical(t$charset[1], "ISO-8859-1")
  expect_identical(t$inner, c(NA_character_, "text/csv"))
})

test_that("a registered compound extension and an offset-only rule", {
  withr::defer(try(mime_unregister("application/x-zt-tar"), silent = TRUE))
  mime_register(
    "application/x-zt-tar",
    "application/octet-stream",
    extensions = "tar.zt"
  )
  expect_identical(mime_guess("a.tar.zt"), "application/x-zt-tar")
  expect_error(
    mime_register(
      "application/x-zt-off",
      "application/octet-stream",
      rule = list(offset = 1)
    ),
    class = "zumime_type_error"
  )
})

test_that("function rules run only in context none and not on a supplied type", {
  withr::defer(try(mime_unregister("text/x-zt-ctx"), silent = TRUE))
  mime_register("text/x-zt-ctx", "text/plain", rule = function(x) TRUE)
  x <- charToRaw("hello")
  expect_identical(mime_sniff(x)$type, "text/x-zt-ctx")
  expect_identical(mime_sniff(x, context = "browsing")$type, "text/plain")
  expect_identical(
    mime_sniff(x, type = "text/plain", no_sniff = TRUE)$type,
    "text/plain"
  )
  path <- withr::local_tempfile()
  writeBin(x, path)
  expect_identical(
    mime_sniff(path, type = "text/plain", no_sniff = TRUE)$type,
    "text/plain"
  )
  expect_identical(mime_sniff(path, context = "browsing")$type, "text/plain")
  s <- mime_sniffer(type = "text/plain", no_sniff = TRUE)
  mime_push(s, x)
  expect_identical(mime_finish(s)$type, "text/plain")
  s <- mime_sniffer(context = "browsing")
  mime_push(s, x)
  expect_identical(mime_finish(s)$type, "text/plain")
})

test_that("a data rule sees a type found past the head on every route", {
  withr::defer(try(mime_unregister("application/x-zt-iso"), silent = TRUE))
  x <- raw(40000)
  x[1:4] <- charToRaw("ZZZZ")
  x[32770:32774] <- charToRaw("CD001")
  path <- withr::local_tempfile()
  writeBin(x, path)
  expect_identical(mime_type(path)$type, "application/x-iso9660-image")
  mime_register(
    "application/x-zt-iso",
    "application/x-iso9660-image",
    rule = list(offset = 0, bytes = "ZZZZ")
  )
  expect_identical(mime_type(path)$type, "application/x-zt-iso")
  expect_identical(mime_type(path, limit = 0)$type, "application/x-zt-iso")
  expect_identical(mime_sniff(x, limit = 0)$type, "application/x-zt-iso")
  expect_true(mime_check(path, "application/x-zt-iso"))
})

test_that("a data rule under text/plain keeps a C1 guess probable on every route", {
  withr::defer(try(mime_unregister("text/x-zt-log"), silent = TRUE))
  mime_register(
    "text/x-zt-log",
    "text/plain",
    rule = list(offset = 0, bytes = "ZTLOG")
  )
  x <- c(charToRaw("ZTLOG caf"), as.raw(0xe9), charToRaw("\n"))
  path <- withr::local_tempfile()
  writeBin(x, path)
  s <- mime_sniffer()
  mime_push(s, x)
  routes <- list(
    mime_sniff(x),
    mime_sniff(path),
    mime_type(path),
    mime_finish(s)
  )
  for (r in routes) {
    expect_identical(r$type, "text/x-zt-log")
    expect_identical(as.character(r$confidence), "probable")
    expect_identical(r$charset, "ISO-8859-1")
  }
  expect_false(mime_check(x, "text/x-zt-log", min_confidence = "definite"))
  expect_false(mime_check(path, "text/x-zt-log", min_confidence = "definite"))
})

test_that("a data rule under text/html keeps the meta prescan on every route", {
  withr::defer(try(mime_unregister("text/x-zt-html"), silent = TRUE))
  mime_register(
    "text/x-zt-html",
    "text/html",
    rule = list(offset = 15, bytes = "<!--zt-->")
  )
  x <- c(
    charToRaw('<!DOCTYPE html><!--zt--><meta charset="koi8-r">caf'),
    as.raw(0xe9)
  )
  path <- withr::local_tempfile()
  writeBin(x, path)
  for (r in list(mime_sniff(x), mime_sniff(path))) {
    expect_identical(r$type, "text/x-zt-html")
    expect_identical(r$charset, "koi8-r")
  }
})

test_that("a rule under octet-stream does not pre-empt a type past the head", {
  withr::defer(try(mime_unregister("application/x-zt-any"), silent = TRUE))
  x <- raw(40000)
  x[1:4] <- charToRaw("ZZZZ")
  x[32770:32774] <- charToRaw("CD001")
  path <- withr::local_tempfile()
  writeBin(x, path)
  mime_register(
    "application/x-zt-any",
    "application/octet-stream",
    rule = list(offset = 0, bytes = "ZZZZ")
  )
  expect_identical(mime_sniff(x, limit = 0)$type, "application/x-iso9660-image")
  expect_identical(mime_type(path)$type, "application/x-iso9660-image")
  expect_identical(
    mime_type(path, limit = 0)$type,
    "application/x-iso9660-image"
  )
})

test_that("a function rule sees a type that text = \"family\" found", {
  withr::defer(try(mime_unregister("text/x-zt-idcsv"), silent = TRUE))
  dir <- local_tree(list(a = "id,name\n1,a\n2,b\n"))
  local_mocked_bindings(
    has_package = function(pkg) pkg == "zucsv",
    suggested_fun = function(pkg, name) {
      function(path, delimiter) list(ncol = 2L, nrow = 2L)
    }
  )
  mime_register("text/x-zt-idcsv", "text/csv", rule = function(x) {
    startsWith(rawToChar(x), "id,")
  })
  t <- mime_type(file.path(dir, "a"), text = "family")
  expect_identical(t$type, "text/x-zt-idcsv")
  expect_identical(as.character(t$confidence), "probable")
})

test_that("a stream does not wait for a data rule past its limit", {
  withr::defer(try(mime_unregister("image/x-zt-far"), silent = TRUE))
  gif <- c(charToRaw("GIF89a"), raw(100))
  expect_identical(mime_push(mime_sniffer(), gif)$type, "image/gif")
  mime_register(
    "image/x-zt-far",
    "image/gif",
    rule = list(offset = 100000, bytes = "Q")
  )
  expect_identical(mime_push(mime_sniffer(), gif)$type, "image/gif")
  s <- mime_sniffer(limit = 0)
  expect_null(mime_push(s, gif))
})

test_that("a function rule must take an argument", {
  expect_error(
    mime_register("text/x-zt-arity", "text/plain", rule = function() TRUE),
    class = "zumime_type_error"
  )
  expect_false("text/x-zt-arity" %in% mime_types()$type)
  withr::defer(try(mime_unregister("text/x-zt-dots"), silent = TRUE))
  mime_register("text/x-zt-dots", "text/plain", rule = function(...) FALSE)
  withr::defer(try(mime_unregister("text/x-zt-prim"), silent = TRUE))
  mime_register("text/x-zt-prim", "text/plain", rule = is.raw)
  expect_true(all(c("text/x-zt-dots", "text/x-zt-prim") %in% mime_types()$type))
})
