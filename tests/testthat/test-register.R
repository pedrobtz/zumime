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
  expect_gte(length(added), 200L)
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
