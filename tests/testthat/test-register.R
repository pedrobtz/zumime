test_that("a data rule is detected at definite under its parent", {
  withr::defer(try(mime_unregister("application/x-zt-data"), silent = TRUE))
  mime_register("application/x-zt-data", "application/octet-stream",
    extensions = "ztd", rule = list(offset = 2, bytes = "ZT"))
  r <- mime_sniff(as.raw(c(1, 2, 0x5a, 0x54, 0)))
  expect_identical(r$type, "application/x-zt-data")
  expect_identical(as.character(r$confidence), "definite")
  expect_identical(mime_guess("x.ZTD"), "application/x-zt-data")
  expect_identical(mime_extensions("application/x-zt-data"), list("ztd"))
  types <- mime_types()
  expect_identical(types$detected_by[types$type == "application/x-zt-data"],
    "registered")
  expect_true(mime_is("application/x-zt-data", "application/octet-stream"))
  expect_identical(mime_parent("application/x-zt-data"),
    list("application/octet-stream"))
})

test_that("a mask and a registered parent are honoured", {
  withr::defer({
    try(mime_unregister("application/x-zt-child"), silent = TRUE)
    try(mime_unregister("application/x-zt-zip"), silent = TRUE)
  })
  mime_register("application/x-zt-zip", "application/zip",
    rule = list(offset = 30, bytes = "mimetypf", mask = as.raw(c(rep(0xff, 7), 0))))
  mime_register("application/x-zt-child", "application/x-zt-zip",
    rule = list(offset = 0, bytes = "PK"))
  z <- build_zip(list(mimetype = "x", b = "y"))
  expect_identical(mime_sniff(z)$type, "application/x-zt-child")
  expect_error(mime_unregister("application/x-zt-zip"),
    class = "zumime_registry_error")
})

test_that("a function rule runs last, at probable", {
  withr::defer(try(mime_unregister("text/x-zt-fn"), silent = TRUE))
  mime_register("text/x-zt-fn", "text/plain",
    rule = function(x) grepl("^MAGIC", rawToChar(x)))
  dir <- local_tree(list(a = "MAGIC words\n", b = "other\n"))
  r <- mime_type(file.path(dir, c("a", "b")))
  expect_identical(r$type, c("text/x-zt-fn", "text/plain"))
  expect_identical(as.character(r$confidence), c("probable", "probable"))
  expect_identical(mime_sniff(charToRaw("MAGIC"))$type, "text/x-zt-fn")
  expect_check_equivalence(file.path(dir, c("a", "b")),
    list("text/x-zt-fn", "text/plain"), c("probable", "definite"))
})

test_that("registering checks the type and the parent", {
  expect_error(mime_register("application/x-zt-a", "foo/unknown"),
    class = "zumime_registry_error")
  expect_error(mime_register("image/png", "application/octet-stream"),
    class = "zumime_registry_error")
  expect_error(mime_register("application/x-sqlite3", "application/octet-stream"),
    class = "zumime_registry_error")
  expect_error(mime_unregister("application/x-zt-never"),
    class = "zumime_registry_error")
  expect_error(mime_register("not a type", "text/plain"),
    class = "zumime_type_error")
  expect_error(mime_register("application/x-zt-b", "text/plain", rule = 1),
    class = "zumime_type_error")
  expect_error(mime_register("application/x-zt-b", "text/plain",
    rule = list(bytes = raw(65))), class = "zumime_type_error")
  expect_error(mime_register("application/x-zt-b", "text/plain",
    rule = list(bytes = "ab", mask = as.raw(1))), class = "zumime_type_error")
  expect_error(mime_register("application/x-zt-b", "text/plain",
    extensions = ""), class = "zumime_type_error")
})

test_that("registering twice fails and unregistering forgets", {
  withr::defer(try(mime_unregister("application/x-zt-twice"), silent = TRUE))
  mime_register("application/x-zt-twice", "application/octet-stream",
    rule = list(bytes = "ZZTW"))
  expect_error(mime_register("application/x-zt-twice", "text/plain"),
    class = "zumime_registry_error")
  mime_unregister("application/x-zt-twice")
  expect_identical(mime_sniff(c(charToRaw("ZZTW"), as.raw(0)))$type,
    "application/octet-stream")
  expect_false("application/x-zt-twice" %in% mime_types()$type)
})

test_that("a data rule cannot sit under a function-rule type", {
  withr::defer(try(mime_unregister("text/x-zt-fnparent"), silent = TRUE))
  withr::defer(try(mime_unregister("text/x-zt-datachild"), silent = TRUE))
  mime_register("text/x-zt-fnparent", "text/plain",
    rule = function(x) TRUE)
  expect_error(
    mime_register("text/x-zt-datachild", "text/x-zt-fnparent",
      rule = list(bytes = "hello")),
    class = "zumime_registry_error"
  )
  # A function rule under it is fine.
  mime_register("text/x-zt-datachild", "text/x-zt-fnparent",
    rule = function(x) grepl("hello", rawToChar(x)))
  expect_identical(mime_sniff(charToRaw("hello world"))$type,
    "text/x-zt-datachild")
})
