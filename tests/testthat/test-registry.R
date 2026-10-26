test_that("mime_extensions() puts the canonical extension first", {
  expect_identical(mime_extensions("image/jpeg")[[1]][1], "jpg")
  expect_identical(mime_extensions("application/yaml")[[1]][1], "yaml")
  expect_identical(mime_extensions("application/pdf"), list("pdf"))
})

test_that("mime_extensions() resolves aliases, parameters and case", {
  expect_identical(
    mime_extensions("application/x-sqlite3"),
    mime_extensions("application/vnd.sqlite3")
  )
  expect_identical(
    mime_extensions("IMAGE/JPEG; q=0.9"),
    mime_extensions("image/jpeg")
  )
})

test_that("mime_extensions() gives character(0) for an unknown type", {
  expect_identical(
    mime_extensions(c("foo/bar", NA)),
    list(character(), character())
  )
})

test_that("registry functions reject a non-character argument", {
  expect_error(mime_extensions(1), class = "zumime_type_error")
  expect_error(mime_guess(list("a.pdf")), class = "zumime_type_error")
  expect_error(mime_parent(TRUE), class = "zumime_type_error")
  expect_error(mime_is("image/png", 3), class = "zumime_type_error")
  expect_error(mime_extensions(1), class = "zumime_error")
})

test_that("a type string in bytes encoding is an unknown type, not an error", {
  b <- "text/plain\xff"
  Encoding(b) <- "bytes"
  png <- as.raw(c(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a))
  expect_identical(mime_parse(b), list(NULL))
  expect_identical(mime_sniff(png, type = b)$type, "image/png")
  expect_identical(mime_finish(mime_sniffer(type = b))$type, "text/plain")
  expect_false(mime_is(b, "image"))
  expect_false(mime_check(png, b))
  expect_identical(mime_extensions(b), list(character()))
  expect_type(mime_parent(b), "list")
  expect_error(mime_register("text/x-zt-b", b), class = "zumime_registry_error")
})
