test_that("mime_is() resolves aliases", {
  expect_true(mime_is("application/x-sqlite3", "application/vnd.sqlite3"))
  expect_true(mime_is("application/vnd.sqlite3", "application/x-sqlite3"))
})

test_that("mime_is() accepts a top-level type", {
  expect_true(mime_is("image/png", "image"))
  expect_false(mime_is("text/csv", "image"))
  expect_true(mime_is("Image/PNG; q=1", "IMAGE"))
})

test_that("mime_is() counts descendants", {
  docx <- "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
  expect_true(mime_is(docx, "application/zip"))
  expect_true(mime_is("image/svg+xml", "application/xml"))
  expect_true(mime_is("text/csv", "text/plain"))
  expect_false(mime_is("application/zip", docx))
})

test_that("mime_is() is vectorised over x and any-of over what", {
  expect_identical(
    mime_is(
      c("image/png", "application/pdf", NA, "foo/bar"),
      c("application/pdf", "image")
    ),
    c(TRUE, TRUE, NA, FALSE)
  )
})

test_that("everything is application/octet-stream", {
  expect_true(all(mime_is(
    c("image/png", "foo/bar", "text/plain"),
    "application/octet-stream"
  )))
})

test_that("mime_parent() gives the lineage nearest first", {
  expect_identical(
    mime_parent("image/svg+xml"),
    list(c("application/xml", "text/plain", "application/octet-stream"))
  )
  expect_identical(mime_parent("application/octet-stream"), list(character()))
  expect_identical(mime_parent("foo/bar"), list(NA_character_))
  expect_identical(
    mime_parent("application/x-sqlite3"),
    list("application/octet-stream")
  )
})
