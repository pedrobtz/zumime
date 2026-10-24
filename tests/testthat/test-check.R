test_that("mime_check() answers from the bytes, never the name", {
  dir <- local_tree(list(photo.pdf = png_bytes(), real.pdf = pdf_bytes()))
  paths <- file.path(dir, c("photo.pdf", "real.pdf"))
  expect_identical(
    mime_check(paths, c("application/pdf", "image/jpeg")),
    c(FALSE, TRUE)
  )
  expect_identical(mime_check(paths, "image"), c(TRUE, FALSE))
  expect_true(mime_check(png_bytes(), "image/png"))
  expect_false(mime_check(png_bytes(), "application/pdf"))
})

test_that("min_confidence decides whether text heuristics count", {
  dir <- local_tree(list(a.json = "{\"a\": 1}"))
  p <- file.path(dir, "a.json")
  expect_true(mime_check(p, "application/json"))
  expect_false(mime_check(p, "application/json", min_confidence = "definite"))
})

test_that("descendants count and unreadable paths are not allowed", {
  dir <- local_tree(list(r.docx = build_zip(ooxml_entries("word"))))
  p <- file.path(dir, c("r.docx", "missing.pdf"))
  expect_identical(mime_check(p, "application/zip"), c(TRUE, FALSE))
  expect_identical(mime_check(p, "application/zip", "none"), c(TRUE, NA))
})

test_that("an allowlist of three types costs three probes", {
  # A GIF is related to none of the three, so each is probed once.
  dir <- local_tree(list(anim = c(charToRaw("GIF89a"), raw(10))))
  allowed <- c("application/pdf", "image/png", "image/jpeg")
  before <- probe_count()
  full <- full_pass_count()
  expect_false(mime_check(file.path(dir, "anim"), allowed))
  expect_identical(probe_count() - before, 3)
  # Refused at the gate: the readers never ran.
  expect_identical(full_pass_count() - full, 0)
  full <- full_pass_count()
  expect_false(mime_check(c(charToRaw("GIF89a"), raw(10)), allowed))
  expect_identical(full_pass_count() - full, 0)
  # A related input goes past it.
  expect_true(mime_check(c(charToRaw("GIF89a"), raw(10)), "image/gif"))
  expect_identical(full_pass_count() - full, 1)
  before <- probe_count()
  mime_check(rep(file.path(dir, "anim"), 4), allowed)
  expect_identical(probe_count() - before, 12)
})

test_that("mime_check() equals mime_type() for every subset of three types", {
  skip_if_gctorture()
  dir <- check_tree()
  paths <- c(list.files(dir, full.names = TRUE), file.path(dir, "missing"))
  sets <- utils::combn(check_candidates(), 3, simplify = FALSE)
  expect_check_equivalence(paths, sets, c("probable", "definite", "none"))
})

test_that("the equivalence holds over the file-type corpus", {
  skip_if_gctorture()
  dir <- fixture_dir("file-type")
  paths <- list.files(dir, full.names = TRUE)
  sets <- utils::combn(check_candidates(), 3, simplify = FALSE)
  expect_check_equivalence(paths, sets, c("probable", "definite"))
})

test_that("mime_check() rejects malformed arguments", {
  expect_error(mime_check(1, "image"), class = "zumime_type_error")
  expect_error(mime_check("a", 1), class = "zumime_type_error")
  expect_error(mime_check("a", "image", "certain"), class = "zumime_type_error")
  expect_error(mime_check("a", "image", NA), class = "zumime_type_error")
  # min_confidence has one default, so the whole set of levels is not one.
  expect_error(
    mime_check("a", "image", c("none", "extension", "probable", "definite")),
    class = "zumime_type_error"
  )
})

test_that("mime_check() reads only the head of a long raw vector", {
  x <- c(pdf_bytes(), raw(5000))
  expect_true(mime_check(x, "application/pdf"))
  late <- c(raw(5000), pdf_bytes())
  expect_false(mime_check(late, "application/pdf"))
})

test_that("an NA path is not allowed", {
  expect_identical(mime_check(NA_character_, "image"), FALSE)
  expect_identical(mime_check(NA_character_, "image", "none"), NA)
})
