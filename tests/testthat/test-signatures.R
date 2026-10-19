# One generated input per signature row, built from the table itself: the
# pattern bytes (already masked) at the row's offset, zero fill, padded to
# the resource header length. Group codes follow enum zumime_sig_group.

test_that("every signature row matches an input generated from it", {
  rows <- .Call(zumime_signature_rows)
  # A floor, not a count: the standard's tables alone have more than 50
  # rows, so fewer means the table failed to load.
  expect_gt(length(rows$type), 50L)
  for (i in seq_along(rows$type)) {
    got <- sniff_row(rows, i, row_input(rows, i))
    expect_true(
      mime_is(got$type, rows$type[i]),
      info = paste(i, rows$type[i], got$type)
    )
    expect_identical(
      as.character(got$confidence),
      "definite",
      info = paste(i, rows$type[i])
    )
  }
})

test_that("case-insensitive rows match lower case and '>' terminates", {
  rows <- .Call(zumime_signature_rows)
  tt <- which(bitwAnd(rows$flags, 2L) != 0L)
  # The standard's tag-terminated rows: the 17 HTML tags of section 7.1.
  expect_length(tt, 17L)
  for (i in tt) {
    pat <- rows$pattern[[i]]
    folded <- ifelse(
      as.integer(rows$mask[[i]]) == 0xdf,
      as.integer(pat) + 32L,
      as.integer(pat)
    )
    folded[length(folded)] <- 0x3e
    bytes <- c(charToRaw(" \t\r\n"), as.raw(folded), charToRaw("x"))
    expect_identical(mime_sniff(bytes)$type, "text/html", info = i)
  }
})

test_that("a tar header with a bad checksum is not tar", {
  bytes <- c(tar_header(), raw(1024))
  bytes[149] <- charToRaw("7")
  expect_identical(mime_sniff(bytes)$type, "application/octet-stream")
  expect_identical(
    mime_sniff(c(tar_header(), raw(1024)))$type,
    "application/x-tar"
  )
})

test_that("an offset row is skipped for a raw vector shorter than its offset", {
  bytes <- raw(32774)
  bytes[32770:32774] <- charToRaw("CD001")
  expect_identical(
    mime_sniff(bytes, limit = 0)$type,
    "application/x-iso9660-image"
  )
  expect_identical(mime_sniff(bytes)$type, "application/octet-stream")
  expect_identical(
    mime_sniff(bytes[1:32770], limit = 0)$type,
    "application/octet-stream"
  )
})

test_that("zumime's own rows never override text", {
  expect_identical(mime_sniff(charToRaw("wOFF is a word"))$type, "text/plain")
  expect_identical(
    mime_sniff(charToRaw("BZh, said the bee"))$type,
    "text/plain"
  )
})
