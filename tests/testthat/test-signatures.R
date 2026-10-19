# One generated input per signature row, built from the table itself: the
# pattern bytes (already masked) at the row's offset, zero fill, padded to
# the resource header length. Group codes follow enum zumime_sig_group.

sniff_row <- function(rows, i, bytes) {
  group <- rows$group[i]
  context <- if (group == 4L) "font" else "none"
  mime_sniff(bytes, context = context, limit = 0)
}

row_input <- function(rows, i) {
  off <- rows$offset[i]
  pat <- rows$pattern[[i]]
  if (bitwAnd(rows$flags[i], 4L) != 0L) {
    bytes <- c(tar_header(), raw(1024))
  } else {
    bytes <- raw(max(1445L, off + length(pat)))
    bytes[off + seq_along(pat)] <- pat
  }
  bytes
}

test_that("every signature row matches an input generated from it", {
  rows <- .Call(zumime_signature_rows)
  expect_gt(length(rows$type), 50L)
  for (i in seq_along(rows$type)) {
    got <- sniff_row(rows, i, row_input(rows, i))
    expect_true(mime_is(got$type, rows$type[i]),
      info = paste(i, rows$type[i], got$type))
    expect_identical(as.character(got$confidence), "definite", info = i)
  }
})

test_that("case-insensitive rows match lower case and '>' terminates", {
  rows <- .Call(zumime_signature_rows)
  tt <- which(bitwAnd(rows$flags, 2L) != 0L)
  expect_length(tt, 17L)
  for (i in tt) {
    pat <- rows$pattern[[i]]
    folded <- ifelse(as.integer(rows$mask[[i]]) == 0xdf,
      as.integer(pat) + 32L, as.integer(pat))
    folded[length(folded)] <- 0x3e
    bytes <- c(charToRaw(" \t\r\n"), as.raw(folded), charToRaw("x"))
    expect_identical(mime_sniff(bytes)$type, "text/html", info = i)
  }
})

test_that("a tar header with a bad checksum is not tar", {
  bytes <- c(tar_header(), raw(1024))
  bytes[149] <- charToRaw("7")
  expect_identical(mime_sniff(bytes)$type, "application/octet-stream")
  expect_identical(mime_sniff(c(tar_header(), raw(1024)))$type,
    "application/x-tar")
})

test_that("an offset row is skipped for a raw vector shorter than its offset", {
  bytes <- raw(32774)
  bytes[32770:32774] <- charToRaw("CD001")
  expect_identical(mime_sniff(bytes, limit = 0)$type,
    "application/x-iso9660-image")
  expect_identical(mime_sniff(bytes)$type, "application/octet-stream")
  expect_identical(mime_sniff(bytes[1:32770], limit = 0)$type,
    "application/octet-stream")
})

test_that("zumime's own rows never override text", {
  expect_identical(mime_sniff(charToRaw("wOFF is a word"))$type, "text/plain")
  expect_identical(mime_sniff(charToRaw("BZh, said the bee"))$type,
    "text/plain")
})
