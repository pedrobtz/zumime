test_that("gzip header fields are skipped before the RDS header", {
  rds <- c(charToRaw("X\n"), as.raw(c(0, 0, 0, 3)), raw(20))
  d <- deflate_raw(rds)
  for (args in list(list(name = "x.rds"), list(comment = "saved"),
    list(extra = as.raw(1:6)), list(hcrc = TRUE),
    list(extra = as.raw(1:2), name = "x", comment = "c", hcrc = TRUE))) {
    g <- do.call(gzip_member, c(list(d, length(rds)), args))
    expect_identical(mime_sniff(g)$type, "application/x-rds",
      info = paste(names(args), collapse = "+"))
  }
})

test_that("complete = TRUE follows header fields and concatenated members", {
  text <- charToRaw("a,b\n1,2\n")
  one <- gzip_member(deflate_raw(text), length(text), name = "data.csv")
  dir <- local_tree(list(
    "named.csv.gz" = one,
    "two.csv.gz" = c(one, gzip_bytes("3,4\n")),
    "padded.csv.gz" = c(one, raw(16)),
    "junk.csv.gz" = c(one, charToRaw("not gzip")),
    "wrong-size.csv.gz" = gzip_member(deflate_raw(text), 99, name = "x")
  ))
  names <- c("named.csv.gz", "two.csv.gz", "padded.csv.gz", "junk.csv.gz",
    "wrong-size.csv.gz")
  t <- mime_type(file.path(dir, names), complete = TRUE)
  expect_identical(t$type, rep("application/gzip", 5))
  expect_identical(t$complete, c(TRUE, TRUE, TRUE, FALSE, FALSE))
})

test_that("complete = TRUE skips FEXTRA, FCOMMENT and FHCRC", {
  text <- charToRaw("a,b\n1,2\n")
  d <- deflate_raw(text)
  members <- list(
    extra = gzip_member(d, length(text), extra = as.raw(1:6)),
    comment = gzip_member(d, length(text), comment = "saved by pigz"),
    hcrc = gzip_member(d, length(text), hcrc = TRUE),
    all = gzip_member(d, length(text), extra = as.raw(1:2), name = "x",
      comment = "c", hcrc = TRUE)
  )
  files <- stats::setNames(members, paste0(names(members), ".csv.gz"))
  dir <- local_tree(files)
  t <- mime_type(file.path(dir, names(files)), complete = TRUE)
  expect_identical(t$type, rep("application/gzip", 4))
  expect_identical(t$complete, rep(TRUE, 4))
})

test_that("malformed DEFLATE is incomplete and not an R file", {
  rds_size <- 26
  # A stored block whose NLEN is not the complement of LEN.
  bad_stored <- c(as.raw(1), u16(5), u16(0), charToRaw("hello"))
  # A dynamic block whose code-length code is over-subscribed: 19 codes of
  # length 1.
  bits <- c(1L, 0L, 1L, rep(0L, 5), rep(0L, 5), c(1L, 1L, 1L, 1L),
    rep(c(1L, 0L, 0L), 19))
  bad_dynamic <- pack_bits(bits)
  # A fixed-code block whose first symbol is a match: the distance reaches
  # before the start of the output.
  bad_distance <- pack_bits(c(1L, 1L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 1L,
    rep(0L, 5), rep(0L, 16)))
  dir <- local_tree(list(
    "a.gz" = gzip_member(bad_stored, 5),
    "b.gz" = gzip_member(bad_dynamic, rds_size),
    "c.gz" = gzip_member(bad_distance, rds_size)
  ))
  t <- mime_type(file.path(dir, c("a.gz", "b.gz", "c.gz")), complete = TRUE)
  expect_identical(t$type, rep("application/gzip", 3))
  expect_identical(t$complete, c(FALSE, FALSE, FALSE))
})
