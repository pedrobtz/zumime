test_that("gzip header fields are skipped before the RDS header", {
  rds <- c(charToRaw("X\n"), as.raw(c(0, 0, 0, 3)), raw(20))
  d <- deflate_raw(rds)
  for (args in list(
    list(name = "x.rds"),
    list(comment = "saved"),
    list(extra = as.raw(1:6)),
    list(hcrc = TRUE),
    list(extra = as.raw(1:2), name = "x", comment = "c", hcrc = TRUE)
  )) {
    g <- do.call(gzip_member, c(list(d, length(rds)), args))
    expect_identical(
      mime_sniff(g)$type,
      "application/x-rds",
      info = paste(names(args), collapse = "+")
    )
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
  names <- c(
    "named.csv.gz",
    "two.csv.gz",
    "padded.csv.gz",
    "junk.csv.gz",
    "wrong-size.csv.gz"
  )
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
    all = gzip_member(
      d,
      length(text),
      extra = as.raw(1:2),
      name = "x",
      comment = "c",
      hcrc = TRUE
    )
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
  bits <- c(
    1L,
    0L,
    1L,
    rep(0L, 5),
    rep(0L, 5),
    c(1L, 1L, 1L, 1L),
    rep(c(1L, 0L, 0L), 19)
  )
  bad_dynamic <- pack_bits(bits)
  # A fixed-code block whose first symbol is a match: the distance reaches
  # before the start of the output.
  bad_distance <- pack_bits(c(
    1L,
    1L,
    0L,
    0L,
    0L,
    0L,
    0L,
    0L,
    0L,
    1L,
    rep(0L, 5),
    rep(0L, 16)
  ))
  dir <- local_tree(list(
    "a.gz" = gzip_member(bad_stored, 5),
    "b.gz" = gzip_member(bad_dynamic, rds_size),
    "c.gz" = gzip_member(bad_distance, rds_size)
  ))
  t <- mime_type(file.path(dir, c("a.gz", "b.gz", "c.gz")), complete = TRUE)
  expect_identical(t$type, rep("application/gzip", 3))
  expect_identical(t$complete, c(FALSE, FALSE, FALSE))
})

test_that("every other DEFLATE error branch is incomplete", {
  # A field of n bits, least significant first, as the inflater reads it.
  field <- function(value, n) as.integer(bitwAnd(value, 2^(seq_len(n) - 1)) > 0)
  # Huffman code bits, most significant first.
  code <- function(x) as.integer(strsplit(x, "")[[1]])
  # A final dynamic block header and its code-length code lengths, given in
  # the standard's order (16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3,
  # 13, 2, 14, 1, 15).
  dynamic <- function(hlit, hdist, cl) {
    c(
      1L,
      field(2, 2),
      field(hlit, 5),
      field(hdist, 5),
      field(length(cl) - 4, 4),
      unlist(lapply(cl, field, n = 3))
    )
  }
  # 18 then 7 bits: a run of 11 to 138 zero lengths.
  zeros <- function(prefix, n) c(code(prefix), field(n - 11, 7))
  # Code-length code {0: "10", 2: "11", 18: "0"}.
  cl_0_2_18 <- c(0, 0, 1, 2, rep(0, 11), 2)
  # Code-length code {0: "10", 1: "11", 18: "0"}.
  cl_0_1_18 <- c(0, 0, 1, 2, rep(0, 13), 2)
  streams <- list(
    # Block type 3 is reserved.
    reserved = c(1L, 1L, 1L),
    # Fixed code 11000110 is length symbol 286, which has no meaning.
    length_286 = c(1L, field(1, 2), code("11000110")),
    # HLIT = 30 asks for 287 literal/length codes.
    hlit_287 = dynamic(30, 0, c(1, 0, 0, 1)),
    # Code-length code {0: "0", 16: "1"}: a repeat with nothing to repeat.
    repeat_first = c(dynamic(0, 0, c(1, 0, 0, 1)), 1L),
    # Two runs of 138 zeros overrun the 258 lengths.
    run_overrun = c(
      dynamic(0, 0, c(0, 0, 1, 1)),
      code("1"),
      field(127, 7),
      code("1"),
      field(127, 7)
    ),
    # 258 zero lengths: no end-of-block code.
    no_end_of_block = c(
      dynamic(0, 0, c(0, 0, 1, 1)),
      code("1"),
      field(127, 7),
      code("1"),
      field(109, 7)
    ),
    # Literals 0 and 256 of length 2: an incomplete code of two symbols.
    incomplete = c(
      dynamic(0, 0, cl_0_2_18),
      code("11"),
      zeros("0", 138),
      zeros("0", 117),
      code("11"),
      code("11")
    ),
    # Only 256 has a code, "0"; the data reads "1" and 14 zeros, which no
    # code of up to 15 bits matches.
    no_code = c(
      dynamic(0, 0, cl_0_1_18),
      zeros("0", 138),
      zeros("0", 118),
      code("11"),
      code("11"),
      1L,
      rep(0L, 14)
    )
  )
  members <- lapply(streams, function(b) gzip_member(pack_bits(b), 26))
  header <- gzip_member(raw(), 0)[1:10]
  # A stored block cut inside its header, and one cut inside its data.
  members$stored_header <- c(header, as.raw(c(1, 100)))
  members$stored_data <- c(
    header,
    as.raw(1),
    u16(100),
    u16(65435),
    charToRaw("hello")
  )
  files <- stats::setNames(members, paste0(names(members), ".gz"))
  dir <- local_tree(files)
  t <- mime_type(file.path(dir, names(files)), complete = TRUE)
  expect_identical(t$type, rep("application/gzip", length(files)))
  expect_identical(t$complete, rep(FALSE, length(files)), info = names(files))
})
