test_that("every Go net/http sniff case agrees with the no-context path", {
  cases <- go_sniff_cases()
  for (i in seq_len(nrow(cases))) {
    got <- mime_sniff(hex_raw(cases$hex[i]))
    want <- mime_parse(cases$content_type[i])[[1]]
    want_type <- paste0(want$type, "/", want$subtype)
    # Both ways: equal up to aliases. One way alone, every negative case
    # would pass, since every type descends from application/octet-stream.
    expect_true(mime_is(got$type, want_type) && mime_is(want_type, got$type),
      info = paste(cases$desc[i], got$type))
    if (!is.null(want$parameters$charset)) {
      expect_identical(tolower(got$charset), tolower(want$parameters$charset),
        info = cases$desc[i])
    }
  }
})
