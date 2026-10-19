test_that("every Go net/http sniff case agrees with the no-context path", {
  cases <- go_sniff_cases()
  for (i in seq_len(nrow(cases))) {
    got <- mime_sniff(hex_raw(cases$hex[i]))
    want <- mime_parse(cases$content_type[i])[[1]]
    want_type <- paste0(want$type, "/", want$subtype)
    expect_true(mime_is(got$type, want_type), info = cases$desc[i])
    if (!is.null(want$parameters$charset)) {
      expect_identical(tolower(got$charset), tolower(want$parameters$charset),
        info = cases$desc[i])
    }
  }
})
