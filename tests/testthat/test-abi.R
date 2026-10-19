test_that("the shared object exports R_init_zumime only", {
  skip_if(
    is_instrumented_build(),
    "instrumented build: its runtime exports symbols of its own"
  )
  names <- sub("^.*[[:space:]]", "", exported_symbols())
  names <- sub("^_", "", names)
  expect_identical(sort(names), "R_init_zumime")
})
