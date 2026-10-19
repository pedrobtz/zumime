# Directory of a fetched oracle corpus (tools/fetch-fixtures), skipping the
# calling test when it is absent.
fixture_dir <- function(name) {
  dir <- test_path("fixtures", name)
  if (!dir.exists(dir)) {
    msg <- paste0("fixtures/", name, " not fetched; run tools/fetch-fixtures")
    require_oracles(msg)
    skip(msg)
  }
  dir
}

# The oracles job (oracles.yaml) sets ZUMIME_REQUIRE_ORACLES=true: there a
# missing fixture directory or source tree is a failure, not a skip, so a
# broken fetch cannot turn the job into skips that stay green.
require_oracles <- function(msg) {
  if (identical(Sys.getenv("ZUMIME_REQUIRE_ORACLES"), "true")) {
    stop(msg, call. = FALSE)
  }
}

# The WPT mime-types entries as a list of list(input, output). An input
# holding U+0000 cannot be an R string, so those entries are dropped and
# counted in attr(, "dropped").
wpt_mime_entries <- function(file) {
  skip_if_not_installed("jsonlite")
  text <- paste(readLines(file, warn = FALSE, encoding = "UTF-8"),
    collapse = "\n")
  text <- gsub("\\u0000", "<<NUL>>", text, fixed = TRUE)
  entries <- Filter(is.list, jsonlite::fromJSON(text, simplifyVector = FALSE))
  nul <- vapply(entries, function(e) grepl("<<NUL>>", e$input, fixed = TRUE),
    logical(1))
  structure(entries[!nul], dropped = sum(nul))
}
