# The package source root when the tests run from a source tree
# (devtools::test()), or NULL from an installed package, where tools/ is
# not shipped.
source_root <- function() {
  root <- normalizePath(test_path("..", ".."), mustWork = FALSE)
  if (file.exists(file.path(root, "tools", "generate-tables.R"))) root else NULL
}
