#' Build information
#'
#' Reports what this build of zumime contains: the package version and the
#' version of the generated type tables, which is the date of the upstream
#' sources they were built from.
#'
#' @return A list with `version`, the package version as a string, and
#'   `table_version`, the date of the table sources as a string
#'   (`"YYYY-MM-DD"`).
#' @export
#' @examples
#' zumime_info()
zumime_info <- function() {
  list(
    version = unname(getNamespaceVersion("zumime")),
    table_version = types_table_version
  )
}
