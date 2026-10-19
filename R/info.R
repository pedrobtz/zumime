#' Build information
#'
#' Reports what this build of zumime contains: the package version and the
#' version of the generated type tables, which is the date of the upstream
#' sources they were built from.
#'
#' @return A list with `version`, the package version as a string;
#'   `table_version`, the date of the table sources as a string
#'   (`"YYYY-MM-DD"`); and `family`, the optional family packages this
#'   session can offer text to with `mime_type(text = "family")`. zutoml is
#'   not yet on CRAN; install it from GitHub.
#' @seealso [mime_type()] for the arguments that use the family.
#' @export
#' @examples
#' zumime_info()
zumime_info <- function() {
  list(
    version = unname(getNamespaceVersion("zumime")),
    table_version = types_table_version,
    # Listed without loading: an info call should not load three packages.
    family = family_packages[vapply(family_packages, is_installed, TRUE)]
  )
}
