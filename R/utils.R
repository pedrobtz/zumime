# Helpers used across files: argument checks, optional packages, and two
# small utilities.

check_character <- function(x, arg = deparse(substitute(x))) {
  if (!is.character(x) && !(is.atomic(x) && all(is.na(x)))) {
    zumime_abort(
      "type",
      sprintf("`%s` must be a character vector.", arg),
      call = sys.call(-1L)
    )
  }
  as.character(x)
}

check_flag <- function(x, arg = deparse(substitute(x))) {
  if (!isTRUE(x) && !isFALSE(x)) {
    zumime_abort(
      "type",
      sprintf("`%s` must be TRUE or FALSE.", arg),
      call = sys.call(-1L)
    )
  }
}

check_limit <- function(limit) {
  if (
    !is.numeric(limit) ||
      length(limit) != 1L ||
      is.na(limit) ||
      limit < 0 ||
      limit > .Machine$integer.max ||
      limit != floor(limit)
  ) {
    zumime_abort(
      "type",
      "`limit` must be a whole number from 0 to .Machine$integer.max.",
      call = sys.call(-1L)
    )
  }
  as.double(limit)
}

check_choice <- function(
  x,
  choices,
  arg = deparse(substitute(x)),
  call = sys.call(-1L)
) {
  if (identical(x, choices)) {
    return(choices[1])
  }
  if (!is.character(x) || length(x) != 1L || !(x %in% choices)) {
    zumime_abort(
      "type",
      sprintf(
        "`%s` must be one of %s.",
        arg,
        paste0("\"", choices, "\"", collapse = ", ")
      ),
      call = call
    )
  }
  x
}

need_package <- function(pkg, what) {
  if (!has_package(pkg)) {
    zumime_abort(
      "dependency",
      sprintf(
        "`%s` needs the %s package, which is not installed.",
        what,
        pkg
      ),
      call = sys.call(-1L)
    )
  }
}

# The one place a suggested package is looked up, so tests can stand in for
# packages CI does not install (zuutf and zutoml are not on CRAN).
has_package <- function(pkg) requireNamespace(pkg, quietly = TRUE)

suggested_fun <- function(pkg, name) getExportedValue(pkg, name)

# Installed, without loading it: for reports such as zumime_info().
is_installed <- function(pkg) nzchar(system.file(package = pkg))

is_string <- function(x) is.character(x) && length(x) == 1L && !is.na(x)

`%||%` <- function(x, y) if (is.null(x)) y else x
