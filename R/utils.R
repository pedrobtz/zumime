# Helpers used across files: argument checks, optional packages, and two
# small utilities.
#
# Each check names its caller with `call = sys.call(sys.parent())`: the
# call of the frame the check was called from, not of the frame below it on
# the stack (`sys.call(-1L)`). So the call is right even when the check is
# an argument forced inside another function, as in
# `canonical_type(check_character(x))`. A helper that checks for an exported
# function passes that function's call on as `call`.

# A character vector, or an atomic vector of NAs (missing types). NULL is
# not one, on every R version: is.atomic(NULL) changed in R 4.4.0.
check_character <- function(
  x,
  arg = deparse(substitute(x)),
  call = sys.call(sys.parent())
) {
  if (is.null(x) || !(is.character(x) || (is.atomic(x) && all(is.na(x))))) {
    zumime_abort(
      "type",
      sprintf("`%s` must be a character vector.", arg),
      call = call
    )
  }
  as.character(x)
}

check_flag <- function(
  x,
  arg = deparse(substitute(x)),
  call = sys.call(sys.parent())
) {
  if (!isTRUE(x) && !isFALSE(x)) {
    zumime_abort(
      "type",
      sprintf("`%s` must be TRUE or FALSE.", arg),
      call = call
    )
  }
}

check_limit <- function(limit, call = sys.call(sys.parent())) {
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
      call = call
    )
  }
  as.double(limit)
}

# One of `choices`. With `vector_default`, the whole of `choices` is the
# formal's default, as for match.arg(), and stands for the first.
check_choice <- function(
  x,
  choices,
  vector_default = TRUE,
  arg = deparse(substitute(x)),
  call = sys.call(sys.parent())
) {
  if (vector_default && identical(x, choices)) {
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

need_package <- function(pkg, what, call = sys.call(sys.parent())) {
  if (!has_package(pkg)) {
    zumime_abort(
      "dependency",
      sprintf(
        "`%s` needs the %s package, which is not installed.",
        what,
        pkg
      ),
      call = call
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
