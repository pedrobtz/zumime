#' @keywords internal
"_PACKAGE"

## usethis namespace: start
#' @useDynLib zumime, .registration = TRUE
## usethis namespace: end
NULL

# Unload the library with the namespace, so a reload starts with an empty
# C registry to match the empty R one.
.onUnload <- function(libpath) {
  library.dynam.unload("zumime", libpath)
}
