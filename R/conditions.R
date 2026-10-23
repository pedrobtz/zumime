# Every condition inherits from zumime_error (design section 8); tests assert
# on the class, never on the message. The default `call` is the caller's, as
# in R/utils.R.
zumime_abort <- function(kind, message, call = sys.call(sys.parent())) {
  stop(structure(
    class = c(
      paste0("zumime_", kind, "_error"),
      "zumime_error",
      "error",
      "condition"
    ),
    list(message = message, call = call)
  ))
}

# A warning for a problem the answer survives, such as a registered rule
# that failed.
zumime_warn <- function(kind, message, call = sys.call(sys.parent())) {
  warning(structure(
    class = c(
      paste0("zumime_", kind, "_warning"),
      "zumime_warning",
      "warning",
      "condition"
    ),
    list(message = message, call = call)
  ))
}
