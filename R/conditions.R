# Every condition inherits from zumime_error (design section 8); tests assert
# on the class, never on the message. The default `call` is the caller's, as
# in R/utils.R.
zumime_abort <- function(kind, message, call = sys.call(sys.parent())) {
  stop(zumime_condition(kind, "error", message, call))
}

# A warning for a problem the answer survives, such as a registered rule
# that failed.
zumime_warn <- function(kind, message, call = sys.call(sys.parent())) {
  warning(zumime_condition(kind, "warning", message, call))
}

# A condition of class zumime_<kind>_<type>, zumime_<type>, <type>.
zumime_condition <- function(kind, type, message, call) {
  structure(
    list(message = message, call = call),
    class = c(
      paste0("zumime_", kind, "_", type),
      paste0("zumime_", type),
      type,
      "condition"
    )
  )
}
