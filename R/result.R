# The result frame (design section 5, Results; D10): a plain data frame with
# a printing class.

confidence_levels <- c("none", "extension", "probable", "definite")

as_confidence <- function(x) {
  factor(x, levels = confidence_levels, ordered = TRUE)
}

# The fields of the lists the C routines return, in their order.
# zumime_sniff_raw and zumime_stream_push: `supplied_charset` is TRUE when
# the answer is text, so a supplied charset parameter applies.
raw_fields <- c(
  "type",
  "confidence",
  "charset",
  "newline",
  "supplied_charset",
  "encrypted",
  "interpreter"
)
# zumime_sniff_paths: `error` is the reason a path could not be read.
path_fields <- c(
  "type",
  "confidence",
  "charset",
  "encrypted",
  "complete",
  "newline",
  "interpreter",
  "error"
)

# The one-row result for bytes in hand, from zumime_sniff_raw or
# zumime_stream_push, its elements named by `raw_fields`. A supplied type
# that stands comes back as NA.
raw_result <- function(res, supplied) {
  type <- res$type
  if (is.na(type)) {
    type <- supplied$essence
  }
  charset <- res$charset
  if (isTRUE(res$supplied_charset) && !is.null(supplied$charset)) {
    charset <- supplied$charset
  }
  new_result(
    path = NA_character_,
    type = type,
    confidence = res$confidence,
    charset = charset,
    encrypted = res$encrypted,
    newline = res$newline,
    interpreter = res$interpreter
  )
}

new_result <- function(
  path,
  type,
  confidence,
  charset = NA_character_,
  inner = NA_character_,
  encrypted = NA,
  complete = NA,
  newline = NA_character_,
  interpreter = NA_character_
) {
  n <- length(path)
  fill <- function(x) if (length(x) == n) x else rep_len(x, n)
  inner <- fill(inner)
  encrypted <- fill(encrypted)
  complete <- fill(complete)
  charset <- fill(charset)
  newline <- fill(newline)
  interpreter <- fill(interpreter)
  # Built directly: data.frame() costs more than the sniff itself.
  out <- list(
    path = as.character(path),
    type = as.character(type),
    confidence = as_confidence(confidence),
    charset = as.character(charset),
    inner = as.character(inner),
    encrypted = as.logical(encrypted),
    complete = as.logical(complete),
    newline = as.character(newline),
    interpreter = as.character(interpreter)
  )
  attr(out, "row.names") <- .set_row_names(n)
  class(out) <- c("zumime_result", "data.frame")
  out
}

#' @export
print.zumime_result <- function(x, ...) {
  cat(sprintf(
    "<zumime_result: %d row%s>\n",
    nrow(x),
    if (nrow(x) == 1L) "" else "s"
  ))
  print(structure(x, class = "data.frame"), ...)
  invisible(x)
}
