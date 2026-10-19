# The result frame (design section 5, Results; D10): a plain data frame with
# a printing class.

confidence_levels <- c("none", "extension", "probable", "definite")

new_result <- function(path, type, confidence, charset = NA_character_,
                       inner = NA_character_, encrypted = NA,
                       complete = NA, newline = NA_character_,
                       interpreter = NA_character_) {
  n <- length(path)
  fill <- function(x) if (length(x) == n) x else rep_len(x, n)
  inner <- fill(inner)
  encrypted <- fill(encrypted)
  complete <- fill(complete)
  charset <- fill(charset)
  newline <- fill(newline)
  interpreter <- fill(interpreter)
  out <- data.frame(
    path = as.character(path),
    type = as.character(type),
    confidence = factor(confidence, levels = confidence_levels,
      ordered = TRUE),
    charset = as.character(charset),
    inner = as.character(inner),
    encrypted = as.logical(encrypted),
    complete = as.logical(complete),
    newline = as.character(newline),
    interpreter = as.character(interpreter),
    stringsAsFactors = FALSE
  )
  class(out) <- c("zumime_result", "data.frame")
  out
}

#' @export
print.zumime_result <- function(x, ...) {
  cat(sprintf("<zumime_result: %d row%s>\n", nrow(x),
    if (nrow(x) == 1L) "" else "s"))
  print(structure(x, class = "data.frame"), ...)
  invisible(x)
}
