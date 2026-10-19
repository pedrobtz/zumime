#' Parse and serialise MIME types
#'
#' `mime_parse()` is the WHATWG MIME Sniffing Standard's "parse a MIME
#' type": type and subtype are lower-cased HTTP tokens; parameters keep
#' their order, names are lower-cased, quoted values are unescaped, and a
#' repeated name keeps its first value. `mime_format()` is "serialize a MIME
#' type", quoting a value that is empty or not a token.
#'
#' @param x A character vector of MIME types, such as `Content-Type`
#'   header values.
#' @param strict If `TRUE`, an input that fails to parse raises
#'   `zumime_parse_error` instead of giving `NULL`.
#' @return `mime_parse()` returns a list with one record per input: a list
#'   of `type`, `subtype` and `parameters` (a named list of strings), or
#'   `NULL` for input that fails to parse and for `NA`.
#'
#'   `mime_format()` returns a character vector, `NA` for a `NULL` record.
#' @references <https://mimesniff.spec.whatwg.org/#parsing-a-mime-type>
#' @export
#' @examples
#' rec <- mime_parse("Text/HTML; Charset=\"UTF-8\"; charset=latin1")
#' str(rec)
#' mime_format(rec)
#' mime_format(mime_parse("text/plain;name=\"a b\""))
#' mime_parse("not a type")
mime_parse <- function(x, strict = FALSE) {
  x <- check_character(x)
  if (!isTRUE(strict) && !isFALSE(strict)) {
    zumime_abort("type", "`strict` must be TRUE or FALSE.")
  }
  out <- .Call(zumime_mime_parse, utf8_or_replace(x))
  if (strict) {
    bad <- which(vapply(out, is.null, logical(1)) & !is.na(x))
    if (length(bad)) {
      zumime_abort(
        "parse",
        sprintf(
          "Input %d is not a valid MIME type: \"%s\".",
          bad[1],
          x[bad[1]]
        )
      )
    }
  }
  out
}

#' @param record One record from `mime_parse()`, or a list of them.
#' @rdname mime_parse
#' @export
mime_format <- function(record) {
  if (is_record(record)) {
    record <- list(record)
  }
  if (
    !is.list(record) ||
      !all(vapply(record, function(r) is.null(r) || is_record(r), TRUE))
  ) {
    zumime_abort(
      "type",
      "`record` must be a record from `mime_parse()` or a list of them."
    )
  }
  record <- lapply(record, function(r) {
    if (is.null(r)) {
      return(NULL)
    }
    p <- r$parameters
    list(
      enc2utf8(r$type),
      enc2utf8(r$subtype),
      structure(
        lapply(p, enc2utf8),
        names = enc2utf8(names(p) %||% character())
      )
    )
  })
  .Call(zumime_mime_format, record)
}

is_record <- function(r) {
  is.list(r) &&
    !is.null(r$type) &&
    is_string(r$type) &&
    is_string(r$subtype) &&
    is.list(r$parameters) &&
    all(vapply(r$parameters, is_string, TRUE)) &&
    (length(r$parameters) == 0L || !is.null(names(r$parameters)))
}

is_string <- function(x) is.character(x) && length(x) == 1L && !is.na(x)

`%||%` <- function(x, y) if (is.null(x)) y else x

# x in UTF-8 for the parser. enc2utf8() turns a byte the native encoding
# cannot hold into the text "<c3>", which then parses as a value; the
# standard decodes it to U+FFFD, which no token or value may hold.
utf8_or_replace <- function(x) {
  bad <- !is.na(x) & Encoding(x) == "unknown" & !validUTF8(x)
  # U+FFFD as bytes: as a string it would be translated to the native
  # encoding, which may not hold it.
  fffd <- rawToChar(as.raw(c(0xef, 0xbf, 0xbd)))
  x[bad] <- iconv(x[bad], "", "UTF-8", sub = fffd)
  Encoding(x[bad]) <- "UTF-8"
  enc2utf8(x)
}
