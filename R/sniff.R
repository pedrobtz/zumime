#' Sniff a type from bytes
#'
#' Runs the WHATWG MIME Sniffing Standard's "MIME type sniffing algorithm"
#' over the first bytes of a raw vector, with its three inputs: the
#' supplied type (a `Content-Type` value, or `NULL`), the no-sniff flag, and
#' the sniffing context.
#'
#' The `"browsing"` context is what a browser computes for a navigation:
#' the standard's tables and nothing else. The default `"none"` asks the
#' plain file question: the same algorithm, then zumime's own signatures
#' (compression wrappers, tar, ISO 9660, RAR 5, 7z, fonts, WebAssembly)
#' where the standard found only binary bytes. `"image"`, `"audio_video"`
#' and `"font"` are the standard's context-specific algorithms: they look
#' only for types of that kind and otherwise return the supplied type.
#'
#' A text result carries `charset`, from the first rule that answers: the
#' supplied type's `charset` parameter, a byte-order mark, an XML
#' declaration, an HTML `<meta>` prescan, valid UTF-8, then the C1 rule
#' (`windows-1252` when a byte in 0x80 to 0x9F appears, else
#' `ISO-8859-1`), which lowers `confidence` to `"probable"`.
#'
#' @param x A raw vector, or a character vector of paths, which are read as
#'   [mime_type()] reads them; an unreadable path gives a row with `type`
#'   `NA`.
#' @param type The supplied type, such as a `Content-Type` header value, or
#'   `NULL` when there is none. A value that does not parse as a MIME type
#'   is treated as `NULL`.
#' @param no_sniff `TRUE` for the no-sniff flag
#'   (`X-Content-Type-Options: nosniff`): a supplied type is then
#'   returned as is.
#' @param context One of `"none"`, `"browsing"`, `"image"`,
#'   `"audio_video"` or `"font"`.
#' @param limit The number of bytes to read; `0` reads them all. A raw
#'   vector longer than `limit` is sniffed on its first `limit` bytes.
#' @return A `zumime_result` data frame with one row per path (one for a
#'   raw vector) and columns `path` (`NA` for a raw vector), `type` (a
#'   canonical type), `confidence` (an ordered factor:
#'   `none < extension < probable < definite`), `charset`, `inner`,
#'   `encrypted`, `complete`, `newline` (`"lf"`, `"crlf"`, `"cr"`,
#'   `"mixed"`, or `NA`) and `interpreter`.
#' @references <https://mimesniff.spec.whatwg.org/>
#' @seealso [mime_parse()] for the supplied type's grammar.
#' @export
#' @examples
#' png <- as.raw(c(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a))
#' mime_sniff(png)
#' mime_sniff(charToRaw("<!DOCTYPE html><title>x</title>"))
#'
#' # A server that says text/plain about a binary file
#' mime_sniff(png, type = "text/plain")
#'
#' # The supplied type wins under nosniff
#' mime_sniff(png, type = "text/csv", no_sniff = TRUE)
mime_sniff <- function(
  x,
  type = NULL,
  no_sniff = FALSE,
  context = c("none", "browsing", "image", "audio_video", "font"),
  limit = 4096L
) {
  check_bytes_or_paths(x)
  supplied <- supplied_type(type)
  check_flag(no_sniff)
  context <- check_context(context)
  limit <- check_limit(limit)
  if (is.character(x)) {
    res <- sniff_paths(x, limit, FALSE, supplied, no_sniff, context)
    out <- path_result(x, res, supplied)
    return(apply_registered(out, x, limit, sniffed(res$type, context)))
  }

  res <- .Call(
    zumime_sniff_raw,
    x,
    limit,
    supplied$essence,
    supplied$apache_bug,
    no_sniff,
    context
  )
  names(res) <- raw_fields
  out <- raw_result(res, supplied)
  apply_registered(out, x, limit, sniffed(res$type, context))
}

# The rows zumime typed itself: context "none" and not a supplied type that
# stands, which C returns as NA. Registered rules refine only these, as the
# C side's data rules do.
sniffed <- function(type, context) {
  context == 0L & !is.na(type)
}

# The supplied MIME type detection algorithm's outcome: the canonical
# essence (NULL when undefined), its charset parameter, and the
# check-for-apache-bug flag.
supplied_type <- function(type, call = sys.call(sys.parent())) {
  none <- list(essence = NULL, charset = NULL, apache_bug = FALSE)
  if (is.null(type) || (length(type) == 1L && is.na(type))) {
    return(none)
  }
  if (!is.character(type) || length(type) != 1L) {
    zumime_abort(
      "type",
      "`type` must be a single string or NULL.",
      call = call
    )
  }
  apache_bug <- type %in%
    c(
      "text/plain",
      "text/plain; charset=ISO-8859-1",
      "text/plain; charset=iso-8859-1",
      "text/plain; charset=UTF-8"
    )
  rec <- mime_parse(type)[[1]]
  if (is.null(rec)) {
    return(none)
  }
  list(
    essence = canonical_type(paste0(rec$type, "/", rec$subtype)),
    charset = rec$parameters[["charset"]],
    apache_bug = apache_bug
  )
}

# The sniffing contexts in the C enum's order. The `context` defaults of
# mime_sniff() and mime_sniffer() spell out the same vector, so the usage
# shows the choices; keep the three in step.
contexts <- c("none", "browsing", "image", "audio_video", "font")

# The context as the C side's enum value.
check_context <- function(context, call = sys.call(sys.parent())) {
  context <- check_choice(context, contexts, call = call)
  match(context, contexts) - 1L
}
