#' Sniff a stream chunk by chunk
#'
#' `mime_sniffer()` starts an incremental sniffer; `mime_push()` hands it
#' the next chunk and returns `NULL` while the bytes seen cannot yet decide
#' the type, or the result row once they can. `mime_finish()` forces an
#' answer from what has been seen, as the end of a short stream would. The
#' answer is the one [mime_sniff()] gives for the same first `limit` bytes.
#'
#' Once the sniffer has decided, further pushes ignore their chunks and
#' return the same row. Once it has finished, a push raises a
#' `zumime_state_error`; `mime_finish()` can still be called and returns
#' the same row.
#'
#' The bytes decide when no longer signature could still override the
#' match, the container reader for the type has what it needs, or `limit`
#' bytes have arrived. Text decides only at `limit` or at the finish, since
#' a later byte can still change it. The tail-reading columns (`complete`)
#' are `NA` for a stream.
#'
#' The sniffer keeps its bytes in an R raw vector. A sniffer saved and
#' loaded again keeps those bytes but forgets its decision, and is
#' undecided until the next push.
#'
#' @inheritParams mime_sniff
#' @param s A sniffer from `mime_sniffer()`.
#' @param chunk A raw vector, the next bytes of the stream.
#' @return `mime_sniffer()` returns a `zumime_sniffer`. `mime_push()`
#'   returns `NULL` or a one-row `zumime_result`; `mime_finish()` always
#'   returns the result.
#' @seealso [mime_sniff()] for bytes in hand.
#' @export
#' @examples
#' s <- mime_sniffer()
#' mime_push(s, charToRaw("GIF8"))
#' mime_push(s, charToRaw("9a"))
#'
#' # Text waits for the limit or the finish.
#' t <- mime_sniffer(limit = 64)
#' mime_push(t, charToRaw("hello, "))
#' mime_finish(t)
mime_sniffer <- function(type = NULL, no_sniff = FALSE,
                         context = c("none", "browsing", "image",
                           "audio_video", "font"),
                         limit = 4096L) {
  supplied <- supplied_type(type)
  check_flag(no_sniff)
  context <- check_context(context)
  limit <- check_limit(limit)
  s <- .Call(zumime_stream_new, limit)
  attr(s, "params") <- list(supplied = supplied, no_sniff = no_sniff,
    context = context, limit = limit)
  class(s) <- "zumime_sniffer"
  s
}

#' @rdname mime_sniffer
#' @export
mime_push <- function(s, chunk) {
  check_sniffer(s)
  if (!is.raw(chunk)) {
    zumime_abort("type", "`chunk` must be a raw vector.")
  }
  if (stream_state(s)$state == "finished") {
    zumime_abort("state", "The sniffer is finished; start a new one.")
  }
  stream_result(s, chunk, final = FALSE)
}

#' @rdname mime_sniffer
#' @export
mime_finish <- function(s) {
  check_sniffer(s)
  stream_result(s, NULL, final = TRUE)
}

#' @export
print.zumime_sniffer <- function(x, ...) {
  st <- stream_state(x)
  p <- attr(x, "params")
  cat(sprintf("<zumime_sniffer: %s of %s bytes, %s>\n", format(st$n),
    if (p$limit > 0) format(p$limit) else "unlimited", st$state))
  invisible(x)
}

check_sniffer <- function(s) {
  if (!inherits(s, "zumime_sniffer") || typeof(s) != "externalptr") {
    zumime_abort("type", "`s` must be a sniffer from `mime_sniffer()`.",
      call = sys.call(-1L))
  }
}

stream_result <- function(s, chunk, final) {
  p <- attr(s, "params")
  fns <- session$types$parent[session$types$kind == "function"]
  res <- .Call(zumime_stream_push, s, chunk, final, p$limit,
    p$supplied$essence, p$supplied$apache_bug, p$no_sniff, p$context,
    as.character(fns))
  if (is.null(res)) return(NULL)
  out_type <- res[[1]]
  if (is.na(out_type)) out_type <- p$supplied$essence
  charset <- res[[3]]
  if (isTRUE(res[[5]]) && !is.null(p$supplied$charset)) {
    charset <- p$supplied$charset
  }
  out <- new_result(
    path = NA_character_,
    type = out_type,
    confidence = res[[2]],
    charset = charset,
    encrypted = res[[6]],
    newline = res[[4]],
    interpreter = res[[7]]
  )
  if (length(fns)) out <- apply_registered(out, stream_bytes(s), p$limit)
  out
}

# A sniffer's state, "undecided", "decided" or "finished", and the number
# of bytes it holds.
stream_state <- function(s) {
  st <- .Call(zumime_stream_state, s)
  list(state = c("undecided", "decided", "finished")[st[1]], n = st[2])
}

# The bytes a sniffer holds, for function rules.
stream_bytes <- function(s) {
  buf <- .Call(zumime_stream_buffer, s)
  buf[seq_len(stream_state(s)$n)]
}
