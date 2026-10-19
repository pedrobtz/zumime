#' Is a file one of these types?
#'
#' The upload question: `TRUE` when the bytes say the file is one of
#' `allowed`, or a descendant of one, at `min_confidence` or better. The name
#' is never consulted, since the question exists because names lie.
#'
#' The answer always equals
#' `mime_is(t$type, allowed) & t$confidence >= min_confidence`, with
#' `t <- mime_type(x)`, or `mime_sniff(x)` for a raw vector. It is computed
#' in one pass, with a shortcut that this equality hides. The container
#' readers, text readers and tail reads are skipped for every input whose
#' first answer could not end as an allowed type. No result frame is built.
#' Call [mime_type()] to learn why a file was refused.
#'
#' @param x A raw vector, or a character vector of paths.
#' @param allowed A character vector of types, aliases or top-level types,
#'   as [mime_is()] takes them.
#' @param min_confidence The weakest evidence accepted: `"probable"` (the
#'   default) accepts byte evidence of either kind; `"definite"` is for
#'   allowlists that must not trust a text heuristic. `"extension"` and
#'   `"none"` are accepted for completeness.
#' @return A logical vector, one element per path (one for a raw vector);
#'   `FALSE` for an unreadable path unless `min_confidence` is `"none"`,
#'   where it is `NA`.
#' @seealso [mime_type()] for the full answer.
#' @export
#' @examples
#' dir <- tempfile()
#' dir.create(dir)
#' png <- as.raw(c(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a))
#' writeBin(png, file.path(dir, "photo.pdf"))
#' writeLines("%PDF-1.7", file.path(dir, "real.pdf"))
#' paths <- file.path(dir, c("photo.pdf", "real.pdf"))
#' mime_check(paths, c("application/pdf", "image/jpeg"))
#' mime_check(png, "image")
#' unlink(dir, recursive = TRUE)
mime_check <- function(x, allowed, min_confidence = "probable") {
  if (!is.character(x) && !is.raw(x)) {
    zumime_abort(
      "type",
      "`x` must be a raw vector or a character vector of paths."
    )
  }
  allowed <- check_character(allowed)
  if (
    !is.character(min_confidence) ||
      length(min_confidence) != 1L ||
      !(min_confidence %in% confidence_levels)
  ) {
    zumime_abort(
      "type",
      sprintf(
        "`min_confidence` must be one of %s.",
        paste0("\"", confidence_levels, "\"", collapse = ", ")
      )
    )
  }
  m <- factor(min_confidence, levels = confidence_levels, ordered = TRUE)
  limit <- 4096

  # Function rules run in R after the C pass, so the shortcut cannot see
  # them; answer in full.
  if (any(session$types$kind == "function")) {
    t <- if (is.raw(x)) mime_sniff(x) else mime_type(x)
    return(mime_is(t$type, allowed) & t$confidence >= m)
  }

  sets <- related_sets(allowed)
  out <- .Call(
    zumime_check,
    x,
    limit,
    lapply(sets, `[[`, "related"),
    lapply(sets, `[[`, "within"),
    match(min_confidence, confidence_levels) - 1L
  )
  # An unreadable path is type NA at confidence "none".
  unreadable <- factor("none", levels = confidence_levels, ordered = TRUE)
  out[is.na(out)] <- NA & (unreadable >= m)
  out
}

# For each allowed type, two sorted vectors of C ids: `related`, the types
# an input's first answer may have and still end as that type (the types
# within it, their ancestors, and gzip for R's own formats); and `within`,
# the types that are it or descend from it.
related_sets <- function(allowed) {
  if (!identical(session$related_version, session$version)) {
    session$related <- new.env(parent = emptyenv())
    session$related_version <- session$version
  }
  lapply(allowed, function(a) {
    key <- if (is.na(a)) "\rNA" else a
    hit <- session$related[[key]]
    if (!is.null(hit)) {
      return(hit)
    }
    types <- all_types()
    ids <- c(seq_len(nrow(types_registry)) - 1L, session$types$id)
    within <- types[mime_is(types, a) %in% TRUE]
    table <- lineage_table()
    up <- unique(unlist(table[within], use.names = FALSE))
    if (any(within %in% c("application/x-rds", "application/x-rdata"))) {
      up <- c(up, "application/gzip")
    }
    set <- list(
      related = sort(unique(ids[match(c(within, up), types)])),
      within = sort(unique(ids[match(within, types)]))
    )
    assign(key, set, envir = session$related)
    set
  })
}

# The static counter the shortcut increments once per allowed type tested.
# Not API: the test of design D15 reads it.
probe_count <- function() .Call(zumime_probe_count)
