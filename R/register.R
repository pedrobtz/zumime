# Types registered for the session (design section 6.9). The C table holds
# their names, parents and data rules; this environment holds what R needs:
# extensions, function rules and the registration order.
session <- new.env(parent = emptyenv())
session$types <- data.frame(
  type = character(),
  parent = character(),
  id = integer(),
  kind = character(),
  stringsAsFactors = FALSE
)
session$extensions <- list()
session$rules <- list()
session$version <- 0L

#' Register a type for the session
#'
#' Adds a type under a parent in the hierarchy, so that [mime_sniff()],
#' [mime_type()], [mime_check()] and the registry functions know it until
#' the session ends or [mime_unregister()] removes it. A package that wants
#' its format recognised registers it in its `.onLoad()`.
#'
#' A data rule, `list(offset, bytes, mask)`, runs in C whenever the bytes
#' have been typed as the parent, costs what a built-in signature costs,
#' and is reported at `"definite"`. A function rule is called from R with
#' the bytes read and must return `TRUE` or `FALSE`; it runs last, only when
#' the parent matched, and is reported at `"probable"`. A data rule cannot sit
#' under a type that a function rule decides, since data rules run first.
#'
#' @param type The new type, such as `"application/x-myformat"`.
#' @param parent An existing type the new one descends from.
#' @param extensions File extensions for [mime_guess()], without the dot, or
#'   `NULL`.
#' @param rule `NULL` for a type known by name only; a list of `offset` (a
#'   whole number), `bytes` (a raw vector or a string, at most 64 bytes)
#'   and an optional `mask` (a raw vector as long as `bytes`); or a function
#'   of one raw vector.
#' @return `mime_register()` returns the type, invisibly.
#'   `mime_unregister()` returns `NULL`, invisibly.
#' @seealso [mime_types()], where registered types show
#'   `detected_by = "registered"`.
#' @export
#' @examples
#' mime_register("application/x-zumime-demo", "application/octet-stream",
#'   extensions = "zdemo", rule = list(offset = 0, bytes = "ZDEMO"))
#' mime_sniff(charToRaw("ZDEMO\x01\x02"))
#' mime_guess("file.zdemo")
#' mime_unregister("application/x-zumime-demo")
mime_register <- function(type, parent, extensions = NULL, rule = NULL) {
  if (!is_string(type) || is.null(mime_parse(type)[[1]])) {
    zumime_abort("type", "`type` must be a single MIME type string.")
  }
  rec <- mime_parse(type)[[1]]
  essence <- paste0(rec$type, "/", rec$subtype)
  if (!is_string(parent)) {
    zumime_abort("type", "`parent` must be a single type string.")
  }
  parent <- canonical_type(parent)
  if (nchar(essence, type = "bytes") > 127L) {
    zumime_abort(
      "registry",
      sprintf(
        "A registered type is at most 127 bytes long, not %d.",
        nchar(essence, type = "bytes")
      )
    )
  }
  if (essence %in% all_types() || essence %in% names(types_alias_map)) {
    zumime_abort("registry", sprintf("\"%s\" is already a type.", essence))
  }
  if (!(parent %in% all_types())) {
    zumime_abort(
      "registry",
      sprintf("The parent \"%s\" is not a type.", parent)
    )
  }
  # A data rule runs in C before R's function rules, so it could never see
  # a type that only a function rule decides.
  if (
    !is.function(rule) &&
      !is.null(rule) &&
      parent %in% session$types$type[session$types$kind == "function"]
  ) {
    zumime_abort(
      "registry",
      sprintf(
        paste(
          "\"%s\" is decided by a function rule; a data rule cannot sit",
          "under it. Use a function rule for \"%s\"."
        ),
        parent,
        essence
      )
    )
  }
  extensions <- check_extensions(extensions)
  data_rule <- NULL
  fn <- NULL
  if (is.function(rule)) {
    fn <- rule
  } else if (!is.null(rule)) {
    data_rule <- check_rule(rule)
  }
  id <- .Call(
    zumime_register_type,
    essence,
    parent,
    as.double(data_rule$offset %||% 0),
    data_rule$bytes,
    data_rule$mask
  )
  if (is.na(id)) {
    zumime_abort("registry", "No room for more registered types.")
  }
  kind <- if (!is.null(fn)) {
    "function"
  } else if (!is.null(data_rule)) {
    "data"
  } else {
    "name"
  }
  session$types <- rbind(
    session$types,
    data.frame(
      type = essence,
      parent = parent,
      id = id,
      kind = kind,
      stringsAsFactors = FALSE
    )
  )
  session$extensions[[essence]] <- extensions
  session$rules[[essence]] <- fn
  session$version <- session$version + 1L
  invisible(essence)
}

#' @rdname mime_register
#' @export
mime_unregister <- function(type) {
  if (!is_string(type)) {
    zumime_abort("type", "`type` must be a single type string.")
  }
  type <- canonical_type(type)
  if (!(type %in% session$types$type)) {
    zumime_abort("registry", sprintf("\"%s\" is not a registered type.", type))
  }
  if (type %in% session$types$parent) {
    zumime_abort(
      "registry",
      sprintf(
        "\"%s\" is the parent of another registered type.",
        type
      )
    )
  }
  .Call(zumime_unregister_type, type)
  session$types <- session$types[session$types$type != type, , drop = FALSE]
  session$extensions[[type]] <- NULL
  session$rules[[type]] <- NULL
  session$version <- session$version + 1L
  invisible(NULL)
}

check_extensions <- function(x) {
  if (is.null(x)) {
    return(character())
  }
  if (!is.character(x) || anyNA(x)) {
    zumime_abort(
      "type",
      "`extensions` must be a character vector or NULL.",
      call = sys.call(-1L)
    )
  }
  x <- tolower(sub("^\\.", "", x))
  if (any(!nzchar(x))) {
    zumime_abort(
      "type",
      "`extensions` must not be empty strings.",
      call = sys.call(-1L)
    )
  }
  x
}

check_rule <- function(rule) {
  bad <- function() {
    zumime_abort(
      "type",
      paste(
        "`rule` must be NULL, a function, or a list of `offset`, `bytes`",
        "(1 to 64 bytes) and an optional `mask` of the same length."
      ),
      call = sys.call(-2L)
    )
  }
  if (!is.list(rule) || is.null(rule$bytes)) {
    bad()
  }
  offset <- rule$offset %||% 0
  bytes <- rule$bytes
  if (is.character(bytes) && length(bytes) == 1L) {
    bytes <- charToRaw(bytes)
  }
  if (!is.raw(bytes) || length(bytes) < 1L || length(bytes) > 64L) {
    bad()
  }
  if (
    !is.numeric(offset) ||
      length(offset) != 1L ||
      is.na(offset) ||
      offset < 0 ||
      offset != floor(offset) ||
      offset > .Machine$integer.max
  ) {
    bad()
  }
  mask <- rule$mask
  if (!is.null(mask) && (!is.raw(mask) || length(mask) != length(bytes))) {
    bad()
  }
  list(offset = offset, bytes = bytes, mask = mask)
}

# Every type name the session knows: generated, then registered.
all_types <- function() c(types_registry$type, session$types$type)

# Parent of each type, registered ones included; NA for the root and for
# unknown types.
type_parent <- function(type) {
  p <- types_registry$parent[match(type, types_registry$type)]
  reg <- match(type, session$types$type)
  p[!is.na(reg)] <- session$types$parent[reg[!is.na(reg)]]
  p
}

# Function rules whose parent is a row's type, applied in registration
# order until nothing changes. `x` is a raw vector or the rows' paths.
apply_registered <- function(out, x, limit) {
  if (!length(session$rules)) {
    return(out)
  }
  fns <- session$types[session$types$kind == "function", , drop = FALSE]
  for (i in seq_len(nrow(out))) {
    bytes <- NULL
    for (depth in 1:8) {
      hit <- which(fns$parent == out$type[i])
      if (!length(hit) || is.na(out$type[i])) {
        break
      }
      if (is.null(bytes)) {
        bytes <- head_bytes(x, i, limit)
      }
      if (is.null(bytes)) {
        break
      }
      changed <- FALSE
      for (h in hit) {
        ok <- tryCatch(
          isTRUE(session$rules[[fns$type[h]]](bytes)),
          error = function(e) FALSE
        )
        if (ok) {
          out$type[i] <- fns$type[h]
          out$confidence[i] <- min(
            out$confidence[i],
            factor("probable", levels = confidence_levels, ordered = TRUE)
          )
          changed <- TRUE
          break
        }
      }
      if (!changed) break
    }
  }
  out
}

head_bytes <- function(x, i, limit) {
  if (is.raw(x)) {
    return(if (limit > 0 && length(x) > limit) x[seq_len(limit)] else x)
  }
  path <- x[i]
  size <- suppressWarnings(file.size(path))
  if (is.na(size)) {
    return(NULL)
  }
  readBin(path, "raw", if (limit > 0) min(limit, size) else size)
}
