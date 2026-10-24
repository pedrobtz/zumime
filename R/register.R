# Types registered for the session (design section 6.9). The C table holds
# their names, parents and data rules; this environment holds what R needs:
# extensions, function rules and the registration order.
session <- new.env(parent = emptyenv())
session$types <- data.frame(
  type = character(),
  parent = character(),
  id = integer(),
  kind = character()
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
#' the parent matched, and is reported at `"probable"`. A function rule that
#' raises an error counts as `FALSE`, and the call warns once with a
#' `zumime_rule_warning` naming the type. A data rule cannot sit under a type
#' that a function rule decides, since data rules run first.
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
#' mime_register(
#'   "application/x-zumime-demo",
#'   "application/octet-stream",
#'   extensions = "zdemo",
#'   rule = list(offset = 0, bytes = "ZDEMO")
#' )
#' mime_sniff(charToRaw("ZDEMO\x01\x02"))
#' mime_guess("file.zdemo")
#' mime_unregister("application/x-zumime-demo")
mime_register <- function(type, parent, extensions = NULL, rule = NULL) {
  args <- check_register_args(type, parent, rule)
  essence <- args$essence
  parent <- args$parent
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
    data.frame(type = essence, parent = parent, id = id, kind = kind)
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

# mime_register()'s checks on the type, the parent and where the rule may
# sit. Returns the type's essence and the canonical parent.
check_register_args <- function(
  type,
  parent,
  rule,
  call = sys.call(sys.parent())
) {
  rec <- if (is_string(type)) mime_parse(type)[[1]]
  if (is.null(rec)) {
    zumime_abort(
      "type",
      "`type` must be a single MIME type string.",
      call = call
    )
  }
  essence <- paste0(rec$type, "/", rec$subtype)
  if (!is_string(parent)) {
    zumime_abort(
      "type",
      "`parent` must be a single type string.",
      call = call
    )
  }
  parent <- canonical_type(parent)
  if (nchar(essence, type = "bytes") > 127L) {
    zumime_abort(
      "registry",
      sprintf(
        "A registered type is at most 127 bytes long, not %d.",
        nchar(essence, type = "bytes")
      ),
      call = call
    )
  }
  if (essence %in% all_types() || essence %in% names(types_alias_map)) {
    zumime_abort(
      "registry",
      sprintf("\"%s\" is already a type.", essence),
      call = call
    )
  }
  if (!(parent %in% all_types())) {
    zumime_abort(
      "registry",
      sprintf("The parent \"%s\" is not a type.", parent),
      call = call
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
      ),
      call = call
    )
  }
  list(essence = essence, parent = parent)
}

check_extensions <- function(x, call = sys.call(sys.parent())) {
  if (is.null(x)) {
    return(character())
  }
  if (!is.character(x) || anyNA(x)) {
    zumime_abort(
      "type",
      "`extensions` must be a character vector or NULL.",
      call = call
    )
  }
  x <- tolower(sub("^\\.", "", x))
  if (any(!nzchar(x))) {
    zumime_abort(
      "type",
      "`extensions` must not be empty strings.",
      call = call
    )
  }
  x
}

check_rule <- function(rule, call = sys.call(sys.parent())) {
  bad <- function() {
    zumime_abort(
      "type",
      paste(
        "`rule` must be NULL, a function, or a list of `offset`, `bytes`",
        "(1 to 64 bytes) and an optional `mask` of the same length."
      ),
      call = call
    )
  }
  if (!is.list(rule) || is.null(rule[["bytes"]])) {
    bad()
  }
  offset <- rule[["offset"]] %||% 0
  bytes <- rule[["bytes"]]
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
  mask <- rule[["mask"]]
  if (!is.null(mask) && (!is.raw(mask) || length(mask) != length(bytes))) {
    bad()
  }
  list(offset = offset, bytes = bytes, mask = mask)
}

# Function rules whose parent is a row's type, applied in registration
# order until nothing changes. `x` is a raw vector or the rows' paths.
apply_registered <- function(out, x, limit) {
  if (length(session$rules) == 0L) {
    return(out)
  }
  fns <- session$types[session$types$kind == "function", , drop = FALSE]
  failed <- character()
  for (i in seq_len(nrow(out))) {
    type <- out$type[i]
    # A directory or other inode is never opened.
    if (is.na(type) || !any(fns$parent == type) || startsWith(type, "inode/")) {
      next
    }
    bytes <- head_bytes(x, i, limit)
    if (is.null(bytes)) {
      next
    }
    hit <- apply_rules_to(type, bytes, fns)
    failed <- union(failed, hit$failed)
    if (hit$type != type) {
      out$type[i] <- hit$type
      out$confidence[i] <- min(out$confidence[i], as_confidence("probable"))
    }
  }
  if (length(failed) > 0L) {
    zumime_warn(
      "rule",
      sprintf(
        "The rule registered for %s failed and was taken as FALSE.",
        paste0("\"", failed, "\"", collapse = ", ")
      ),
      call = NULL
    )
  }
  out
}

# Descend from `type` through the function rules under it, taking the
# first that matches at each level. A rule that fails does not match, and
# is named in `failed`.
apply_rules_to <- function(type, bytes, fns) {
  failed <- character()
  for (level in seq_len(max_rule_depth)) {
    matched <- FALSE
    for (h in which(fns$parent == type)) {
      ok <- tryCatch(
        isTRUE(session$rules[[fns$type[h]]](bytes)),
        error = function(e) {
          failed <<- c(failed, fns$type[h])
          FALSE
        }
      )
      if (ok) {
        type <- fns$type[h]
        matched <- TRUE
        break
      }
    }
    if (!matched) {
      break
    }
  }
  list(type = type, failed = failed)
}

# How many function rules may sit one under another. Registration needs an
# existing parent, so chains cannot loop; the bound keeps a long chain from
# reading the bytes over and over.
max_rule_depth <- 8L
