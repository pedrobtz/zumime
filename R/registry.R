# The type registry (design sections 6.3 and 6.6). The tables are generated
# by tools/generate-tables.R into R/sysdata.rda: types_registry,
# types_ext_map, types_alias_map and types_table_version.

# Canonical essence of each type string: parameters dropped, whitespace
# trimmed, lower-cased, aliases resolved. Unknown types come back as their
# essence; NA stays NA.
canonical_type <- function(x) {
  x <- tolower(trimws(sub(";.*$", "", x)))
  hit <- match(x, names(types_alias_map))
  x[!is.na(hit)] <- types_alias_map[hit[!is.na(hit)]]
  unname(x)
}

#' The type registry
#'
#' Every type zumime knows, with its parent, aliases, extensions and the
#' kind of evidence that detects it.
#'
#' @return A data frame with one row per canonical type and columns `type`,
#'   `parent` (`NA` for the root, `application/octet-stream`), `aliases` and
#'   `extensions` (list columns of character vectors, the canonical
#'   extension first), `category` (the top-level type) and `detected_by`
#'   (`"signature"`, `"container"`, `"text"`, `"extension"` or
#'   `"registered"`).
#' @seealso [mime_parent()] for one type's lineage.
#' @export
#' @examples
#' types <- mime_types()
#' nrow(types)
#' types[types$type == "application/zip", ]
mime_types <- function() {
  reg <- session$types
  if (!nrow(reg)) return(types_registry)
  extra <- data.frame(
    type = reg$type,
    parent = reg$parent,
    category = sub("/.*$", "", reg$type),
    detected_by = "registered",
    stringsAsFactors = FALSE
  )
  extra$aliases <- rep(list(character()), nrow(reg))
  extra$extensions <- unname(session$extensions[reg$type])
  rbind(types_registry, extra[names(types_registry)])
}

#' Extensions of a type
#'
#' @param type A character vector of types. Aliases, parameters and case
#'   are ignored.
#' @return A list with one character vector per type, the canonical
#'   extension first, without the dot. An unknown type gives
#'   `character(0)`.
#' @seealso [mime_guess()] for the reverse.
#' @export
#' @examples
#' mime_extensions(c("image/jpeg", "application/x-sqlite3"))
mime_extensions <- function(type) {
  type <- canonical_type(check_character(type))
  hit <- match(type, types_registry$type)
  out <- lapply(seq_along(type), function(k) {
    if (!is.na(hit[k])) return(types_registry$extensions[[hit[k]]])
    session$extensions[[type[k]]] %||% character()
  })
  out
}

#' Guess a type from a file name
#'
#' Takes the longest known suffix after the last directory separator,
#' ignoring case, so `.tar.gz` is known as a compound and
#' `report.FINAL.PDF` is a PDF. Nothing is read from the file.
#'
#' @param path A character vector of paths or file names.
#' @return A character vector of canonical types, `NA` where no suffix is
#'   known.
#' @seealso [mime_extensions()] for the reverse.
#' @export
#' @examples
#' mime_guess(c("report.FINAL.PDF", "data.tar.gz", "README", "x.rds"))
mime_guess <- function(path) {
  path <- enc2utf8(check_character(path))
  suffix <- .Call(zumime_suffixes, path)
  keys <- names(types_ext_map)
  hit <- match(suffix[[2]], keys)
  miss <- is.na(hit)
  hit[miss] <- match(suffix[[1]][miss], keys)
  out <- types_ext_map[hit]
  if (length(session$extensions)) {
    ext <- unlist(session$extensions, use.names = FALSE)
    owner <- rep(names(session$extensions), lengths(session$extensions))
    reg <- match(suffix[[2]], ext)
    one <- match(suffix[[1]], ext)
    reg[is.na(reg)] <- one[is.na(reg)]
    out[!is.na(reg)] <- owner[reg[!is.na(reg)]]
  }
  unname(out)
}

# Lineage of one canonical type, nearest first, from the registry and any
# registered types. Every known type's lineage is computed once per
# registry version and kept in `session`.
lineage <- function(type) {
  table <- lineage_table()
  out <- table[[type]]
  if (is.null(out)) character() else out
}

lineage_table <- function() {
  if (identical(session$lineage_version, session$version)) {
    return(session$lineage)
  }
  types <- all_types()
  parents <- type_parent(types)
  idx <- match(parents, types)
  out <- vector("list", length(types))
  names(out) <- types
  # Walk all types up one level at a time.
  cur <- idx
  acc <- lapply(seq_along(types), function(i) character())
  for (depth in seq_len(64)) {
    live <- which(!is.na(cur))
    if (!length(live)) break
    for (i in live) acc[[i]] <- c(acc[[i]], types[cur[i]])
    cur[live] <- idx[cur[live]]
  }
  out[] <- acc
  session$lineage <- out
  session$lineage_version <- session$version
  out
}

#' The lineage of a type
#'
#' Every type has one parent, ending at `application/octet-stream`: text
#' types descend from `text/plain`, XML dialects from `application/xml`,
#' JSON dialects from `application/json`, ZIP-based formats from
#' `application/zip`.
#'
#' @param type A character vector of types. Aliases, parameters and case
#'   are ignored.
#' @return A list with one character vector per type: its ancestors,
#'   nearest first, empty for the root and `NA` for an unknown type.
#' @seealso [mime_is()] to test membership.
#' @export
#' @examples
#' mime_parent("image/svg+xml")
#' mime_parent(c("application/x-sqlite3", "application/octet-stream"))
mime_parent <- function(type) {
  type <- canonical_type(check_character(type))
  lapply(type, function(t) {
    if (is.na(t) || !(t %in% all_types())) NA_character_ else lineage(t)
  })
}

#' Is a type one of these?
#'
#' `TRUE` when a type equals one of `what`, descends from it, or has it as
#' its top-level type (`"image"`). Aliases, parameters and case are ignored
#' on both sides. An unknown type descends from `application/octet-stream`
#' only.
#'
#' @param x A character vector of types.
#' @param what A character vector of types, aliases or top-level types.
#' @return A logical vector the length of `x`, `NA` where `x` is `NA`.
#' @seealso [mime_parent()] for the lineage.
#' @export
#' @examples
#' mime_is("application/x-sqlite3", "application/vnd.sqlite3")
#' mime_is(c("image/png", "text/csv"), "image")
#' mime_is("image/svg+xml", "application/xml")
mime_is <- function(x, what) {
  x <- canonical_type(check_character(x))
  what <- canonical_type(check_character(what))
  what <- what[!is.na(what)]
  u <- unique(x)
  hit <- vapply(u, function(t) {
    if (is.na(t)) return(NA)
    known <- t %in% all_types()
    family <- c(t, if (known) lineage(t) else "application/octet-stream")
    any(family %in% what) || sub("/.*$", "", t) %in% what
  }, logical(1), USE.NAMES = FALSE)
  hit[match(x, u)]
}
