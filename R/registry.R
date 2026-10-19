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
  types_registry
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
  out <- lapply(hit, function(i) {
    if (is.na(i)) character() else types_registry$extensions[[i]]
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
  unname(out)
}

# Lineage of one canonical type, nearest first, from the registry and any
# registered types.
lineage <- function(type) {
  out <- character()
  parent <- types_registry$parent[match(type, types_registry$type)]
  while (length(parent) && !is.na(parent)) {
    out <- c(out, parent)
    parent <- types_registry$parent[match(parent, types_registry$type)]
  }
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
    if (is.na(t) || !(t %in% types_registry$type)) NA_character_ else
      lineage(t)
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
    known <- t %in% types_registry$type
    family <- c(t, if (known) lineage(t) else "application/octet-stream")
    any(family %in% what) || sub("/.*$", "", t) %in% what
  }, logical(1), USE.NAMES = FALSE)
  hit[match(x, u)]
}
