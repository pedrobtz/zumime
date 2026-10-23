# The type registry (design sections 6.3 and 6.6). The tables are generated
# by tools/generate-tables.R into R/sysdata.rda: types_registry,
# types_ext_map, types_alias_map and types_table_version.

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
#' @family registry
#' @export
#' @examples
#' types <- mime_types()
#' nrow(types)
#' types[types$type == "application/zip", ]
mime_types <- function() {
  reg <- session$types
  if (nrow(reg) == 0L) {
    return(types_registry)
  }
  extra <- data.frame(
    type = reg$type,
    parent = reg$parent,
    category = sub("/.*$", "", reg$type),
    detected_by = "registered"
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
#' @family registry
#' @export
#' @examples
#' mime_extensions(c("image/jpeg", "application/x-sqlite3"))
mime_extensions <- function(type) {
  type <- canonical_type(check_character(type))
  hit <- match(type, types_registry$type)
  lapply(seq_along(type), function(k) {
    if (!is.na(hit[k])) {
      return(types_registry$extensions[[hit[k]]])
    }
    session$extensions[[type[k]]] %||% character()
  })
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
#' @family registry
#' @export
#' @examples
#' mime_guess(c("report.FINAL.PDF", "data.tar.gz", "README", "x.rds"))
mime_guess <- function(path) {
  path <- enc2utf8(check_character(path))
  suffix <- .Call(zumime_suffixes, path)
  ext <- as.character(unlist(session$extensions, use.names = FALSE))
  owner <- as.character(rep(
    names(session$extensions),
    lengths(session$extensions)
  ))
  # The compound suffix before the single one, across both tables; at the
  # same length a registered extension wins.
  lookup <- function(s) {
    out <- owner[match(s, ext)]
    builtin <- is.na(out)
    out[builtin] <- types_ext_map[match(s[builtin], names(types_ext_map))]
    out
  }
  out <- lookup(suffix[[2]])
  single <- is.na(out)
  out[single] <- lookup(suffix[[1]][single])
  unname(out)
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
#' @family registry
#' @export
#' @examples
#' mime_parent("image/svg+xml")
#' mime_parent(c("application/x-sqlite3", "application/octet-stream"))
mime_parent <- function(type) {
  type <- canonical_type(check_character(type))
  lapply(type, function(one) {
    if (is.na(one) || !(one %in% all_types())) NA_character_ else lineage(one)
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
#' @family registry
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
  hit <- vapply(
    u,
    function(one) {
      if (is.na(one)) {
        return(NA)
      }
      known <- one %in% all_types()
      family <- c(one, if (known) lineage(one) else "application/octet-stream")
      any(family %in% what) || sub("/.*$", "", one) %in% what
    },
    logical(1),
    USE.NAMES = FALSE
  )
  hit[match(x, u)]
}

# Canonical essence of each type string: parameters dropped, whitespace
# trimmed, lower-cased, aliases resolved. Unknown types come back as their
# essence; NA stays NA.
canonical_type <- function(x) {
  x <- tolower(trimws(sub(";.*$", "", x)))
  hit <- match(x, names(types_alias_map))
  x[!is.na(hit)] <- types_alias_map[hit[!is.na(hit)]]
  unname(x)
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

# Lineage of one canonical type, nearest first, from the registry and any
# registered types. Every known type's lineage is computed once per
# registry version and kept in `session`.
lineage <- function(type) {
  lineage_table()[[type]] %||% character()
}

lineage_table <- function() {
  if (identical(session$lineage_version, session$version)) {
    return(session$lineage)
  }
  types <- all_types()
  parents <- type_parent(types)
  idx <- match(parents, types)
  # Walk all types up one level at a time. The generator rejects cycles and
  # registration needs an existing parent, so the walk ends; the bound only
  # guards against a table that breaks that promise.
  cur <- idx
  acc <- rep(list(character()), length(types))
  names(acc) <- types
  for (step in seq_len(max_lineage)) {
    live <- which(!is.na(cur))
    if (length(live) == 0L) {
      break
    }
    for (i in live) {
      acc[[i]] <- c(acc[[i]], types[cur[i]])
    }
    cur[live] <- idx[cur[live]]
  }
  session$lineage <- acc
  session$lineage_version <- session$version
  acc
}

# The deepest lineage the walk follows: today's deepest is far shorter.
max_lineage <- 64L
