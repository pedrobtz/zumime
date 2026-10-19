#!/usr/bin/env Rscript
# Generates zumime's type registry (design section 4, layer 1; D8) from:
#
#   tools/sources/*.csv     IANA media types registry, one file per top-level
#                           type (CC0 1.0, https://www.iana.org/help/licensing-terms)
#   tools/sources/mime.types  Apache httpd's type map (Apache-2.0)
#   tools/types.yaml        hand-maintained parents, aliases, extensions
#
# and writes R/sysdata.rda and src/zumime_types.h, so R and C name the same
# types by the same ids. Nothing is taken from the GPL `mime` package.
#
#   Rscript tools/generate-tables.R            # verify checksums, regenerate
#   Rscript tools/generate-tables.R --check    # regenerate into a tempdir and
#                                              # exit 1 if the outputs differ
#   Rscript tools/generate-tables.R --fetch    # download the sources again and
#                                              # record url, date and sha256
#
# Run from the package root. Needs the yaml and digest packages.

args <- commandArgs(trailingOnly = TRUE)
fetch <- "--fetch" %in% args
check <- "--check" %in% args
out_arg <- grep("^--out=", args, value = TRUE)

sources_yaml <- "tools/table-sources.yaml"
types_yaml <- "tools/types.yaml"
iana_types <- c(
  "application", "audio", "font", "haptics", "image", "message", "model",
  "multipart", "text", "video"
)

stopifnot(file.exists("DESCRIPTION"), file.exists(types_yaml))

sha256 <- function(path) digest::digest(file = path, algo = "sha256")

# --- Sources --------------------------------------------------------------

if (fetch) {
  entries <- c(
    lapply(iana_types, function(t) list(
      file = paste0(t, ".csv"),
      url = sprintf("https://www.iana.org/assignments/media-types/%s.csv", t)
    )),
    list(list(
      file = "mime.types",
      url = "https://raw.githubusercontent.com/apache/httpd/trunk/docs/conf/mime.types"
    ))
  )
  for (i in seq_along(entries)) {
    dest <- file.path("tools/sources", entries[[i]]$file)
    utils::download.file(entries[[i]]$url, dest, mode = "wb", quiet = TRUE)
    entries[[i]]$retrieved <- format(Sys.Date())
    entries[[i]]$sha256 <- sha256(dest)
  }
  old <- if (file.exists(sources_yaml)) yaml::read_yaml(sources_yaml)$sources
  # A source whose bytes did not change keeps its old retrieval date, so the
  # table version moves only when the data does.
  for (i in seq_along(entries)) {
    prev <- Filter(function(o) identical(o$file, entries[[i]]$file), old)
    if (length(prev) && identical(prev[[1]]$sha256, entries[[i]]$sha256)) {
      entries[[i]]$retrieved <- prev[[1]]$retrieved
    }
  }
  writeLines(
    c(
      "# Upstream files behind the type registry, written by",
      "# tools/generate-tables.R --fetch. Copies live in tools/sources/.",
      yaml::as.yaml(list(sources = entries))
    ),
    sources_yaml
  )
}

sources <- yaml::read_yaml(sources_yaml)$sources
for (s in sources) {
  path <- file.path("tools/sources", s$file)
  if (!identical(sha256(path), s$sha256)) {
    stop(path, " does not match its recorded sha256; run with --fetch")
  }
}
table_version <- max(vapply(sources, function(s) s$retrieved, ""))

# --- Read -------------------------------------------------------------------

# type -> character vector of extensions, in source order. Insertion order is
# kept so that Apache's file order decides a contested extension.
ext_of <- list()
add_type <- function(type, exts = character()) {
  if (is.null(ext_of[[type]])) ext_of[[type]] <<- character()
  ext_of[[type]] <<- unique(c(ext_of[[type]], exts))
}
alias_to <- character() # alias -> canonical

for (t in iana_types) {
  csv <- utils::read.csv(file.path("tools/sources", paste0(t, ".csv")),
    stringsAsFactors = FALSE, check.names = FALSE)
  for (i in seq_len(nrow(csv))) {
    type <- tolower(trimws(csv$Template[i]))
    if (!nzchar(type)) type <- tolower(paste0(t, "/", trimws(csv$Name[i])))
    favour <- regmatches(
      csv$Name[i],
      regexec("in favou?r of ([A-Za-z0-9.+_-]+/[A-Za-z0-9.+_-]+)", csv$Name[i])
    )[[1]]
    if (length(favour)) {
      alias_to[type] <- tolower(favour[2])
    }
    add_type(type)
  }
}

apache <- readLines("tools/sources/mime.types", warn = FALSE)
for (line in apache) {
  if (grepl("^# [a-z0-9]+/[^[:space:]]+$", line)) {
    add_type(tolower(sub("^# ", "", line)))
  } else if (grepl("^[a-z0-9]", line)) {
    f <- strsplit(trimws(line), "[[:space:]]+")[[1]]
    add_type(tolower(f[1]), tolower(f[-1]))
  }
}

spec <- yaml::read_yaml(types_yaml)$types
for (type in names(spec)) {
  add_type(type, tolower(unlist(spec[[type]]$extensions)))
  for (a in tolower(unlist(spec[[type]]$aliases))) alias_to[a] <- type
}

# --- Fold aliases -----------------------------------------------------------

# An alias chain (a -> b -> c) resolves to its end. A deprecation whose
# target is not a type stays a type of its own.
resolve <- function(x) {
  seen <- character()
  while (!is.na(alias_to[x]) && !(x %in% seen)) {
    seen <- c(seen, x)
    x <- unname(alias_to[x])
  }
  x
}
alias_to <- vapply(names(alias_to), resolve, "")
alias_to <- alias_to[alias_to %in% names(ext_of) & names(alias_to) != alias_to]
for (a in names(alias_to)) {
  if (!is.null(ext_of[[a]])) {
    add_type(alias_to[[a]], ext_of[[a]])
    ext_of[[a]] <- NULL
  }
}

types <- sort(names(ext_of))

# --- Extensions -------------------------------------------------------------

# types.yaml claims first, then the sources in their order: the first type
# to list an extension owns it, and the others drop it, so every extension
# a type lists maps back to that type.
owner <- character()
for (type in names(spec)) {
  for (e in tolower(unlist(spec[[type]]$extensions))) {
    if (is.na(owner[e])) owner[e] <- resolve(type)
  }
}
for (type in names(ext_of)) {
  for (e in ext_of[[type]]) if (is.na(owner[e])) owner[e] <- type
}
extensions <- lapply(types, function(type) {
  e <- ext_of[[type]]
  e <- e[owner[e] == type]
  canon <- spec[[type]]$canonical
  if (!is.null(canon)) e <- unique(c(canon, e))
  e
})
names(extensions) <- types
owner <- owner[order(names(owner))]

# --- Parents ----------------------------------------------------------------

default_parent <- function(type) {
  rules <- c(
    "\\+xml$" = "application/xml",
    "\\+json$" = "application/json",
    "\\+zip$" = "application/zip",
    "\\+gzip$" = "application/gzip"
  )
  for (r in names(rules)) if (grepl(r, type)) return(rules[[r]])
  if (startsWith(type, "text/")) return("text/plain")
  "application/octet-stream"
}
parent <- vapply(types, function(type) {
  s <- spec[[type]]
  if (!is.null(s) && "parent" %in% names(s)) {
    if (is.null(s$parent)) NA_character_ else s$parent
  } else {
    default_parent(type)
  }
}, "")
bad <- !is.na(parent) & !(parent %in% types)
if (any(bad)) stop("unknown parent: ", paste(types[bad], parent[bad]))

aliases <- lapply(types, function(type) sort(names(alias_to)[alias_to == type]))
detected_by <- vapply(types, function(type) {
  d <- spec[[type]]$detected_by
  if (is.null(d)) "extension" else d
}, "")

types_registry <- data.frame(
  type = types,
  parent = unname(parent),
  category = sub("/.*$", "", types),
  detected_by = unname(detected_by),
  stringsAsFactors = FALSE
)
types_registry$aliases <- unname(aliases)
types_registry$extensions <- unname(extensions)
types_registry <- types_registry[c(
  "type", "parent", "aliases", "extensions", "category", "detected_by"
)]
types_ext_map <- owner
types_alias_map <- alias_to[order(names(alias_to))]
types_table_version <- table_version

# --- C header ---------------------------------------------------------------

enum_names <- paste0("ZUMIME_T_", toupper(gsub("[^A-Za-z0-9]", "_", types)))
dup <- duplicated(enum_names)
while (any(dup)) {
  enum_names[dup] <- paste0(enum_names[dup], "_2")
  dup <- duplicated(enum_names)
}
parent_id <- match(parent, types) - 1L
parent_id[is.na(parent_id)] <- -1L

header <- c(
  "/* Generated by tools/generate-tables.R from the IANA media types registry,",
  "* Apache httpd's mime.types and tools/types.yaml. Do not edit by hand.",
  sprintf("* Table version %s. */", table_version),
  "",
  "#ifndef ZUMIME_TYPES_H",
  "#define ZUMIME_TYPES_H",
  "",
  sprintf("#define ZUMIME_TABLE_VERSION \"%s\"", table_version),
  "",
  "enum zumime_type_id {",
  sprintf("  %s = %d,", enum_names, seq_along(types) - 1L),
  sprintf("  ZUMIME_N_TYPES = %d", length(types)),
  "};",
  "",
  "extern const char *const zumime_type_names[ZUMIME_N_TYPES];",
  "extern const int zumime_type_parents[ZUMIME_N_TYPES];",
  "",
  "#ifdef ZUMIME_TYPES_IMPLEMENTATION",
  "const char *const zumime_type_names[ZUMIME_N_TYPES] = {",
  sprintf("  \"%s\",", types),
  "};",
  "",
  "/* Parent of each type by id; -1 for the root. */",
  "const int zumime_type_parents[ZUMIME_N_TYPES] = {",
  paste0("  ", vapply(split(parent_id, ceiling(seq_along(parent_id) / 16)),
    function(x) paste0(paste(x, collapse = ", "), ","), "")),
  "};",
  "#endif",
  "",
  "#endif"
)
header[2:3] <- paste0(" ", header[2:3])

# --- Write ------------------------------------------------------------------

out_dir <- if (length(out_arg)) sub("^--out=", "", out_arg) else if (check)
  tempfile("zumime-tables-") else "."
dir.create(file.path(out_dir, "R"), recursive = TRUE, showWarnings = FALSE)
dir.create(file.path(out_dir, "src"), recursive = TRUE, showWarnings = FALSE)
header_path <- file.path(out_dir, "src", "zumime_types.h")
rda_path <- file.path(out_dir, "R", "sysdata.rda")
writeLines(header, header_path, useBytes = TRUE)
save(types_registry, types_ext_map, types_alias_map, types_table_version,
  file = rda_path, compress = "xz", version = 3)

message(sprintf("%d types, %d extensions, %d aliases; table version %s",
  length(types), length(owner), length(alias_to), table_version))

if (check) {
  # The .rda carries the writing R's version in its header, so the objects
  # are compared rather than the bytes; the C header is compared byte for
  # byte.
  same_header <- identical(
    readBin(header_path, "raw", file.size(header_path)),
    readBin("src/zumime_types.h", "raw", file.size("src/zumime_types.h"))
  )
  new <- new.env()
  old <- new.env()
  load(rda_path, new)
  load("R/sysdata.rda", old)
  same_data <- identical(sort(ls(new)), sort(ls(old))) &&
    all(vapply(ls(new), function(n) identical(new[[n]], old[[n]]), TRUE))
  if (!same_header || !same_data) {
    message("generated tables differ from the committed ones: ",
      if (!same_header) "src/zumime_types.h " else "",
      if (!same_data) "R/sysdata.rda" else "")
    quit(status = 1)
  }
  message("committed tables match their sources")
}
