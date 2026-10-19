#' Type files from their bytes and their names
#'
#' Reads the first bytes of each path in one C loop, types them as
#' [mime_sniff()] does, guesses a type from the name as [mime_guess()] does,
#' and says whether the two agree. The other columns answer what a consumer
#' asks before opening a file: what a compressed file holds, whether it is
#' encrypted or truncated, its line endings, and a script's interpreter.
#'
#' Unreadable and missing paths give a row with `type` `NA` and
#' `confidence` `"none"`, so one bad entry does not abort a scan of a tree;
#' `strict = TRUE` raises `zumime_io_error` instead. A directory is
#' `inode/directory`, and nothing is read from it.
#'
#' `agree` is `TRUE` when the byte type and the name type lie on one
#' lineage, so bytes that say `text/plain` agree with a `.csv` name and a
#' ZIP agrees with a `.docx` name; `FALSE` when they differ, such as a PNG
#' named `.txt`; and `NA` when either is unknown. A disagreement is a
#' finding, not an error.
#'
#' The default answer depends on nothing outside the package. Three
#' arguments ask for an optional family package. `inner = "decompress"`
#' uses zukomp. `charset = "detect"` uses zuutf. `text = "family"` uses
#' zucsv, zujson and zutoml, each when installed. zuutf and zutoml are not
#' yet on CRAN; install them from GitHub. An argument whose package is
#' absent raises `zumime_dependency_error`. `text = "family"` uses whichever
#' sniffers are installed, listed by `zumime_info()$family`.
#'
#' @param path A character vector of paths.
#' @param limit The number of bytes to read from each file; `0` reads whole
#'   files.
#' @param complete If `TRUE`, also read each file's end and fill
#'   `complete`: a ZIP needs its end-of-central-directory record, a PDF
#'   `%%EOF` in its last kilobyte, a gzip stream must inflate to its
#'   trailer, and Parquet must end in `PAR1`. Other formats give `NA`. A
#'   PDF is `encrypted` when its trailer dictionary, found in the last 4 KB,
#'   names `/Encrypt`.
#' @param inner How to find the type inside a compression wrapper (gzip,
#'   bzip2, xz, zstd, LZ4, lzip, compress): `"name"` takes it from the rest
#'   of the name, so `data.csv.gz` holds `text/csv`; `"decompress"`
#'   decompresses gzip with zukomp and sniffs the result, falling back to
#'   the name for other wrappers and for files over 16 MiB.
#' @param text `"whatwg"` keeps the standard's answer for text; `"family"`
#'   offers a still generic `text/plain` to the family's sniffers.
#' @param charset `"declared"` reports the charset the bytes declare;
#'   `"detect"` asks zuutf where they declare none, or only the C1 guess.
#' @param strict If `TRUE`, an unreadable path raises `zumime_io_error`.
#' @return A `zumime_result` data frame with one row per path and columns
#'   `path`, `type`, `confidence`, `charset`, `by_name`, `agree`, `inner`,
#'   `encrypted`, `complete`, `newline` and `interpreter`.
#' @seealso [mime_sniff()] for bytes and the standard's contexts,
#'   [mime_check()] for an allowlist.
#' @export
#' @examples
#' dir <- tempfile()
#' dir.create(dir)
#' writeLines(c("a,b", "1,2"), file.path(dir, "data.csv"))
#' saveRDS(mtcars, file.path(dir, "cars.rds"))
#' writeBin(as.raw(c(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a)),
#'   file.path(dir, "logo.txt"))
#' mime_type(list.files(dir, full.names = TRUE))
#' unlink(dir, recursive = TRUE)
mime_type <- function(
  path,
  limit = 4096L,
  complete = FALSE,
  inner = c("name", "decompress"),
  text = c("whatwg", "family"),
  charset = c("declared", "detect"),
  strict = FALSE
) {
  path <- check_paths(path)
  limit <- check_limit(limit)
  check_flag(complete)
  check_flag(strict)
  inner <- check_choice(inner, c("name", "decompress"))
  text <- check_choice(text, c("whatwg", "family"))
  charset <- check_choice(charset, c("declared", "detect"))
  if (inner == "decompress") {
    need_package("zukomp", "inner = \"decompress\"")
  }
  if (charset == "detect") {
    need_package("zuutf", "charset = \"detect\"")
  }

  res <- sniff_paths(path, limit, complete)
  check_strict(path, res, strict)
  out <- path_result(path, res)
  out <- apply_registered(out, path, limit)

  if (text == "family") {
    out <- family_refine(out)
  }
  if (charset == "detect") {
    out <- detect_charset(out, limit)
  }
  out$inner <- inner_type(out, inner, limit)
  out$by_name <- mime_guess(path)
  out$agree <- agree(out$type, out$confidence, out$by_name)
  out[c(
    "path",
    "type",
    "confidence",
    "charset",
    "by_name",
    "agree",
    "inner",
    "encrypted",
    "complete",
    "newline",
    "interpreter"
  )]
}

# The C loop, with the context and supplied type of mime_sniff() when
# given. Paths are expanded here; the loop opens them as given.
sniff_paths <- function(
  path,
  limit,
  complete,
  supplied = NULL,
  no_sniff = FALSE,
  context = 0L
) {
  .Call(
    zumime_sniff_paths,
    enc2native(path.expand(path)),
    limit,
    complete,
    supplied$essence,
    isTRUE(supplied$apache_bug),
    no_sniff,
    context
  )
}

check_paths <- function(path) {
  if (!is.character(path)) {
    zumime_abort(
      "type",
      "`path` must be a character vector of paths.",
      call = sys.call(-1L)
    )
  }
  path
}

check_choice <- function(x, choices, arg = deparse(substitute(x))) {
  if (identical(x, choices)) {
    return(choices[1])
  }
  if (!is.character(x) || length(x) != 1L || !(x %in% choices)) {
    zumime_abort(
      "type",
      sprintf(
        "`%s` must be one of %s.",
        arg,
        paste0("\"", choices, "\"", collapse = ", ")
      ),
      call = sys.call(-1L)
    )
  }
  x
}

check_strict <- function(path, res, strict) {
  bad <- which(!is.na(res[[8]]))
  if (strict && length(bad)) {
    i <- bad[1]
    zumime_abort(
      "io",
      sprintf("Cannot read \"%s\": %s.", path[i], res[[8]][i]),
      call = sys.call(-1L)
    )
  }
}

need_package <- function(pkg, what) {
  if (!has_package(pkg)) {
    zumime_abort(
      "dependency",
      sprintf(
        "`%s` needs the %s package, which is not installed.",
        what,
        pkg
      ),
      call = sys.call(-1L)
    )
  }
}

path_result <- function(path, res, supplied = NULL) {
  type <- res[[1]]
  supplied_rows <- is.na(type) & is.na(res[[8]])
  if (any(supplied_rows)) {
    type[supplied_rows] <- supplied$essence
  }
  charset <- res[[3]]
  if (!is.null(supplied$charset)) {
    text_rows <- supplied_rows | mime_is(type, "text/plain") %in% TRUE
    charset[text_rows & !is.na(type)] <- supplied$charset
  }
  new_result(
    path = path,
    type = type,
    confidence = res[[2]],
    charset = charset,
    encrypted = res[[4]],
    complete = res[[5]],
    newline = res[[6]],
    interpreter = res[[7]]
  )
}

# Bytes and name lie on one lineage. Unknown bytes (the floor, or an
# unreadable path) and unknown names give NA.
agree <- function(type, confidence, by_name) {
  known <- !is.na(type) &
    !is.na(by_name) &
    !(type == "application/octet-stream" & confidence == "none")
  out <- rep(NA, length(type))
  if (!any(known)) {
    return(out)
  }
  # Once per distinct pair: a tree has few.
  key <- paste(type, by_name, sep = "\r")
  pairs <- unique(data.frame(key, type, by_name)[known, , drop = FALSE])
  one <- vapply(
    seq_len(nrow(pairs)),
    function(k) {
      isTRUE(mime_is(pairs$type[k], pairs$by_name[k])) ||
        isTRUE(mime_is(pairs$by_name[k], pairs$type[k]))
    },
    logical(1)
  )
  out[known] <- one[match(key[known], pairs$key)]
  out
}

wrapper_types <- function() {
  c(
    "application/gzip",
    "application/x-bzip2",
    "application/x-xz",
    "application/zstd",
    "application/x-lz4",
    "application/lzip",
    "application/x-compress"
  )
}

# The type inside a compression wrapper, from the rest of the name or, with
# "decompress", from the bytes zukomp inflates.
inner_type <- function(out, inner, limit) {
  res <- rep(NA_character_, nrow(out))
  wrapped <- which(out$type %in% wrapper_types())
  if (!length(wrapped)) {
    return(res)
  }
  res[wrapped] <- inner_by_name(out$path[wrapped])
  if (inner == "decompress") {
    for (i in wrapped[out$type[wrapped] == "application/gzip"]) {
      by_bytes <- decompress_type(out$path[i], limit)
      if (!is.na(by_bytes)) res[i] <- by_bytes
    }
  }
  res
}

inner_by_name <- function(path) {
  base <- tolower(sub("^.*[/\\\\]", "", path))
  rest <- sub("\\.[^./\\\\]*$", "", path)
  out <- mime_guess(rest)
  out[rest == path] <- NA_character_
  out[grepl("\\.(tgz|tbz|tbz2|txz|tzst|taz)$", base)] <- "application/x-tar"
  out
}

decompress_type <- function(path, limit) {
  cap <- 16 * 1024^2
  size <- file.size(path)
  if (is.na(size) || size > cap) {
    return(NA_character_)
  }
  bytes <- readBin(path, "raw", size)
  decompress <- suggested_fun("zukomp", "komp_decompress")
  out <- tryCatch(
    decompress(bytes, "gzip", max_output = cap),
    error = function(e) NULL
  )
  if (is.null(out)) {
    return(NA_character_)
  }
  mime_sniff(out, limit = limit)$type
}

# text = "family": a still generic text/plain is offered to the family's
# sniffers, each used when installed. Their answers are probable.
family_refine <- function(out) {
  sniffers <- family_sniffers()
  rows <- which(out$type %in% "text/plain")
  for (i in rows) {
    t <- NA_character_
    for (s in sniffers) {
      t <- tryCatch(s(out$path[i]), error = function(e) NA_character_)
      if (!is.na(t)) break
    }
    if (!is.na(t)) {
      out$type[i] <- t
      out$confidence[i] <- min(
        out$confidence[i],
        factor("probable", levels = confidence_levels, ordered = TRUE)
      )
    }
  }
  out
}

family_packages <- function() c("zucsv", "zujson", "zutoml")

family_sniffers <- function() {
  have <- vapply(family_packages(), has_package, logical(1))
  sniffers <- list(
    zucsv = function(path) {
      sniff <- suggested_fun("zucsv", "sniff_csv")
      for (d in c(",", "\t", ";")) {
        s <- sniff(path, delimiter = d)
        if (isTRUE(s$ncol >= 2L) && isTRUE(s$nrow >= 1L)) {
          return(if (d == "\t") "text/tab-separated-values" else "text/csv")
        }
      }
      NA_character_
    },
    zujson = function(path) {
      validate <- suggested_fun("zujson", "json_validate")
      txt <- readChar(path, file.size(path), useBytes = TRUE)
      if (isTRUE(validate(txt))) "application/json" else NA_character_
    },
    zutoml = function(path) {
      validate <- suggested_fun("zutoml", "toml_validate")
      bytes <- readBin(path, "raw", file.size(path))
      if (isTRUE(validate(bytes))) "application/toml" else NA_character_
    }
  )
  sniffers[have]
}

# charset = "detect": zuutf's statistical detection where the bytes declare
# no charset or only the C1 guess.
detect_charset <- function(out, limit) {
  detect <- suggested_fun("zuutf", "utf_detect")
  rows <- which(
    mime_is(out$type, "text/plain") %in%
      TRUE &
      (is.na(out$charset) | out$charset %in% c("windows-1252", "ISO-8859-1"))
  )
  for (i in rows) {
    bytes <- readBin(
      out$path[i],
      "raw",
      if (limit > 0) {
        limit
      } else {
        file.size(out$path[i])
      }
    )
    cand <- tryCatch(detect(bytes), error = function(e) character())
    if (length(cand)) out$charset[i] <- cand[1]
  }
  out
}

# The one place a suggested package is looked up, so tests can stand in for
# packages CI does not install (zuutf and zutoml are not on CRAN).
has_package <- function(pkg) requireNamespace(pkg, quietly = TRUE)

suggested_fun <- function(pkg, name) getExportedValue(pkg, name)
