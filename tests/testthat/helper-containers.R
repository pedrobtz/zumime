# Container builders for the reader tests: every container is built from
# bytes in the test, so the suite runs without the fixture corpus.

u16 <- function(x) as.raw(c(x %% 256, (x %/% 256) %% 256))
u32 <- function(x) {
  as.raw(c(
    x %% 256,
    (x %/% 256) %% 256,
    (x %/% 65536) %% 256,
    (x %/% 16777216) %% 256
  ))
}
u32be <- function(x) rev(u32(x))
bytes <- function(s) if (is.raw(s)) s else charToRaw(s)

# A raw DEFLATE stream: a gzip member without its 10-byte header (R's
# gzfile() writes no optional fields) and 8-byte trailer. Not
# memCompress(): under valgrind its libdeflate compressor is reported as
# possibly lost, in R, on every call.
deflate_raw <- function(x) {
  z <- gzip_bytes(x)
  stopifnot(z[4] == as.raw(0))
  z[11:(length(z) - 8)]
}

# A ZIP archive. `entries` is a named list of contents; `method` 0 stores,
# 8 deflates. `flags` and `extra` apply to every entry. With
# `descriptor = TRUE` the local headers carry flag 3 and a data descriptor
# follows each entry's data; the local sizes are zero unless `sizes`, and
# the descriptor has no signature unless `signature`. `zip64` writes the
# Zip64 marker 0xFFFFFFFF as the directory's offset, and `comment` is the
# archive comment.
build_zip <- function(
  entries,
  method = 0L,
  flags = 0L,
  extra = raw(),
  descriptor = FALSE,
  sizes = !descriptor,
  signature = TRUE,
  zip64 = FALSE,
  comment = raw()
) {
  local <- raw()
  central <- raw()
  for (name in names(entries)) {
    data <- bytes(entries[[name]])
    stored <- if (method == 8L) deflate_raw(data) else data
    f <- flags + if (descriptor) 8L else 0L
    csize <- if (sizes) length(stored) else 0L
    nm <- charToRaw(name)
    offset <- length(local)
    local <- c(
      local,
      charToRaw("PK"),
      as.raw(c(3, 4)),
      u16(20),
      u16(f),
      u16(method),
      u16(0),
      u16(0),
      u32(0),
      u32(csize),
      u32(if (sizes) length(data) else 0L),
      u16(length(nm)),
      u16(length(extra)),
      nm,
      extra,
      stored
    )
    if (descriptor) {
      local <- c(
        local,
        if (signature) c(charToRaw("PK"), as.raw(c(7, 8))),
        u32(0),
        u32(length(stored)),
        u32(length(data))
      )
    }
    central <- c(
      central,
      charToRaw("PK"),
      as.raw(c(1, 2)),
      u16(20),
      u16(20),
      u16(f),
      u16(method),
      u16(0),
      u16(0),
      u32(0),
      u32(length(stored)),
      u32(length(data)),
      u16(length(nm)),
      u16(length(extra)),
      u16(0),
      u16(0),
      u16(0),
      u32(0),
      u32(offset),
      nm,
      extra
    )
  }
  eocd <- c(
    charToRaw("PK"),
    as.raw(c(5, 6)),
    u16(0),
    u16(0),
    u16(length(entries)),
    u16(length(entries)),
    u32(length(central)),
    u32(if (zip64) 2^32 - 1 else length(local)),
    u16(length(comment)),
    comment
  )
  c(local, central, eocd)
}

ooxml_entries <- function(folder, main_ct = NULL, vba = FALSE) {
  ct <- paste0(
    "<?xml version=\"1.0\"?><Types><Override PartName=\"/x\" ",
    "ContentType=\"",
    if (is.null(main_ct)) "application/xml" else main_ct,
    "\"/></Types>"
  )
  e <- list("[Content_Types].xml" = ct, "_rels/.rels" = "<Relationships/>")
  e[[paste0(folder, "/document.xml")]] <- "<x/>"
  if (vba) {
    e[[paste0(folder, "/vbaProject.bin")]] <- as.raw(1:8)
  }
  e
}

# An OLE2 compound file: 512-byte sectors, the FAT in sector 0, `pad` free
# sectors, then the directory (more than one sector beyond four entries). A
# large `pad` puts the directory past the head, as Office does.
build_ole2 <- function(streams, clsid = raw(16), pad = 0L) {
  entry <- function(name, type, clsid = raw(16)) {
    n <- unlist(lapply(utf8ToInt(name), function(cp) u16(cp)))
    n <- c(n, as.raw(c(0, 0)))
    e <- raw(128)
    e[seq_along(n)] <- n
    e[65:66] <- u16(length(n))
    e[67] <- as.raw(type)
    e[69:80] <- as.raw(0xff)
    e[81:96] <- clsid
    e
  }
  dir <- c(
    entry("Root Entry", 5, clsid),
    unlist(lapply(streams, entry, type = 2))
  )
  ndir <- ceiling(length(dir) / 512)
  dir <- c(dir, raw(ndir * 512 - length(dir)))
  header <- raw(512)
  header[1:8] <- as.raw(c(0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1))
  header[25:26] <- u16(0x3e)
  header[27:28] <- u16(3)
  header[29:30] <- as.raw(c(0xfe, 0xff))
  header[31:32] <- u16(9)
  header[33:34] <- u16(6)
  header[45:48] <- u32(1)
  header[49:52] <- u32(1 + pad)
  header[57:60] <- u32(4096)
  header[61:64] <- as.raw(c(0xfe, 0xff, 0xff, 0xff))
  header[77:512] <- as.raw(0xff)
  header[77:80] <- u32(0)
  fat <- rep(as.raw(0xff), 512)
  fat[1:4] <- as.raw(c(0xfd, 0xff, 0xff, 0xff))
  for (k in seq_len(ndir)) {
    sec <- pad + k
    nxt <- if (k < ndir) u32(sec + 1) else as.raw(c(0xfe, 0xff, 0xff, 0xff))
    fat[(4 * sec + 1):(4 * sec + 4)] <- nxt
  }
  c(header, fat, raw(512 * pad), dir)
}

msi_clsid <- function() {
  as.raw(c(0x84, 0x10, 0x0c, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46))
}

build_ftyp <- function(major, compat = character()) {
  body <- c(charToRaw(major), u32be(0), unlist(lapply(compat, charToRaw)))
  c(
    u32be(8 + length(body)),
    charToRaw("ftyp"),
    body,
    u32be(8),
    charToRaw("free")
  )
}

# One Ogg page holding one packet.
build_ogg <- function(packet) {
  packet <- bytes(packet)
  c(
    charToRaw("OggS"),
    as.raw(c(0, 2)),
    raw(8),
    u32(1),
    u32(0),
    u32(0),
    as.raw(1),
    as.raw(length(packet)),
    packet
  )
}

# An EBML header whose DocType comes after `pad` filler bytes.
build_ebml <- function(doctype, pad = 0L) {
  dt <- charToRaw(doctype)
  body <- c(
    rep(as.raw(c(0xec, 0x80)), pad),
    as.raw(c(0x42, 0x82)),
    as.raw(0x80 + length(dt)),
    dt
  )
  c(
    as.raw(c(0x1a, 0x45, 0xdf, 0xa3)),
    as.raw(0x80 + length(body)),
    body,
    raw(16)
  )
}

sniff_type <- function(x, ...) mime_sniff(bytes(x), ...)$type

docx_type <- function() {
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
}

# A small tree under a temporary directory, removed when `env` ends. Each
# file is written from bytes; returns the directory.
local_tree <- function(files, env = parent.frame()) {
  dir <- withr::local_tempdir(.local_envir = env)
  for (name in names(files)) {
    path <- file.path(dir, name)
    dir.create(dirname(path), showWarnings = FALSE, recursive = TRUE)
    writeBin(bytes(files[[name]]), path)
  }
  dir
}

gzip_bytes <- function(x) {
  f <- tempfile(fileext = ".gz")
  on.exit(unlink(f))
  con <- gzfile(f, "wb")
  writeBin(bytes(x), con)
  close(con)
  readBin(f, "raw", file.size(f))
}

pdf_bytes <- function(encrypt = FALSE, eof = TRUE) {
  body <- paste0(
    "%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\n",
    "trailer << /Root 1 0 R",
    if (encrypt) " /Encrypt 2 0 R" else "",
    " >>\nstartxref\n0\n",
    if (eof) "%%EOF\n" else ""
  )
  charToRaw(body)
}

# A tree with one file per kind of answer, for the D15 equivalence.
check_tree <- function(env = parent.frame()) {
  local_tree(
    list(
      "a.pdf" = pdf_bytes(),
      "b.png" = png_bytes(),
      "c.docx" = build_zip(ooxml_entries("word")),
      "d.zip" = build_zip(list(a = "x")),
      "e.json" = "{\"a\": 1}",
      "f.txt" = "plain words\n",
      "g.svg" = "<?xml version=\"1.0\"?><svg/>",
      "h.bin" = as.raw(c(0, 1, 2, 3)),
      "i.html" = "<html><body>",
      "j.ogg" = build_ogg("OpusHead"),
      "k.doc" = build_ole2("WordDocument"),
      "l.c1" = c(charToRaw("caf"), as.raw(0xe9)),
      "m.rds" = gzip_bytes(c(charToRaw("X\n"), as.raw(c(0, 0, 0, 3)), raw(20)))
    ),
    env = env
  )
}

check_candidates <- function() {
  c(
    "application/pdf",
    "image/png",
    "image",
    "application/zip",
    docx_type(),
    "application/json",
    "text/plain",
    "application/xml",
    "audio/ogg",
    "application/x-ole-storage",
    "application/x-rds",
    "application/octet-stream"
  )
}

# design D15: mime_check(x, a, m) == mime_is(t$type, a) & t$confidence >= m.
expect_check_equivalence <- function(paths, allowed_sets, levels) {
  t <- mime_type(paths)
  for (a in allowed_sets) {
    for (m in levels) {
      want <- mime_is(t$type, a) &
        t$confidence >= factor(m, levels = levels(t$confidence), ordered = TRUE)
      expect_identical(
        mime_check(paths, a, m),
        want,
        info = paste(paste(a, collapse = ", "), m)
      )
    }
  }
}

# Inputs for the byte-at-a-time property: one per kind of answer.
stream_inputs <- function() {
  c(list(
    pdf = pdf_bytes(),
    png = c(
      png_bytes()[1:8],
      u32be(13),
      charToRaw("IHDR"),
      raw(17),
      u32be(0),
      charToRaw("IDAT"),
      raw(4)
    ),
    gif = c(charToRaw("GIF89a"), raw(20)),
    tar = c(tar_header(), raw(1024)),
    docx = build_zip(ooxml_entries("word")),
    ole = build_ole2("Workbook"),
    m4a = build_ftyp("M4A ", c("mp42")),
    mkv = build_ebml("webm", pad = 30),
    ogg = build_ogg("OpusHead"),
    mp3 = c(mp3_frame(), raw(413), mp3_frame(), raw(8)),
    html = charToRaw("  <html><body>x"),
    json = charToRaw("{\"type\": \"Feature\", \"geometry\": {}}"),
    text = charToRaw("plain words\n"),
    bin = as.raw(c(1:20, 0)),
    exe = c(charToRaw("MZ"), raw(100)),
    elf = c(charToRaw("\x7fELF"), raw(60)),
    rds = gzip_bytes(c(charToRaw("X\n"), as.raw(c(0, 0, 0, 3)), raw(20))),
    ws = charToRaw("      "),
    # Tag-terminated row that does not match: "<html" then "x".
    htmlx = charToRaw("<htmlx lang=en>words"),
    short = as.raw(0xff),
    jpeg = as.raw(c(0xff, 0xd8, 0xff, 0xe0, 0, 0)),
    apng = c(
      png_bytes()[1:8],
      u32be(13),
      charToRaw("IHDR"),
      raw(17),
      u32be(8),
      charToRaw("acTL"),
      raw(12),
      u32be(1),
      charToRaw("IDAT"),
      raw(5)
    ),
    # The directory past 4 KiB.
    ole_padded = build_ole2(c("WordDocument", "1Table"), pad = 20L),
    # An offset row past 32 KiB.
    iso = local({
      iso <- raw(40000)
      iso[32770:32774] <- charToRaw("CD001")
      iso
    })
  ))
}

# A gzip member over raw DEFLATE `deflate`, with optional header fields
# (FEXTRA, FNAME, FCOMMENT, FHCRC) and a trailer whose size is `isize`. The
# CRC is zero: zumime does not check it.
gzip_member <- function(
  deflate,
  isize,
  extra = NULL,
  name = NULL,
  comment = NULL,
  hcrc = FALSE
) {
  flg <- 0L
  fields <- raw()
  if (!is.null(extra)) {
    flg <- flg + 4L
    fields <- c(fields, u16(length(extra)), extra)
  }
  if (!is.null(name)) {
    flg <- flg + 8L
    fields <- c(fields, charToRaw(name), as.raw(0))
  }
  if (!is.null(comment)) {
    flg <- flg + 16L
    fields <- c(fields, charToRaw(comment), as.raw(0))
  }
  if (hcrc) {
    flg <- flg + 2L
    fields <- c(fields, raw(2))
  }
  c(
    as.raw(c(0x1f, 0x8b, 8, flg)),
    raw(4),
    as.raw(c(0, 3)),
    fields,
    deflate,
    raw(4),
    u32(isize)
  )
}

# Bits, least significant first, packed into bytes.
pack_bits <- function(bits) {
  bits <- c(bits, rep(0L, (8 - length(bits) %% 8) %% 8))
  m <- matrix(bits, nrow = 8)
  as.raw(colSums(m * 2^(0:7)))
}

# Feed x one byte at a time to a fresh sniffer, in C: list(bytes taken,
# type decided, decided before the end). A supplied type that stands is
# reported as its essence, as mime_sniff() does.
stream_bytewise <- function(
  x,
  limit = 4096,
  type = NULL,
  no_sniff = FALSE,
  context = "none"
) {
  supplied <- supplied_type(type)
  got <- .Call(
    zumime_stream_bytewise,
    x,
    as.double(limit),
    supplied$essence,
    supplied$apache_bug,
    no_sniff,
    check_context(context)
  )
  if (is.na(got[[2]]) && !is.null(supplied$essence)) {
    got[[2]] <- supplied$essence
  }
  got
}
