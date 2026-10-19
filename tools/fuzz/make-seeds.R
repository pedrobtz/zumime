# Writes the seed corpus tools/fuzz/seeds/ from the test suite's byte
# builders: one small input per kind of answer. Run from the package root:
#   Rscript tools/fuzz/make-seeds.R
#   Rscript tools/fuzz/make-seeds.R --check   # exit 1 if seeds/ differs
# Deflated seeds come from the zlib R links to, and macOS's zlib compresses
# differently from Linux's: check where the seeds were written.
check <- "--check" %in% commandArgs(trailingOnly = TRUE)
for (f in list.files("tests/testthat", "^helper-.*\\.R$", full.names = TRUE)) {
  source(f)
}
suppressMessages(pkgload::load_all(quiet = TRUE))
seeds <- "tools/fuzz/seeds"
dir <- if (check) tempfile("seeds") else seeds
unlink(dir, recursive = TRUE)
dir.create(dir, recursive = TRUE)
inputs <- c(stream_inputs(), list(
  zip_cd = build_zip(c(list(big = as.raw(rep(1:255, 4))), ooxml_entries("xl"))),
  zip_enc = build_zip(list(a = "x"), flags = 1L),
  odt = build_zip(list(mimetype = "application/vnd.oasis.opendocument.text")),
  ooxml_deflate = build_zip(ooxml_entries("ppt", main_ct = paste0(
    "application/vnd.openxmlformats-officedocument.presentationml.",
    "slideshow.main+xml")), method = 8L),
  msi = build_ole2("x", clsid = msi_clsid()),
  heic = build_ftyp("mif1", c("heic")),
  svg = charToRaw("<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\"/>"),
  meta = charToRaw("<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=koi8-r\">"),
  ndjson = charToRaw("{\"a\":1}\n{\"b\":2}\n"),
  shebang = charToRaw("#!/usr/bin/env -S python3 -u\nprint(1)\n"),
  srt = charToRaw("1\n00:00:01,000 --> 00:00:02,000\nhi\n"),
  webm = c(as.raw(c(0x1a, 0x45, 0xdf, 0xa3, 0x9f, 0x42, 0x86, 0x81, 0x01,
    0x42, 0x82, 0x84)), charToRaw("webm"), raw(20)),
  utf16 = c(as.raw(c(0xff, 0xfe)), as.vector(rbind(charToRaw("<?xml?>"), as.raw(0))))
))
for (name in names(inputs)) writeBin(inputs[[name]], file.path(dir, name))
if (check) {
  files <- union(list.files(dir), list.files(seeds))
  md5 <- function(d) unname(tools::md5sum(file.path(d, files)))
  differ <- files[is.na(md5(dir)) | is.na(md5(seeds)) | md5(dir) != md5(seeds)]
  if (length(differ) > 0) {
    cat(seeds, "differs from make-seeds.R in:", differ, "\n")
    quit(status = 1)
  }
  cat(seeds, "matches make-seeds.R\n")
} else {
  cat(length(inputs), "seeds written to", dir, "\n")
}
