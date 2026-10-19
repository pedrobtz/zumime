# Design section 12: mime_type() over the same tree gives byte-identical
# frames on every platform. The tree is built from bytes, and its frame,
# written out as text, is compared with a literal recorded on one machine;
# every R CMD check leg (Linux, macOS, Windows, R-devel containers) runs it.

test_that("mime_type() gives the same frame on every platform", {
  dir <- local_tree(list(
    "a.csv" = "id,value\r\n1,2\r\n",
    "b.txt" = png_bytes(),
    "c.docx" = build_zip(ooxml_entries("word")),
    "d.json" = "{\"type\": \"FeatureCollection\", \"features\": []}\n",
    "e.rds" = gzip_bytes(c(charToRaw("X\n"), as.raw(c(0, 0, 0, 3)), raw(20))),
    "f.sh" = "#!/usr/bin/env bash\necho hi\n",
    "g.xml" = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><svg/>",
    "h.bin" = as.raw(c(0, 1, 2, 3, 255)),
    "i.zip" = build_zip(list(a = "x"), flags = 1L),
    "j" = c(charToRaw("caf"), as.raw(0xe9), charToRaw(" au lait\n")),
    "k.doc" = build_ole2("WordDocument"),
    "sub/l.gz" = gzip_bytes("a,b\n1,2\n")
  ))
  paths <- c(sort(list.files(dir, recursive = TRUE)), "sub", "missing.pdf")
  t <- mime_type(file.path(dir, paths), complete = TRUE)
  t$path <- paths
  lines <- vapply(
    seq_len(nrow(t)),
    function(i) {
      paste(vapply(t, function(col) format(col[i]), ""), collapse = "|")
    },
    ""
  )
  expect_identical(
    lines,
    c(
      "a.csv|text/plain|probable|UTF-8|text/csv|TRUE|NA|NA|NA|crlf|NA",
      "b.txt|image/png|definite|NA|text/plain|FALSE|NA|NA|NA|NA|NA",
      "c.docx|application/vnd.openxmlformats-officedocument.wordprocessingml.document|definite|NA|application/vnd.openxmlformats-officedocument.wordprocessingml.document|TRUE|NA|FALSE|TRUE|NA|NA",
      "d.json|application/geo+json|probable|UTF-8|application/json|TRUE|NA|NA|NA|lf|NA",
      "e.rds|application/x-rds|definite|NA|application/x-rds|TRUE|NA|NA|TRUE|NA|NA",
      "f.sh|application/x-sh|probable|UTF-8|application/x-sh|TRUE|NA|NA|NA|lf|bash",
      "g.xml|image/svg+xml|probable|ISO-8859-1|application/xml|TRUE|NA|NA|NA|NA|NA",
      "h.bin|application/octet-stream|none|NA|application/octet-stream|NA|NA|NA|NA|NA|NA",
      "i.zip|application/zip|definite|NA|application/zip|TRUE|NA|TRUE|TRUE|NA|NA",
      "j|text/plain|probable|ISO-8859-1|NA|NA|NA|NA|NA|lf|NA",
      "k.doc|application/msword|definite|NA|application/msword|TRUE|NA|NA|NA|NA|NA",
      "sub/l.gz|application/gzip|definite|NA|application/gzip|TRUE|NA|NA|TRUE|NA|NA",
      "sub|inode/directory|definite|NA|NA|NA|NA|NA|NA|NA|NA",
      "missing.pdf|NA|none|NA|application/pdf|NA|NA|NA|NA|NA|NA"
    )
  )
})
