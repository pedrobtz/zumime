test_that("XML roots and namespaces decide the dialect", {
  decl <- "<?xml version=\"1.0\"?>\n<!-- c --><!DOCTYPE x [<!ENTITY a \"b\">]>"
  cases <- list(
    c("<svg xmlns=\"http://www.w3.org/2000/svg\"/>", "image/svg+xml"),
    c("<svg width=\"1\"/>", "image/svg+xml"),
    c("<feed xmlns=\"http://www.w3.org/2005/Atom\"/>", "application/atom+xml"),
    c("<rss version=\"2.0\"/>", "application/rss+xml"),
    c(
      paste0("<rdf:RDF xmlns:rdf=\"r\" xmlns=\"http://purl.org/rss/1.0/\"/>"),
      "application/rss+xml"
    ),
    c(
      "<kml xmlns=\"http://www.opengis.net/kml/2.2\"/>",
      "application/vnd.google-earth.kml+xml"
    ),
    c(
      "<gpx xmlns=\"http://www.topografix.com/GPX/1/1\"/>",
      "application/gpx+xml"
    ),
    c("<X3D profile=\"Immersive\"/>", "model/x3d+xml"),
    c(
      "<xliff xmlns=\"urn:oasis:names:tc:xliff:document:2.0\"/>",
      "application/xliff+xml"
    ),
    c(
      "<COLLADA xmlns=\"http://www.collada.org/2005/11/COLLADASchema\"/>",
      "model/vnd.collada+xml"
    ),
    c(
      "<html xmlns=\"http://www.w3.org/1999/xhtml\"/>",
      "application/xhtml+xml"
    ),
    c(
      "<book xmlns=\"http://docbook.org/ns/docbook\"/>",
      "application/docbook+xml"
    ),
    c(
      paste0(
        "<office:document xmlns:office=\"urn:oasis:names:tc:",
        "opendocument:xmlns:office:1.0\" office:mimetype=\"application/vnd.",
        "oasis.opendocument.text\"/>"
      ),
      "application/vnd.oasis.opendocument.text-flat-xml"
    ),
    c("<anything/>", "application/xml")
  )
  for (k in cases) {
    r <- mime_sniff(charToRaw(paste0(decl, k[1])))
    expect_identical(r$type, k[2], info = k[1])
    # A dialect is grammar; plain XML keeps the standard's signature.
    want <- if (k[2] == "application/xml") "definite" else "probable"
    expect_identical(as.character(r$confidence), want, info = k[1])
  }
})

test_that("without a declaration only a namespaced root is XML", {
  expect_identical(
    sniff_type("<svg xmlns=\"http://www.w3.org/2000/svg\"/>"),
    "image/svg+xml"
  )
  expect_identical(sniff_type("<svg width=\"1\"/>"), "text/plain")
  expect_identical(sniff_type("<rss version=\"2.0\"/>"), "text/plain")
})

test_that("XML behind a byte-order mark is XML", {
  bom8 <- c(
    as.raw(c(0xef, 0xbb, 0xbf)),
    charToRaw("<?xml version=\"1.0\"?><a/>")
  )
  expect_identical(sniff_type(bom8), "application/xml")
  le <- c(
    as.raw(c(0xff, 0xfe)),
    as.vector(rbind(charToRaw("<?xml version=\"1.0\"?>"), as.raw(0)))
  )
  expect_identical(sniff_type(le), "application/xml")
  be <- c(
    as.raw(c(0xfe, 0xff)),
    as.vector(rbind(as.raw(0), charToRaw("<?xml version=\"1.0\"?>")))
  )
  expect_identical(sniff_type(be), "application/xml")
})

test_that("JSON is scanned and its top-level keys decide dialects", {
  expect_identical(
    sniff_type("{\"a\": [1, 2.5e3, true, null, \"x\\u00e9\"]}"),
    "application/json"
  )
  expect_identical(
    sniff_type("[{\"a\": 1}, {\"b\": -0.5}]"),
    "application/json"
  )
  expect_identical(
    sniff_type("{\"type\": \"FeatureCollection\", \"features\": []}"),
    "application/geo+json"
  )
  expect_identical(
    sniff_type("{\"asset\": {\"version\": \"2.0\"}}"),
    "model/gltf+json"
  )
  expect_identical(
    sniff_type("{\"log\": {\"version\": \"1.2\"}}"),
    "application/har+json"
  )
  expect_identical(
    sniff_type("{\"bomFormat\": \"CycloneDX\"}"),
    "application/vnd.cyclonedx+json"
  )
  # Nested keys do not count.
  expect_identical(sniff_type("{\"a\": {\"asset\": 1}}"), "application/json")
  expect_identical(
    sniff_type("{\"a\": 1}\n{\"a\": 2}\n{\"a\": 3}\n"),
    "application/x-ndjson"
  )
})

test_that("text that only looks like JSON stays text", {
  for (s in c(
    "{not json}",
    "{\"a\": 1} trailing",
    "[1, 2",
    "{\"a\": 1}\n[1]",
    "{\"a\": 1} {\"b\": 2}",
    "{\"a\":\"\t\"}"
  )) {
    expect_identical(sniff_type(s), "text/plain", info = s)
  }
})

test_that("JSON cut by the read limit is still JSON", {
  long <- paste0(
    "{\"features\": [",
    paste(rep("1", 2000), collapse = ","),
    "], \"type\": \"x\"}"
  )
  expect_identical(sniff_type(long, limit = 100), "application/json")
  expect_identical(sniff_type(substr(long, 1, 100)), "text/plain")
})

test_that("the first line decides line-oriented formats", {
  cases <- list(
    c("BEGIN:VCARD\r\nVERSION:4.0\r\n", "text/vcard"),
    c("BEGIN:VCALENDAR\r\n", "text/calendar"),
    c("WEBVTT\n\n00:01.000 --> 00:02.000\nhi\n", "text/vtt"),
    c("1\n00:00:01,000 --> 00:00:02,500\nhello\n", "application/x-subrip"),
    c("WARC/1.1\r\nWARC-Type: warcinfo\r\n", "application/warc"),
    c("{\\rtf1\\ansi hello}", "application/rtf"),
    c("%!PS\n/Courier findfont\n", "application/postscript"),
    c("-----BEGIN PGP MESSAGE-----\n\nhQ\n", "application/pgp-encrypted"),
    c("-----BEGIN PGP SIGNATURE-----\n", "application/pgp-signature"),
    c("-----BEGIN PGP PUBLIC KEY BLOCK-----\n", "application/pgp-keys"),
    c("-----BEGIN CERTIFICATE-----\nMIIB\n", "application/x-pem-file")
  )
  for (k in cases) {
    expect_identical(sniff_type(k[1]), k[2], info = k[1])
  }
  expect_identical(sniff_type("WEBVTTX\n"), "text/plain")
  expect_identical(sniff_type("1\n00:00:01 --> 00:00:02\n"), "text/plain")
})

test_that("a shebang names the interpreter and the script type", {
  shebang <- function(line) mime_sniff(charToRaw(paste0(line, "\necho\n")))
  cases <- list(
    c("#!/bin/sh", "application/x-sh", "sh"),
    c("#!/usr/bin/env bash", "application/x-sh", "bash"),
    c("#!/usr/bin/env -S python3 -u", "text/x-python", "python3"),
    c("#!/usr/bin/env FOO=1 python3.12", "text/x-python", "python3.12"),
    c("#!/usr/bin/perl -w", "text/x-perl", "perl"),
    c("#!/usr/bin/php", "text/x-php", "php"),
    c("#!/usr/bin/lua5.4", "text/x-lua", "lua5.4"),
    c("#!/usr/bin/tclsh", "application/x-tcl", "tclsh"),
    c("#!/usr/bin/env node", "text/javascript", "node"),
    c("#!/usr/bin/env Rscript", "text/x-r", "Rscript"),
    c("#!/usr/local/bin/fish", "text/plain", "fish")
  )
  for (k in cases) {
    r <- shebang(k[1])
    expect_identical(r$type, k[2], info = k[1])
    expect_identical(r$interpreter, k[3], info = k[1])
  }
  expect_identical(mime_sniff(charToRaw("plain"))$interpreter, NA_character_)
  expect_identical(shebang("#!")$interpreter, NA_character_)
})

test_that("an SPSS portable file is found by its SPSSPORT marker", {
  head <- paste0(strrep("ASCII SPSS PORT FILE", 10), strrep("0", 256))
  lines <- substring(
    head,
    seq(1, nchar(head), 80),
    pmin(seq(80, nchar(head) + 79, 80), nchar(head))
  )
  por <- paste0(paste(lines, collapse = "\r\n"), "SPSSPORT", "A8/...")
  expect_identical(sniff_type(por), "application/x-spss-por")
})

test_that("XHTML without an XML declaration stays text/html", {
  # As Go's net/http, libmagic and puremagic answer: the standard's HTML
  # rows decide, and the text reader does not run after text/html.
  body <- "<html xmlns=\"http://www.w3.org/1999/xhtml\"><body/></html>"
  doctype <- paste0(
    "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" ",
    "\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">"
  )
  for (x in c(body, paste0(doctype, "\n", body))) {
    r <- mime_sniff(charToRaw(x))
    expect_identical(r$type, "text/html")
    expect_identical(as.character(r$confidence), "definite")
  }
  r <- mime_sniff(charToRaw(paste0("<?xml version=\"1.0\"?>\n", body)))
  expect_identical(r$type, "application/xhtml+xml")
})

test_that("JSON nested past the depth limit is still JSON when it closes", {
  deep <- function(d, inner = "1") {
    charToRaw(paste0(strrep("[", d), inner, strrep("]", d)))
  }
  expect_identical(sniff_type(deep(30)), "application/json")
  expect_identical(sniff_type(deep(70)), "application/json")
  # Brackets inside a string past the limit do not count.
  expect_identical(sniff_type(deep(70, "\"]]\\\"[\"")), "application/json")
  # Unclosed and whole: not JSON.
  expect_identical(sniff_type(charToRaw(strrep("[", 70))), "text/plain")
  # Unclosed but cut by the limit: JSON so far.
  long <- deep(3000)
  expect_identical(mime_sniff(long, limit = 4096)$type, "application/json")
})

test_that("an interpreter name only matches whole or before a version", {
  shebang <- function(line) mime_sniff(charToRaw(paste0(line, "\necho\n")))
  # "python" is a prefix entry, but a letter after it is another program.
  r <- shebang("#!/usr/bin/pythonista")
  expect_identical(r$type, "text/plain")
  expect_identical(r$interpreter, "pythonista")
  # "sh" is not a prefix entry: "sh5" is not a shell.
  expect_identical(shebang("#!/bin/sh5")$type, "text/plain")
})

test_that("a PEM first line needs its closing dashes", {
  expect_identical(sniff_type("-----BEGIN CERTIFICATE\nMIIB\n"), "text/plain")
  # The label is read for at most 80 bytes.
  long <- paste0("-----BEGIN ", strrep("A", 80), "-----\n")
  expect_identical(sniff_type(long), "text/plain")
  expect_identical(
    sniff_type("-----BEGIN RSA PRIVATE KEY-----\n"),
    "application/x-pem-file"
  )
  # RFC 7468 allows a hyphen between label characters.
  expect_identical(
    sniff_type("-----BEGIN FOO-BAR-----\nMIIB\n-----END FOO-BAR-----\n"),
    "application/x-pem-file"
  )
  expect_identical(
    sniff_type("-----BEGIN CERTIFICATE-----\r\nMIIB\r\n"),
    "application/x-pem-file"
  )
  # The longest label that fits closes at byte 80.
  fits <- paste0("-----BEGIN ", strrep("A", 69), "-----\n")
  expect_identical(sniff_type(fits), "application/x-pem-file")
  expect_identical(sniff_type("-----BEGIN FOO------\n"), "text/plain")
})

test_that("rarer XML roots decide their dialect or stay XML", {
  xml <- function(root) {
    mime_sniff(charToRaw(paste0("<?xml version=\"1.0\"?>", root)))$type
  }
  # RDF without the RSS 1.0 namespace is not a feed.
  expect_identical(
    xml("<rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"/>"),
    "application/xml"
  )
  expect_identical(
    xml("<kml xmlns=\"http://earth.google.com/kml/2.1\"/>"),
    "application/vnd.google-earth.kml+xml"
  )
  expect_identical(
    xml("<kml xmlns=\"http://example.org/kml/\"/>"),
    "application/xml"
  )
  odf <- function(kind) {
    paste0(
      "<office:document xmlns:office=\"urn:oasis:names:tc:",
      "opendocument:xmlns:office:1.0\" office:mimetype=\"application/vnd.",
      "oasis.opendocument.",
      kind,
      "\"/>"
    )
  }
  for (kind in c("spreadsheet", "presentation", "graphics")) {
    expect_identical(
      xml(odf(kind)),
      paste0("application/vnd.oasis.opendocument.", kind, "-flat-xml"),
      info = kind
    )
  }
  # A flat document of another kind stays XML.
  expect_identical(xml(odf("chart")), "application/xml")
})

test_that("the JSON scan checks escapes, numbers and literals", {
  expect_identical(
    sniff_type("{\"a\": \"x\\n\\t\\\"\\\\\\/\"}"),
    "application/json"
  )
  expect_identical(sniff_type("{\"a\": \"\\q\"}"), "text/plain")
  expect_identical(sniff_type("[-1, -0.5]"), "application/json")
  for (s in c("[-x]", "[-]", "[-,1]")) {
    expect_identical(sniff_type(s), "text/plain", info = s)
  }
  expect_identical(sniff_type("[false, true]"), "application/json")
  expect_identical(sniff_type("[folse]"), "text/plain")
  expect_identical(sniff_type("[x]"), "text/plain")
  # A value cannot be missing.
  expect_identical(sniff_type("[,]"), "text/plain")
  expect_identical(sniff_type("[1,]"), "text/plain")
})

test_that("a string left open past the depth limit is JSON only when cut", {
  open <- paste0(strrep("[", 70), "\"abc")
  expect_identical(sniff_type(open), "text/plain")
  expect_identical(
    sniff_type(paste0(open, strrep("d", 200)), limit = 100),
    "application/json"
  )
  # An escape as the last byte in hand steps past the end.
  cut <- paste0(strrep("[", 70), "\"", strrep("\\", 40))
  expect_identical(sniff_type(cut, limit = 100), "application/json")
})

test_that("text missing one marker of a format stays the coarser type", {
  # GeoJSON needs features or geometry beside type.
  expect_identical(sniff_type('{"type": "x"}'), "application/json")
  # SPSSPORT counts only after the 440-byte header.
  expect_identical(sniff_type("hello SPSSPORT\n"), "text/plain")
  # A SubRip cue needs the arrow between its two times.
  expect_identical(
    sniff_type("1\n00:00:01,000 ==> 00:00:02,000\nhi\n"),
    "text/plain"
  )
  # NDJSON needs a line end after every record.
  expect_identical(sniff_type('{"a":1}\n{"a":2} {"a":3}'), "text/plain")
})
