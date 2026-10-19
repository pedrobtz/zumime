# zumime 0.0.0.9000

* Initial CRAN submission.
* `zumime_info()` reports the package version and the version of the type
  tables.
* A type registry generated from IANA's media types registry and Apache
  httpd's `mime.types`, with parents ending at `application/octet-stream`
  and aliases. `mime_types()` returns it; `zumime_info()$table_version` is
  the date of its sources.
* `mime_guess()` guesses a type from a file name, knowing compound suffixes
  such as `.tar.gz`; `mime_extensions()` is the reverse.
* `mime_parent()` gives a type's lineage and `mime_is()` tests whether a
  type is, or descends from, a type, an alias or a top-level type.
* `mime_parse()` and `mime_format()` parse and serialise a MIME type as the
  WHATWG MIME Sniffing Standard defines it.
* `mime_sniff()` runs the WHATWG MIME Sniffing Standard's algorithm over a
  raw vector, with a supplied type, the no-sniff flag and a sniffing
  context, and reports the charset the bytes declare and their line
  endings. Beyond the standard it knows the compression wrappers, tar, ISO
  9660 images, RAR 5, 7z, fonts and WebAssembly.
