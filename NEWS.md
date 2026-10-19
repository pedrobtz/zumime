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
* In the default `"none"` context `mime_sniff()` reads containers: ZIP entry
  names tell Office Open XML (with its macro-enabled, template and slideshow
  variants), OpenDocument, EPUB, JAR, APK and 3MF documents from plain ZIP;
  OLE2 directories tell Word, Excel, PowerPoint, Outlook and installer
  files; ISO base media brands tell MP4, M4A, M4V, QuickTime, 3GP, HEIC,
  HEIF, AVIF and CR3 apart; EBML and Ogg headers name their codecs.
* R's own files are recognised through gzip: RDS and RData, as are
  Parquet, Arrow and Feather, fst, qs2, SQLite, DuckDB, HDF5, NetCDF,
  Stata, SPSS and SAS files.
* Structured text is typed at `"probable"`: XML dialects by root element
  and namespace, JSON and its dialects by top-level keys, NDJSON, and
  line-oriented formats such as vCard, iCalendar, WebVTT and PEM.
* `encrypted` reports ZIP entries encrypted with the classic flag or AES,
  and OLE2 files holding an `EncryptionInfo` stream; `interpreter` names a
  script's shebang program.
* `text/xml` is now an alias of `application/xml`.
* `mime_type()` types files from their bytes and their names in one C
  loop, says whether the two agree, and reports what a consumer needs to
  open each file: the type inside a compression wrapper (`inner`), whether
  it is encrypted, whether it is complete (`complete = TRUE` reads the end
  of ZIP, PDF, gzip and Parquet files), its line endings and a script's
  interpreter. Unreadable paths are `NA` rows unless `strict = TRUE`.
* `mime_sniff()` also takes paths.
* `mime_check()` answers whether files are one of a set of allowed types
  from their bytes alone, faster than `mime_type()` and always with the
  same answer.
* `mime_register()` and `mime_unregister()` add a type for the session,
  detected by a byte rule in C or by an R function.
* Optional help from the family, never consulted unless asked:
  `inner = "decompress"` (zukomp), `text = "family"` (zucsv, zujson,
  zutoml) and `charset = "detect"` (zuutf). `zumime_info()$family` lists
  the family sniffers available.
