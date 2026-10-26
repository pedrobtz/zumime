# zumime 0.1.0

* Initial CRAN submission.

zumime tells what a file is from its bytes and from its name, with no
dependency and no system library.

* `mime_sniff()` runs the WHATWG MIME Sniffing Standard over a raw vector or
  paths, with a supplied type, the no-sniff flag and a sniffing context, and
  reports the charset the bytes declare and their line endings.
* Beyond the standard, in the default context, container readers tell
  Office Open XML (with its macro-enabled, template and slideshow
  variants), OpenDocument, EPUB, JAR and APK from plain ZIP; Word, Excel,
  PowerPoint, Outlook and installer files from OLE2; MP4, M4A, M4V,
  QuickTime, 3GP, HEIC, HEIF and AVIF by their brands; WebM from Matroska;
  and Ogg codecs. R's own RDS and RData files are recognised through gzip,
  as are Parquet, Arrow, fst, qs2, SQLite, DuckDB, HDF5, NetCDF, Stata,
  SPSS and SAS files, executables and common archives.
* Structured text is typed at `"probable"`: XML dialects by root element and
  namespace, JSON and its dialects by top-level keys, NDJSON, line formats
  such as vCard, iCalendar, WebVTT and PEM, and scripts by their shebang.
* `mime_type()` types paths from bytes and name in one C loop, says whether
  the two agree, and reports what a consumer needs before opening a file:
  the type inside a compression wrapper, encryption, completeness (with
  `complete = TRUE`), line endings and a script's interpreter. Directories,
  FIFOs, devices and sockets are typed `inode/*` without being opened.
* `mime_check()` answers whether files are one of a set of allowed types
  from their bytes alone, with the same answer as `mime_type()`.
* `mime_sniffer()`, `mime_push()` and `mime_finish()` sniff a stream chunk by
  chunk and answer as soon as the bytes decide the type.
* A type registry generated from IANA's media types registry and Apache
  httpd's `mime.types`: `mime_types()`, `mime_guess()`, `mime_extensions()`,
  `mime_parent()` and `mime_is()`. Every type has a parent, ending at
  `application/octet-stream`; `zumime_info()$table_version` dates the
  sources.
* `mime_parse()` and `mime_format()` parse and serialise a MIME type as the
  WHATWG standard defines it.
* `mime_register()` and `mime_unregister()` add a type for the session,
  with a data rule matched in C or a function rule called from R. Either
  refines only what zumime sniffs in the default context.
* Optional help from the family, used only when asked: `inner =
  "decompress"` (zukomp), `text = "family"` (zucsv, zujson, zutoml) and
  `charset = "detect"` (zuutf).
