# Changelog

## zumime 0.0.0.9000

- Initial CRAN submission.
- [`zumime_info()`](https://pedrobtz.github.io/zumime/reference/zumime_info.md)
  reports the package version and the version of the type tables.
- A type registry generated from IANA’s media types registry and Apache
  httpd’s `mime.types`, with parents ending at
  `application/octet-stream` and aliases.
  [`mime_types()`](https://pedrobtz.github.io/zumime/reference/mime_types.md)
  returns it; `zumime_info()$table_version` is the date of its sources.
- [`mime_guess()`](https://pedrobtz.github.io/zumime/reference/mime_guess.md)
  guesses a type from a file name, knowing compound suffixes such as
  `.tar.gz`;
  [`mime_extensions()`](https://pedrobtz.github.io/zumime/reference/mime_extensions.md)
  is the reverse.
- [`mime_parent()`](https://pedrobtz.github.io/zumime/reference/mime_parent.md)
  gives a type’s lineage and
  [`mime_is()`](https://pedrobtz.github.io/zumime/reference/mime_is.md)
  tests whether a type is, or descends from, a type, an alias or a
  top-level type.
- [`mime_parse()`](https://pedrobtz.github.io/zumime/reference/mime_parse.md)
  and
  [`mime_format()`](https://pedrobtz.github.io/zumime/reference/mime_parse.md)
  parse and serialise a MIME type as the WHATWG MIME Sniffing Standard
  defines it.
- [`mime_sniff()`](https://pedrobtz.github.io/zumime/reference/mime_sniff.md)
  runs the WHATWG MIME Sniffing Standard’s algorithm over a raw vector,
  with a supplied type, the no-sniff flag and a sniffing context, and
  reports the charset the bytes declare and their line endings. Beyond
  the standard it knows the compression wrappers, tar, ISO 9660 images,
  RAR 5, 7z, fonts and WebAssembly.
- In the default `"none"` context
  [`mime_sniff()`](https://pedrobtz.github.io/zumime/reference/mime_sniff.md)
  reads containers: ZIP entry names tell Office Open XML (with its
  macro-enabled, template and slideshow variants), OpenDocument, EPUB,
  JAR, APK and 3MF documents from plain ZIP; OLE2 directories tell Word,
  Excel, PowerPoint, Outlook and installer files; ISO base media brands
  tell MP4, M4A, M4V, QuickTime, 3GP, HEIC, HEIF, AVIF and CR3 apart;
  EBML and Ogg headers name their codecs.
- R’s own files are recognised through gzip: RDS and RData, as are
  Parquet, Arrow and Feather, fst, qs2, SQLite, DuckDB, HDF5, NetCDF,
  Stata, SPSS and SAS files.
- Structured text is typed at `"probable"`: XML dialects by root element
  and namespace, JSON and its dialects by top-level keys, NDJSON, and
  line-oriented formats such as vCard, iCalendar, WebVTT and PEM.
- `encrypted` reports ZIP entries encrypted with the classic flag or
  AES, and OLE2 files holding an `EncryptionInfo` stream; `interpreter`
  names a script’s shebang program.
- `text/xml` is now an alias of `application/xml`.
- [`mime_type()`](https://pedrobtz.github.io/zumime/reference/mime_type.md)
  types files from their bytes and their names in one C loop, says
  whether the two agree, and reports what a consumer needs to open each
  file: the type inside a compression wrapper (`inner`), whether it is
  encrypted, whether it is complete (`complete = TRUE` reads the end of
  ZIP, PDF, gzip and Parquet files), its line endings and a script’s
  interpreter. Unreadable paths are `NA` rows unless `strict = TRUE`.
- [`mime_sniff()`](https://pedrobtz.github.io/zumime/reference/mime_sniff.md)
  also takes paths.
- [`mime_check()`](https://pedrobtz.github.io/zumime/reference/mime_check.md)
  answers whether files are one of a set of allowed types from their
  bytes alone, faster than
  [`mime_type()`](https://pedrobtz.github.io/zumime/reference/mime_type.md)
  and always with the same answer.
- [`mime_register()`](https://pedrobtz.github.io/zumime/reference/mime_register.md)
  and
  [`mime_unregister()`](https://pedrobtz.github.io/zumime/reference/mime_register.md)
  add a type for the session, detected by a byte rule in C or by an R
  function.
- Optional help from the family, never consulted unless asked:
  `inner = "decompress"` (zukomp), `text = "family"` (zucsv, zujson,
  zutoml) and `charset = "detect"` (zuutf). `zumime_info()$family` lists
  the family sniffers available.
- [`mime_sniffer()`](https://pedrobtz.github.io/zumime/reference/mime_sniffer.md),
  [`mime_push()`](https://pedrobtz.github.io/zumime/reference/mime_sniffer.md)
  and
  [`mime_finish()`](https://pedrobtz.github.io/zumime/reference/mime_sniffer.md)
  sniff a stream chunk by chunk and answer as soon as the bytes seen
  decide the type.
