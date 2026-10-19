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
