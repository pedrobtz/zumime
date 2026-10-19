# zumime: Media Type Detection from Bytes and File Names

Tells what a file is from its first bytes and from its name, with no
system library. Implements the 'WHATWG' 'MIME' Sniffing Standard
<https://mimesniff.spec.whatwg.org/> over raw vectors and paths,
inspects containers ('ZIP' entry names, 'ISO' base media brands, 'RIFF',
'EBML', 'Ogg', 'OLE2' directories) and recognises the data formats R
users hold, such as 'RDS', 'Parquet', 'SQLite' and 'Stata'. Every type
has a parent ending at 'application/octet-stream', and an extension
table generated from the 'IANA' media types registry and the 'Apache'
'httpd' type map answers from the name. One call reports both answers,
whether they agree, and whether a file is compressed, encrypted or
truncated.

## See also

Useful links:

- <https://github.com/pedrobtz/zumime>

- <https://pedrobtz.github.io/zumime/>

- Report bugs at <https://github.com/pedrobtz/zumime/issues>

## Author

**Maintainer**: Pedro Baltazar <pedrobtz@gmail.com> \[copyright holder\]

Authors:

- Pedro Baltazar <pedrobtz@gmail.com> \[copyright holder\]

Other contributors:

- Apache Software Foundation (copyright holder of the httpd mime.types
  file the extension table is generated from; see inst/COPYRIGHTS)
  \[copyright holder\]
