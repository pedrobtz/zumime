# zumime: Media Type Detection from Bytes and File Names

Tells what a file is from its first bytes and from its name, with no
system library. Implements the Web Hypertext Application Technology
Working Group (WHATWG) Multipurpose Internet Mail Extensions (MIME)
Sniffing Standard <https://mimesniff.spec.whatwg.org/> over raw vectors
and paths. Reads inside containers to tell Office documents from plain
'ZIP' archives, audio from video in 'MP4' files, and Word from Excel in
legacy Office files, and recognises the data files 'R' users hold, such
as files saved by 'R', 'Parquet', 'SQLite' and 'Stata' files. Every type
has a parent in a hierarchy, and an extension table generated from the
Internet Assigned Numbers Authority (IANA) media types registry and the
'Apache' 'httpd' type map answers from the name. One call reports both
answers, whether they agree, and whether a file is compressed, encrypted
or truncated.

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
