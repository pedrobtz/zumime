# a result prints as a data frame with a header

    Code
      print(mime_sniff(png_bytes()))
    Output
      <zumime_result: 1 row>
        path      type confidence charset inner encrypted complete newline
      1 <NA> image/png   definite    <NA>  <NA>        NA       NA    <NA>
        interpreter
      1        <NA>

---

    Code
      print(mime_sniff(charToRaw("hello\n")))
    Output
      <zumime_result: 1 row>
        path       type confidence charset inner encrypted complete newline
      1 <NA> text/plain   probable   UTF-8  <NA>        NA       NA      lf
        interpreter
      1        <NA>

