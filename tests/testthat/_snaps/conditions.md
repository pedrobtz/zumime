# each condition class has a message that names its subject

    Code
      mime_sniff(1)
    Condition
      Error in `mime_sniff()`:
      ! `x` must be a raw vector or a character vector of paths.

---

    Code
      mime_type(missing, strict = TRUE)
    Condition
      Error in `mime_type()`:
      ! Cannot read "<dir>/nope.pdf": <reason>.

---

    Code
      mime_parse("nope", strict = TRUE)
    Condition
      Error in `mime_parse()`:
      ! Input 1 is not a valid MIME type: "nope".

---

    Code
      mime_register("image/png", "application/octet-stream")
    Condition
      Error in `mime_register()`:
      ! "image/png" is already a type.

---

    Code
      mime_type(path, inner = "decompress")
    Condition
      Error in `mime_type()`:
      ! `inner = "decompress"` needs the zukomp package, which is not installed.

---

    Code
      mime_push(s, raw(1))
    Condition
      Error in `mime_push()`:
      ! The sniffer is finished; start a new one.

---

    Code
      r <- mime_sniff(charToRaw("hello"))
    Condition
      Warning:
      The rule registered for "text/x-zt-snap" failed and was taken as FALSE.

