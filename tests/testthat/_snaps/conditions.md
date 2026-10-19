# a type error names the argument

    Code
      mime_sniff(1)
    Condition
      Error in `mime_sniff()`:
      ! `x` must be a raw vector or a character vector of paths.

# an io error names the path

    Code
      mime_type(missing, strict = TRUE)
    Condition
      Error in `mime_type()`:
      ! Cannot read "<dir>/nope.pdf": <reason>.

# a parse error names the input

    Code
      mime_parse("nope", strict = TRUE)
    Condition
      Error in `mime_parse()`:
      ! Input 1 is not a valid MIME type: "nope".

# a registry error names the type

    Code
      mime_register("image/png", "application/octet-stream")
    Condition
      Error in `mime_register()`:
      ! "image/png" is already a type.

# a dependency error names the package

    Code
      mime_type(path, inner = "decompress")
    Condition
      Error in `mime_type()`:
      ! `inner = "decompress"` needs the zukomp package, which is not installed.

# a state error says to start again

    Code
      mime_push(s, raw(1))
    Condition
      Error in `mime_push()`:
      ! The sniffer is finished; start a new one.

