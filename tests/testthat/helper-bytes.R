# Byte builders for sniffer tests.

png_bytes <- function() {
  as.raw(c(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0x0d))
}

# A 512-byte ustar header for a file named `name`, with a valid checksum.
tar_header <- function(name = "a.txt") {
  h <- raw(512)
  put <- function(h, off, s) {
    b <- if (is.raw(s)) s else charToRaw(s)
    h[off + seq_along(b)] <- b
    h
  }
  h <- put(h, 0, name)
  h <- put(h, 100, "0000644")
  h <- put(h, 108, "0000000")
  h <- put(h, 116, "0000000")
  h <- put(h, 124, "00000000000")
  h <- put(h, 136, "00000000000")
  h <- put(h, 148, "        ")
  h <- put(h, 156, "0")
  h <- put(h, 257, "ustar")
  h <- put(h, 263, "00")
  sum <- sum(as.integer(h))
  put(h, 148, c(charToRaw(sprintf("%06o", sum)), as.raw(c(0, 0x20))))
}

# An MPEG-1 Layer III frame header (128 kbit/s, 44.1 kHz, no padding),
# whose frame is 417 bytes long.
mp3_frame <- function() as.raw(c(0xff, 0xfb, 0x90, 0x00))

sniff_charset <- function(...) mime_sniff(...)$charset

# Sniff a generated signature input in its row's group context: font rows
# (group 4) are only consulted in the font context.
sniff_row <- function(rows, i, bytes) {
  group <- rows$group[i]
  context <- if (group == 4L) "font" else "none"
  mime_sniff(bytes, context = context, limit = 0)
}

row_input <- function(rows, i) {
  off <- rows$offset[i]
  pat <- rows$pattern[[i]]
  if (bitwAnd(rows$flags[i], 4L) != 0L) {
    bytes <- c(tar_header(), raw(1024))
  } else {
    bytes <- raw(max(1445L, off + length(pat)))
    bytes[off + seq_along(pat)] <- pat
  }
  bytes
}
