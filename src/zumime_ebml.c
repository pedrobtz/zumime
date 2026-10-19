/* EBML (design section 6.2): the DocType element decides Matroska against
 * WebM. The standard's WebM signature looks only at the first 38 bytes;
 * this looks through the first 4 KiB of the header. */

#include <string.h>

#include "zumime_sniff.h"

int zumime_read_ebml(const unsigned char *buf, size_t len) {
  size_t end = len < 4096 ? len : 4096;
  for (size_t i = 4; i + 3 < end; i++) {
    if (buf[i] != 0x42 || buf[i + 1] != 0x82) continue;
    /* The element size: a vint whose length is its leading zero bits. */
    unsigned char first = buf[i + 2];
    size_t vlen = 1;
    while (vlen <= 8 && !(first & (0x80 >> (vlen - 1)))) vlen++;
    if (vlen > 8) continue;
    size_t at = i + 2 + vlen;
    if (at + 4 <= end && memcmp(buf + at, "webm", 4) == 0) return ZUMIME_T_VIDEO_WEBM;
    if (at + 8 <= end && memcmp(buf + at, "matroska", 8) == 0) return -1;
  }
  return -1;
}
