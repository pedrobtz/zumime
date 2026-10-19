/* PNG (design section 6.2): an acTL chunk before the first IDAT makes the
 * file an animated PNG. */

#include <string.h>

#include "zumime_sniff.h"

int zumime_read_png(const unsigned char *buf, size_t len) {
  size_t pos = 8;
  for (int k = 0; k < 64 && pos + 8 <= len; k++) {
    uint32_t n = ((uint32_t) buf[pos] << 24) | ((uint32_t) buf[pos + 1] << 16) |
                 ((uint32_t) buf[pos + 2] << 8) | buf[pos + 3];
    const unsigned char *type = buf + pos + 4;
    if (memcmp(type, "acTL", 4) == 0) return ZUMIME_T_IMAGE_APNG;
    if (memcmp(type, "IDAT", 4) == 0) return -1;
    if ((uint64_t) pos + 12 + n > len) return -1;
    pos += 12 + n;
  }
  return -1;
}
