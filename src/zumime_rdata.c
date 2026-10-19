/* R's own files inside gzip (design section 6.2): saveRDS() and save()
 * compress with gzip by default, so the serialisation header is only seen
 * after inflating the first bytes. "X\n", "A\n" or "B\n" followed by format
 * version 2 or 3 is RDS; "RDX", "RDA" or "RDB" with version 2 or 3 and a
 * newline is RData. bzip2, xz and zstd wrappers are not opened: they need
 * a full block, so those files keep their wrapper's type. */

#include <string.h>

#include "zumime_sniff.h"

static int rdata_header(const unsigned char *p, size_t n) {
  if (n >= 5 && p[0] == 'R' && p[1] == 'D' &&
      (p[2] == 'X' || p[2] == 'A' || p[2] == 'B') && (p[3] == '2' || p[3] == '3') &&
      p[4] == '\n')
    return ZUMIME_T_APPLICATION_X_RDATA;
  if (n >= 6 && (p[0] == 'X' || p[0] == 'B') && p[1] == '\n') {
    uint32_t v = p[0] == 'X'
                     ? ((uint32_t) p[2] << 24) | ((uint32_t) p[3] << 16) |
                           ((uint32_t) p[4] << 8) | p[5]
                     : zumime_le32(p + 2);
    if (v == 2 || v == 3) return ZUMIME_T_APPLICATION_X_RDS;
  }
  if (n >= 4 && p[0] == 'A' && p[1] == '\n' && (p[2] == '2' || p[2] == '3') &&
      p[3] == '\n')
    return ZUMIME_T_APPLICATION_X_RDS;
  return -1;
}

int zumime_read_gzip_rdata(const unsigned char *buf, size_t len) {
  if (len < 18 || buf[0] != 0x1F || buf[1] != 0x8B || buf[2] != 8) return -1;
  unsigned flg = buf[3];
  size_t pos = 10;
  if (flg & 4u) { /* FEXTRA */
    if (pos + 2 > len) return -1;
    pos += 2u + zumime_le16(buf + pos);
  }
  if (flg & 8u) { /* FNAME */
    while (pos < len && buf[pos] != 0) pos++;
    pos++;
  }
  if (flg & 16u) { /* FCOMMENT */
    while (pos < len && buf[pos] != 0) pos++;
    pos++;
  }
  if (flg & 2u) pos += 2; /* FHCRC */
  if (pos >= len) return -1;
  unsigned char head[16];
  size_t n = zumime_inflate(buf + pos, len - pos, head, sizeof(head));
  return rdata_header(head, n);
}
