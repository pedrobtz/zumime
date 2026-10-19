/* ISO base media files (design section 6.2): the ftyp box's major and
 * compatible brands decide MP4, M4A, M4V, QuickTime, 3GP, HEIC, HEIF, AVIF
 * and Canon CR3. A major brand that names a format decides; a generic MP4
 * major brand (isom, mp41) defers to a specific compatible brand. QuickTime
 * movies that start with another atom are recognised by that atom. */

#include <string.h>

#include "zumime_sniff.h"

static int brand_is(const unsigned char *b, const char *lit) {
  return memcmp(b, lit, 4) == 0;
}

static int specific_brand(const unsigned char *b) {
  if (brand_is(b, "qt  ")) return ZUMIME_T_VIDEO_QUICKTIME;
  /* iTunes brands; some writers end them with NUL instead of a space. */
  if (memcmp(b, "M4A", 3) == 0 || memcmp(b, "M4B", 3) == 0 ||
      memcmp(b, "M4P", 3) == 0)
    return ZUMIME_T_AUDIO_MP4;
  if (memcmp(b, "M4V", 3) == 0) return ZUMIME_T_VIDEO_X_M4V;
  if (memcmp(b, "3g2", 3) == 0) return ZUMIME_T_VIDEO_3GPP2;
  if (memcmp(b, "3gp", 3) == 0 || memcmp(b, "3ge", 3) == 0 ||
      memcmp(b, "3gg", 3) == 0 || memcmp(b, "3gs", 3) == 0)
    return ZUMIME_T_VIDEO_3GPP;
  if (brand_is(b, "heic") || brand_is(b, "heix") || brand_is(b, "heim") ||
      brand_is(b, "heis"))
    return ZUMIME_T_IMAGE_HEIC;
  if (brand_is(b, "hevc") || brand_is(b, "hevx") || brand_is(b, "hevm") ||
      brand_is(b, "hevs"))
    return ZUMIME_T_IMAGE_HEIC_SEQUENCE;
  if (brand_is(b, "avif") || brand_is(b, "avis")) return ZUMIME_T_IMAGE_AVIF;
  if (brand_is(b, "crx ")) return ZUMIME_T_IMAGE_X_CANON_CR3;
  if (brand_is(b, "F4A ") || brand_is(b, "F4B ")) return ZUMIME_T_AUDIO_MP4;
  return -1;
}

static int generic_brand(const unsigned char *b) {
  if (brand_is(b, "mif1")) return ZUMIME_T_IMAGE_HEIF;
  if (brand_is(b, "msf1")) return ZUMIME_T_IMAGE_HEIF_SEQUENCE;
  if (memcmp(b, "iso", 3) == 0 || brand_is(b, "mp41") || brand_is(b, "mp42") ||
      brand_is(b, "mp71") || brand_is(b, "avc1") || brand_is(b, "dash") ||
      brand_is(b, "f4v ") || brand_is(b, "F4V ") || brand_is(b, "F4P ") ||
      brand_is(b, "MSNV") || brand_is(b, "NDAS"))
    return ZUMIME_T_VIDEO_MP4;
  return -1;
}

/* A QuickTime movie may begin with a moov, mdat, wide, free, skip or pnot
 * atom instead of an ftyp box. */
static int quicktime_atom(const unsigned char *t) {
  return memcmp(t, "moov", 4) == 0 || memcmp(t, "mdat", 4) == 0 ||
         memcmp(t, "wide", 4) == 0 || memcmp(t, "free", 4) == 0 ||
         memcmp(t, "skip", 4) == 0 || memcmp(t, "pnot", 4) == 0;
}

int zumime_read_bmff(const unsigned char *buf, size_t len) {
  if (len < 12) return -1;
  if (memcmp(buf + 4, "ftyp", 4) != 0)
    return quicktime_atom(buf + 4) ? ZUMIME_T_VIDEO_QUICKTIME : -1;
  uint32_t box = ((uint32_t) buf[0] << 24) | ((uint32_t) buf[1] << 16) |
                 ((uint32_t) buf[2] << 8) | buf[3];
  if (box < 12) return -1;
  size_t end = box < len ? box : len;
  /* The major brand decides when it names a format, generic or not; a
   * generic MP4 major brand defers to a specific compatible brand. */
  int t = specific_brand(buf + 8);
  if (t >= 0) return t;
  if (brand_is(buf + 8, "mif1")) return ZUMIME_T_IMAGE_HEIF;
  if (brand_is(buf + 8, "msf1")) return ZUMIME_T_IMAGE_HEIF_SEQUENCE;
  for (size_t i = 16; t < 0 && i + 4 <= end; i += 4) t = specific_brand(buf + i);
  if (t >= 0) return t;
  t = generic_brand(buf + 8);
  for (size_t i = 16; t < 0 && i + 4 <= end; i += 4) t = generic_brand(buf + i);
  return t;
}
