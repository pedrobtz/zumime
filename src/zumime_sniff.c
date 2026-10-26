/* The WHATWG MIME type sniffing algorithm (design section 6.1): the pattern
 * matching algorithm, the MP4, WebM and MP3 signatures, "identifying a
 * resource with an unknown MIME type", "distinguishing if a resource is
 * text or binary", the computed MIME type, and the context-specific
 * algorithms for image, audio or video, and font contexts. */

#include <string.h>

#include "zumime_sniff.h"

/* --- Byte classes ---------------------------------------------------------- */

static int is_ws_byte(unsigned char c) {
  return c == 0x09 || c == 0x0A || c == 0x0C || c == 0x0D || c == 0x20;
}

static int is_tt_byte(unsigned char c) { return c == 0x20 || c == 0x3E; }

static int is_binary_byte(unsigned char c) {
  return c <= 0x08 || c == 0x0B || (c >= 0x0E && c <= 0x1A) ||
         (c >= 0x1C && c <= 0x1F);
}

static int has_binary_bytes(const unsigned char *buf, size_t len) {
  for (size_t i = 0; i < len; i++)
    if (is_binary_byte(buf[i])) return 1;
  return 0;
}

/* --- Registry helpers ------------------------------------------------------ */

int zumime_type_is(int type, int ancestor) {
  int guard = 0;
  while (type >= 0 && guard++ < ZUMIME_N_TYPES + ZUMIME_MAX_REGISTERED) {
    if (type == ancestor) return 1;
    type = zumime_type_parent(type);
  }
  return 0;
}

int zumime_type_lookup(const char *name) {
  int lo = 0, hi = ZUMIME_N_TYPES - 1;
  while (lo <= hi) {
    int mid = lo + (hi - lo) / 2;
    int c = strcmp(name, zumime_type_names[mid]);
    if (c == 0) return mid;
    if (c < 0)
      hi = mid - 1;
    else
      lo = mid + 1;
  }
  for (int k = 0; k < ZUMIME_MAX_REGISTERED; k++)
    if (zumime_reg[k].active && strcmp(zumime_reg[k].name, name) == 0)
      return ZUMIME_N_TYPES + k;
  return -1;
}

/* --- The pattern matching algorithm (standard section 6) ------------------ */

/* The tar header checksum: the sum of the 512 header bytes with the
 * checksum field (148..155) counted as spaces, against that field read as
 * octal. Both the unsigned and the historical signed sums are accepted. */
static int tar_checksum_ok(const unsigned char *buf, size_t len) {
  if (len < 512) return 0;
  unsigned long usum = 0;
  long ssum = 0;
  for (size_t i = 0; i < 512; i++) {
    unsigned char c = (i >= 148 && i < 156) ? 0x20 : buf[i];
    usum += c;
    ssum += (signed char) c;
  }
  size_t i = 148;
  while (i < 156 && (buf[i] == ' ' || buf[i] == 0)) i++;
  if (i == 156) return 0;
  unsigned long field = 0;
  int digits = 0;
  while (i < 156 && buf[i] >= '0' && buf[i] <= '7') {
    field = field * 8 + (unsigned long) (buf[i] - '0');
    i++;
    digits++;
  }
  if (digits == 0) return 0;
  return field == usum || (long) field == ssum;
}

int zumime_match_row(const zumime_sig *row, const unsigned char *buf,
                     size_t len) {
  const unsigned char *pat = (const unsigned char *) row->pattern;
  const unsigned char *mask = (const unsigned char *) row->mask;
  size_t plen = row->len;
  size_t off = row->offset;

  if (len < off || len - off < plen) return 0;
  size_t s = off;
  if (row->flags & ZUMIME_SIG_WS) {
    while (s < len && is_ws_byte(buf[s])) s++;
  }
  for (size_t p = 0; p < plen; p++, s++) {
    if (s >= len) return 0;
    if ((row->flags & ZUMIME_SIG_TT) && p == plen - 1) {
      if (!is_tt_byte(buf[s])) return 0;
      continue;
    }
    unsigned char m = mask ? mask[p] : 0xFF;
    if ((buf[s] & m) != pat[p]) return 0;
  }
  if ((row->flags & ZUMIME_SIG_TAR) && !tar_checksum_ok(buf, len)) return 0;
  return 1;
}

/* First matching row of a group, or -1. */
static int match_group(int group, const unsigned char *buf, size_t len) {
  for (int i = 0; i < zumime_n_sigs; i++) {
    const zumime_sig *row = &zumime_sigs[i];
    if (row->group != group || row->parent >= 0) continue;
    if (zumime_match_row(row, buf, len)) return row->type;
  }
  return -1;
}

/* --- MP4 (standard section 6.2.1) ------------------------------------------ */

static uint32_t be32(const unsigned char *p) {
  return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) |
         ((uint32_t) p[2] << 8) | (uint32_t) p[3];
}

int zumime_match_mp4(const unsigned char *buf, size_t len) {
  if (len < 12) return 0;
  uint32_t box = be32(buf);
  if (len < box || box % 4 != 0) return 0;
  if (memcmp(buf + 4, "ftyp", 4) != 0) return 0;
  if (memcmp(buf + 8, "mp4", 3) == 0) return 1;
  for (size_t read = 16; read < box; read += 4) {
    if (read + 3 > len) return 0;
    if (memcmp(buf + read, "mp4", 3) == 0) return 1;
  }
  return 0;
}

/* --- WebM (standard section 6.2.2) ----------------------------------------- */

/* "Parse a vint" at buf[iter]: returns the number size. The standard
 * starts its index at 0; the vint is at iter, which is what is meant. */
static size_t parse_vint(const unsigned char *buf, size_t len, size_t iter) {
  unsigned mask = 128;
  size_t size = 1;
  while (size < 8 && size < len - iter) {
    if (buf[iter] & mask) break;
    mask >>= 1;
    size++;
  }
  return size;
}

/* "Matching a padded sequence": the pattern at offset, after any 0x00
 * bytes. */
static int match_padded(const unsigned char *buf, size_t len, size_t off,
                        const char *pat, size_t plen) {
  while (off < len && buf[off] == 0x00) off++;
  if (off > len || len - off < plen) return 0;
  return memcmp(buf + off, pat, plen) == 0;
}

int zumime_match_webm(const unsigned char *buf, size_t len) {
  static const unsigned char ebml[4] = {0x1A, 0x45, 0xDF, 0xA3};
  if (len < 4 || memcmp(buf, ebml, 4) != 0) return 0;
  size_t iter = 4;
  while (iter < len && iter < 38) {
    if (iter + 1 < len && buf[iter] == 0x42 && buf[iter + 1] == 0x82) {
      iter += 2;
      if (iter >= len) return 0;
      iter += parse_vint(buf, len, iter);
      if (len < 4 || iter >= len - 4) return 0;
      if (match_padded(buf, len, iter, "webm", 4)) return 1;
    }
    iter++;
  }
  return 0;
}

/* --- MP3 without ID3 (standard section 6.2.3) -------------------------------
 * The standard's text has operator-precedence slips ("& 0x06 >> 1") and an
 * inverted rate table; this follows Mozilla's mp3sniff.c, which it
 * describes: Layer III frames only, MPEG-1 rates for version bit 0 set.
 * Both scale every frame by 144, which is MPEG-1's; a Layer III frame of
 * MPEG-2 or 2.5 is 72 * bitrate / rate, which is used here. */

static int mp3_header_ok(const unsigned char *p, size_t avail) {
  if (avail < 4) return 0;
  if (p[0] != 0xFF || (p[1] & 0xE0) != 0xE0) return 0;
  int layer = (p[1] & 0x06) >> 1;
  if (layer == 0) return 0;
  if (((p[2] & 0xF0) >> 4) == 15) return 0;
  if (((p[2] & 0x0C) >> 2) == 3) return 0;
  return 4 - layer == 3;
}

static long mp3_frame_size(const unsigned char *p) {
  static const long rates[2][16] = {
      {0, 32000, 40000, 48000, 56000, 64000, 80000, 96000, 112000, 128000,
       160000, 192000, 224000, 256000, 320000, 0},
      {0, 8000, 16000, 24000, 32000, 40000, 48000, 56000, 64000, 80000, 96000,
       112000, 128000, 144000, 160000, 0}};
  static const long samplerates[4] = {44100, 48000, 32000, 0};
  int version = (p[1] & 0x18) >> 3;
  long bitrate = rates[(version & 1) ? 0 : 1][(p[2] & 0xF0) >> 4];
  long freq = samplerates[(p[2] & 0x0C) >> 2];
  if (version == 2)
    freq >>= 1;
  else if (version == 0)
    freq >>= 2;
  /* Not reachable from the tests: mp3_header_ok() refuses the reserved
   * sample-rate index 3 before a frame size is asked for. */
  if (freq == 0) return 0;
  int pad = (p[2] & 0x02) >> 1;
  long scale = (version == 3) ? 144 : 72; /* MPEG-1 : MPEG-2 and 2.5 */
  long size = bitrate * scale / freq;
  if (pad) size++;
  return size;
}

int zumime_match_mp3(const unsigned char *buf, size_t len) {
  if (!mp3_header_ok(buf, len)) return 0;
  long skip = mp3_frame_size(buf);
  if (skip < 4 || (size_t) skip > len) return 0;
  return mp3_header_ok(buf + skip, len - (size_t) skip);
}

/* --- The type pattern matching algorithms (standard sections 6.1 - 6.4) --- */

static int match_audio_video(const unsigned char *buf, size_t len) {
  int t = match_group(ZUMIME_GROUP_AUDIO_VIDEO, buf, len);
  if (t >= 0) return t;
  if (zumime_match_mp4(buf, len)) return ZUMIME_T_VIDEO_MP4;
  if (zumime_match_webm(buf, len)) return ZUMIME_T_VIDEO_WEBM;
  if (zumime_match_mp3(buf, len)) return ZUMIME_T_AUDIO_MPEG;
  return -1;
}

/* --- Supplied type classes (standard section 4.6) ------------------------- */

static int ends_with(const char *s, const char *suffix) {
  size_t n = strlen(s), m = strlen(suffix);
  return n >= m && strcmp(s + n - m, suffix) == 0;
}

static int starts_with(const char *s, const char *prefix) {
  return strncmp(s, prefix, strlen(prefix)) == 0;
}

static int supplied_is_xml(const char *s) {
  return ends_with(s, "+xml") || strcmp(s, "text/xml") == 0 ||
         strcmp(s, "application/xml") == 0;
}

static int supplied_is_html(const char *s) { return strcmp(s, "text/html") == 0; }

static int supplied_is_image(const char *s) { return starts_with(s, "image/"); }

static int supplied_is_audio_video(const char *s) {
  return starts_with(s, "audio/") || starts_with(s, "video/") ||
         strcmp(s, "application/ogg") == 0;
}

static int supplied_is_unknown(const char *s) {
  return s == NULL || strcmp(s, "unknown/unknown") == 0 ||
         strcmp(s, "application/unknown") == 0 || strcmp(s, "*/*") == 0;
}

/* --- Results --------------------------------------------------------------- */

static void set(zumime_result *out, int type, int confidence) {
  out->type = type;
  out->confidence = confidence;
}

static void floor_type(const unsigned char *buf, size_t hlen,
                       zumime_result *out) {
  if (!has_binary_bytes(buf, hlen))
    set(out, ZUMIME_T_TEXT_PLAIN, ZUMIME_CONF_PROBABLE);
  else
    set(out, ZUMIME_T_APPLICATION_OCTET_STREAM, ZUMIME_CONF_NONE);
}

/* The computed type is the supplied type, or the floor when there is none:
 * a context algorithm can end with an undefined supplied type. */
static void supplied_or_floor(const zumime_input *in, zumime_result *out) {
  if (in->supplied != NULL)
    set(out, ZUMIME_SUPPLIED, ZUMIME_CONF_NONE);
  else
    set(out, ZUMIME_T_APPLICATION_OCTET_STREAM, ZUMIME_CONF_NONE);
}

/* Standard section 7.1, with zumime's rows in the "none" context. */
static void identify_unknown(const unsigned char *buf, size_t hlen,
                             int sniff_scriptable, zumime_result *out) {
  int t = -1;
  if (sniff_scriptable) t = match_group(ZUMIME_GROUP_SCRIPTABLE, buf, hlen);
  if (t < 0) t = match_group(ZUMIME_GROUP_NONSCRIPTABLE, buf, hlen);
  if (t < 0) t = match_group(ZUMIME_GROUP_IMAGE, buf, hlen);
  if (t < 0) t = match_audio_video(buf, hlen);
  if (t < 0) t = match_group(ZUMIME_GROUP_ARCHIVE, buf, hlen);
  if (t >= 0) {
    set(out, t, ZUMIME_CONF_DEFINITE);
    return;
  }
  floor_type(buf, hlen, out);
}

/* zumime's own rows: after the standard's tables, and only where the
 * standard found binary bytes and nothing else, so a text file that starts
 * "wOFF" or "BZh" stays text. The offset rows (tar at 257, ISO 9660 at
 * 32769) look past the resource header into what was read. */
static void extend(const unsigned char *buf, size_t len, zumime_result *out) {
  if (out->type != ZUMIME_T_APPLICATION_OCTET_STREAM) return;
  int t = match_group(ZUMIME_GROUP_EXTRA, buf, len);
  if (t >= 0) set(out, t, ZUMIME_CONF_DEFINITE);
}

/* Standard section 7.2. */
static void text_or_binary(const unsigned char *buf, size_t hlen,
                           zumime_result *out) {
  if (hlen >= 2 && ((buf[0] == 0xFE && buf[1] == 0xFF) ||
                    (buf[0] == 0xFF && buf[1] == 0xFE))) {
    set(out, ZUMIME_T_TEXT_PLAIN, ZUMIME_CONF_DEFINITE);
    return;
  }
  if (hlen >= 3 && buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF) {
    set(out, ZUMIME_T_TEXT_PLAIN, ZUMIME_CONF_DEFINITE);
    return;
  }
  floor_type(buf, hlen, out);
}

/* Standard section 7 (and 8.1, the browsing context). */
static void computed_type(const unsigned char *buf, size_t hlen,
                          const zumime_input *in, zumime_result *out) {
  const char *s = in->supplied;
  if (s != NULL && (supplied_is_xml(s) || supplied_is_html(s))) {
    set(out, ZUMIME_SUPPLIED, ZUMIME_CONF_NONE);
    return;
  }
  if (supplied_is_unknown(s)) {
    identify_unknown(buf, hlen, !in->no_sniff, out);
    return;
  }
  if (in->no_sniff) {
    set(out, ZUMIME_SUPPLIED, ZUMIME_CONF_NONE);
    return;
  }
  if (in->apache_bug) {
    text_or_binary(buf, hlen, out);
    return;
  }
  int t = -1;
  if (supplied_is_image(s)) t = match_group(ZUMIME_GROUP_IMAGE, buf, hlen);
  if (t < 0 && supplied_is_audio_video(s)) t = match_audio_video(buf, hlen);
  if (t >= 0)
    set(out, t, ZUMIME_CONF_DEFINITE);
  else
    set(out, ZUMIME_SUPPLIED, ZUMIME_CONF_NONE);
}

/* Standard sections 8.2, 8.3 and 8.7. */
static void context_type(const unsigned char *buf, size_t hlen,
                         const zumime_input *in, zumime_result *out) {
  if (in->supplied != NULL && supplied_is_xml(in->supplied)) {
    set(out, ZUMIME_SUPPLIED, ZUMIME_CONF_NONE);
    return;
  }
  int t;
  switch (in->context) {
  case ZUMIME_CTX_IMAGE:
    t = match_group(ZUMIME_GROUP_IMAGE, buf, hlen);
    break;
  case ZUMIME_CTX_AUDIO_VIDEO:
    t = match_audio_video(buf, hlen);
    break;
  default:
    t = match_group(ZUMIME_GROUP_FONT, buf, hlen);
    break;
  }
  if (t >= 0)
    set(out, t, ZUMIME_CONF_DEFINITE);
  else
    supplied_or_floor(in, out);
}

void zumime_sniff(const unsigned char *buf, size_t len, const zumime_input *in,
                  zumime_result *out) {
  size_t hlen = len < ZUMIME_HEADER_LEN ? len : ZUMIME_HEADER_LEN;
  memset(out, 0, sizeof(*out));

  if (in->context == ZUMIME_CTX_NONE || in->context == ZUMIME_CTX_BROWSING)
    computed_type(buf, hlen, in, out);
  else
    context_type(buf, hlen, in, out);

  out->encrypted = -1;
  if (in->context == ZUMIME_CTX_NONE && out->type != ZUMIME_SUPPLIED) {
    extend(buf, len, out);
    if (in->base_only) return;
    zumime_refine(buf, len, in, out);
    if (!in->defer_registered) zumime_apply_registered(buf, len, out);
  }

  /* Charset and line endings, for a text result. */
  int is_text, is_xml, is_html;
  if (out->type == ZUMIME_SUPPLIED) {
    const char *s = in->supplied;
    is_xml = supplied_is_xml(s);
    is_html = supplied_is_html(s);
    is_text = in->supplied_id >= 0
                  ? zumime_type_is(in->supplied_id, ZUMIME_T_TEXT_PLAIN)
                  : starts_with(s, "text/");
  } else {
    is_xml = zumime_type_is(out->type, ZUMIME_T_APPLICATION_XML);
    is_html = out->type == ZUMIME_T_TEXT_HTML;
    is_text = zumime_type_is(out->type, ZUMIME_T_TEXT_PLAIN);
  }
  /* A charset and line endings belong to text: a text type whose bytes are
   * binary (a DOS EPS header, a WARC record's payload) has neither, unless
   * a byte-order mark says the binary bytes are UTF-16. */
  int bom = len >= 2 && ((buf[0] == 0xFE && buf[1] == 0xFF) ||
                         (buf[0] == 0xFF && buf[1] == 0xFE));
  if (is_text && (bom || !has_binary_bytes(buf, len))) {
    zumime_charset(buf, len, in->truncated, is_xml, is_html, out);
    out->newline = zumime_newline_style(buf, len);
  }
}
