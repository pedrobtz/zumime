/* The incremental sniffer's "can decide" rule (design section 6.10): the
 * bytes seen decide the type when no longer row could override the match,
 * the reader for the type has what it needs, or `limit` bytes have
 * arrived.
 *
 * The rule is conservative. A row is "pending" when the bytes in hand agree
 * with it so far but do not reach its end; any pending row earlier in the
 * order the algorithm consults (the standard's tables, its MP4, WebM and
 * MP3 signatures, then zumime's rows) keeps the sniffer undecided, whatever
 * the context. Text is never decided early: a binary byte, a charset
 * declaration or a later line can still change it. */

#include <string.h>

#include "zumime_sniff.h"

static int is_ws_byte(unsigned char c) {
  return c == 0x09 || c == 0x0A || c == 0x0C || c == 0x0D || c == 0x20;
}

/* 1 when more bytes could still make `row` match. */
static int row_pending(const zumime_sig *row, const unsigned char *buf,
                       size_t len, size_t limit) {
  size_t off = row->offset;
  if ((uint64_t) off + row->len > limit) return 0; /* never reachable */
  size_t s = off;
  if (off >= len) return 1;
  if (row->flags & ZUMIME_SIG_WS) {
    while (s < len && is_ws_byte(buf[s])) s++;
    if (s >= len) return 1;
  }
  for (size_t p = 0; p < row->len; p++, s++) {
    if (s >= len) return 1;
    if ((row->flags & ZUMIME_SIG_TT) && p == (size_t) row->len - 1) {
      if (buf[s] != 0x20 && buf[s] != 0x3E) return 0;
      continue;
    }
    unsigned char m = row->mask ? (unsigned char) row->mask[p] : 0xFF;
    if ((buf[s] & m) != (unsigned char) row->pattern[p]) return 0;
  }
  /* The pattern is all there: only a checksum can still be waiting. */
  if ((row->flags & ZUMIME_SIG_TAR) && len < 512 && limit >= 512) return 1;
  return 0;
}

static uint32_t be32(const unsigned char *p) {
  return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) |
         ((uint32_t) p[2] << 8) | (uint32_t) p[3];
}

/* The standard's algorithmic signatures, read over the resource header. */
static int algorithms_pending(const unsigned char *buf, size_t len,
                              size_t limit) {
  size_t cap = limit < ZUMIME_HEADER_LEN ? limit : ZUMIME_HEADER_LEN;
  size_t h = len < cap ? len : cap;
  /* MP4: "ftyp" at 4 and the whole box. */
  static const char ftyp[4] = {'f', 't', 'y', 'p'};
  if (h < 8) {
    int ok = 1;
    for (size_t i = 4; i < h; i++)
      if (buf[i] != (unsigned char) ftyp[i - 4]) ok = 0;
    if (ok) return 1;
  } else if (memcmp(buf + 4, ftyp, 4) == 0) {
    uint32_t box = be32(buf);
    if (box >= 12 && box <= cap && h < box) return 1;
  }
  /* WebM: the EBML magic, then a DocType in the next few dozen bytes. */
  static const unsigned char ebml[4] = {0x1A, 0x45, 0xDF, 0xA3};
  size_t m = h < 4 ? h : 4;
  if (memcmp(buf, ebml, m) == 0 && h < 64 && h < cap) return 1;
  /* MP3 without ID3: a frame header at 0, and a second one after it. */
  if (h >= 1 && buf[0] == 0xFF) {
    if (h < 4) return h < 2 || (buf[1] & 0xE0) == 0xE0;
    if (zumime_match_mp3(buf, h)) return 0;
    /* A first header that parses but whose second frame is not yet here. */
    if ((buf[1] & 0xE0) == 0xE0 && ((buf[1] & 0x06) >> 1) == 1 && h < 2048 &&
        h < cap)
      return 1;
  }
  return 0;
}

/* The groups the algorithm consults for these inputs (a bit per group),
 * and whether it runs the MP4, WebM and MP3 signatures. */
static unsigned consulted(const zumime_input *in, int *algorithms) {
  const char *s = in->supplied;
  *algorithms = 0;
#define G(g) (1u << (g))
  switch (in->context) {
  case ZUMIME_CTX_IMAGE:
    return G(ZUMIME_GROUP_IMAGE);
  case ZUMIME_CTX_AUDIO_VIDEO:
    *algorithms = 1;
    return G(ZUMIME_GROUP_AUDIO_VIDEO);
  case ZUMIME_CTX_FONT:
    return G(ZUMIME_GROUP_FONT);
  default:
    break;
  }
  unsigned extra = in->context == ZUMIME_CTX_NONE ? G(ZUMIME_GROUP_EXTRA) : 0;
  int unknown = s == NULL || strcmp(s, "unknown/unknown") == 0 ||
                strcmp(s, "application/unknown") == 0 || strcmp(s, "*/*") == 0;
  if (unknown) {
    *algorithms = 1;
    return (in->no_sniff ? 0 : G(ZUMIME_GROUP_SCRIPTABLE)) |
           G(ZUMIME_GROUP_NONSCRIPTABLE) | G(ZUMIME_GROUP_IMAGE) |
           G(ZUMIME_GROUP_AUDIO_VIDEO) | G(ZUMIME_GROUP_ARCHIVE) | extra;
  }
  if (in->no_sniff) return 0;
  if (in->apache_bug) return extra;
  unsigned g = 0;
  if (strncmp(s, "image/", 6) == 0) g |= G(ZUMIME_GROUP_IMAGE);
  if (strncmp(s, "audio/", 6) == 0 || strncmp(s, "video/", 6) == 0 ||
      strcmp(s, "application/ogg") == 0) {
    g |= G(ZUMIME_GROUP_AUDIO_VIDEO);
    *algorithms = 1;
  }
  return g;
#undef G
}

/* Rows that come before index `upto` in the order the algorithm consults
 * them, among the consulted groups, and the algorithmic signatures when
 * they run before `upto`. */
static int earlier_pending(const unsigned char *buf, size_t len, size_t limit,
                           const zumime_input *in, int upto_group,
                           int upto_index) {
  int algorithms;
  unsigned groups = consulted(in, &algorithms);
  for (int i = 0; i < zumime_n_sigs; i++) {
    const zumime_sig *row = &zumime_sigs[i];
    if (!(groups & (1u << row->group))) continue;
    if (row->group > upto_group) continue;
    if (row->group == upto_group && i >= upto_index) continue;
    if (row_pending(row, buf, len, limit)) return 1;
  }
  if (algorithms && upto_group > ZUMIME_GROUP_AUDIO_VIDEO &&
      algorithms_pending(buf, len, limit))
    return 1;
  /* The text-or-binary rule of the Apache bug looks at a BOM's 3 bytes. */
  if (in->apache_bug && len < 3) return 1;
  return 0;
}

/* Where the base type was matched: the first row of that type that matches,
 * or the algorithms' slot for MP4, WebM and MP3. */
static void match_position(const unsigned char *buf, size_t len, int type,
                           int *group, int *index) {
  for (int i = 0; i < zumime_n_sigs; i++) {
    const zumime_sig *row = &zumime_sigs[i];
    if (row->type == type && row->parent < 0 && zumime_match_row(row, buf, len)) {
      *group = row->group;
      *index = i;
      return;
    }
  }
  /* An algorithmic match sits after the audio-video rows. */
  *group = ZUMIME_GROUP_FONT;
  *index = -1;
}

/* Has the reader for `base` everything it needs to settle? */
static int reader_settled(const unsigned char *buf, size_t len, int base,
                          int type) {
  if (base == ZUMIME_T_IMAGE_JPEG) return len >= 4;
  if (base == ZUMIME_T_IMAGE_PNG) {
    if (type == ZUMIME_T_IMAGE_APNG) return 1;
    size_t pos = 8;
    for (int k = 0; k < 64 && pos + 8 <= len; k++) {
      if (memcmp(buf + pos + 4, "IDAT", 4) == 0) return 1;
      uint32_t n = be32(buf + pos);
      if ((uint64_t) pos + 12 + n > len) return 0;
      pos += 12 + n;
    }
    return 0;
  }
  if (base == ZUMIME_T_VIDEO_MP4 || base == ZUMIME_T_APPLICATION_OCTET_STREAM) {
    if (len < 12) return 0;
    if (memcmp(buf + 4, "ftyp", 4) == 0) return len >= be32(buf);
    return 1;
  }
  if (base == ZUMIME_T_APPLICATION_OGG) return type != ZUMIME_T_APPLICATION_OGG;
  /* ZIP, OLE2, Matroska, gzip and text keep reading until the limit. */
  if (base == ZUMIME_T_APPLICATION_ZIP || base == ZUMIME_T_APPLICATION_X_OLE_STORAGE ||
      base == ZUMIME_T_VIDEO_X_MATROSKA || base == ZUMIME_T_APPLICATION_GZIP)
    return 0;
  return 1;
}

static int registered_pending(size_t len, int type) {
  for (int k = 0; k < ZUMIME_MAX_REGISTERED; k++) {
    const zumime_registered *r = &zumime_reg[k];
    if (r->active && r->has_rule && r->parent == type &&
        (uint64_t) r->offset + r->len > len)
      return 1;
  }
  return 0;
}

int zumime_can_decide(const unsigned char *buf, size_t len, size_t limit,
                      const zumime_input *in, const zumime_result *r) {
  if (limit > 0 && len >= limit) return 1;
  if (limit == 0) limit = (size_t) -1;

  if (r->type == ZUMIME_SUPPLIED) {
    /* A text type still waits for its charset. Otherwise the supplied type
     * stands once no consulted table could still match. */
    if (in->supplied_id >= 0
            ? zumime_type_is(in->supplied_id, ZUMIME_T_TEXT_PLAIN)
            : strncmp(in->supplied, "text/", 5) == 0)
      return 0;
    return !earlier_pending(buf, len, limit, in, ZUMIME_N_GROUPS, 0);
  }
  if (zumime_type_is(r->type, ZUMIME_T_TEXT_PLAIN)) return 0;
  if (r->confidence != ZUMIME_CONF_DEFINITE &&
      r->type != ZUMIME_T_APPLICATION_OCTET_STREAM)
    return 0;

  /* The answer before any reader ran. */
  zumime_input base_in = *in;
  base_in.base_only = 1;
  base_in.truncated = 1;
  zumime_result b;
  zumime_sniff(buf, len, &base_in, &b);
  int base = b.type;

  int group, index;
  if (base == ZUMIME_T_APPLICATION_OCTET_STREAM) {
    group = ZUMIME_N_GROUPS;
    index = 0;
  } else {
    match_position(buf, len, base, &group, &index);
  }
  if (earlier_pending(buf, len, limit, in, group, index)) return 0;
  if (in->context == ZUMIME_CTX_NONE && !reader_settled(buf, len, base, r->type))
    return 0;
  if (registered_pending(len, base) || registered_pending(len, r->type)) return 0;
  return 1;
}
