/* ZIP (design section 6.2): entry names, read uncompressed, decide the
 * ZIP-based format; the encryption flag and the AES extra field set
 * `encrypted`.
 *
 * The central directory is found through the end-of-central-directory
 * record in the last 66 KiB (the record plus the largest comment), in the
 * tail when one was read or in the head when the head is the whole file.
 * Without it the local file headers are walked from the start, as far as
 * the bytes in hand and the entries' sizes allow. A "mimetype" entry stored
 * first (EPUB, OpenDocument) is read from its local header. */

#include <string.h>

#include "zumime_sniff.h"

#define EOCD_SEARCH (22u + 65535u)

typedef struct {
  int entries;
  int encrypted;
  int content_types, word, xl, ppt, word_vba, xl_vba, ppt_vba;
  int manifest, android, dex, model3mf;
  int mimetype_type;
  int64_t ctypes_local; /* local header offset of [Content_Types].xml */
} zip_scan;

static int name_is(const unsigned char *n, size_t len, const char *lit) {
  size_t m = strlen(lit);
  return len == m && memcmp(n, lit, m) == 0;
}

static int name_starts(const unsigned char *n, size_t len, const char *lit) {
  size_t m = strlen(lit);
  return len >= m && memcmp(n, lit, m) == 0;
}

/* The AES encryption extra field (WinZip AE-x, header id 0x9901). */
static int extra_has_aes(const unsigned char *x, size_t len) {
  size_t i = 0;
  while (i + 4 <= len) {
    uint16_t id = zumime_le16(x + i);
    uint16_t sz = zumime_le16(x + i + 2);
    if (id == 0x9901) return 1;
    i += 4u + sz;
  }
  return 0;
}

static void on_entry(zip_scan *z, const unsigned char *name, size_t nlen,
                     uint16_t flags, const unsigned char *extra, size_t xlen,
                     int64_t local) {
  z->entries++;
  if ((flags & 1u) || extra_has_aes(extra, xlen)) z->encrypted = 1;
  if (name_is(name, nlen, "[Content_Types].xml")) {
    z->content_types = 1;
    z->ctypes_local = local;
  }
  if (name_starts(name, nlen, "word/")) z->word = 1;
  if (name_starts(name, nlen, "xl/")) z->xl = 1;
  if (name_starts(name, nlen, "ppt/")) z->ppt = 1;
  if (name_is(name, nlen, "word/vbaProject.bin")) z->word_vba = 1;
  if (name_is(name, nlen, "xl/vbaProject.bin")) z->xl_vba = 1;
  if (name_is(name, nlen, "ppt/vbaProject.bin")) z->ppt_vba = 1;
  if (name_is(name, nlen, "META-INF/MANIFEST.MF")) z->manifest = 1;
  if (name_is(name, nlen, "AndroidManifest.xml")) z->android = 1;
  if (name_is(name, nlen, "classes.dex")) z->dex = 1;
  if (name_is(name, nlen, "3D/3dmodel.model")) z->model3mf = 1;
}

/* A stored "mimetype" entry as the first local header: its content names
 * the format. */
static void read_mimetype(zip_scan *z, const unsigned char *b, size_t len) {
  if (len < 30 || memcmp(b, "PK\x03\x04", 4) != 0) return;
  uint16_t method = zumime_le16(b + 8);
  uint32_t csize = zumime_le32(b + 18);
  size_t nlen = zumime_le16(b + 26), xlen = zumime_le16(b + 28);
  if (method != 0 || !name_is(b + 30, (30 + nlen <= len) ? nlen : 0, "mimetype"))
    return;
  size_t data = 30 + nlen + xlen;
  if (csize == 0 || csize > 80 || data > len || len - data < csize) return;
  char type[81];
  size_t n = csize;
  while (n > 0 && (b[data + n - 1] == '\n' || b[data + n - 1] == '\r' ||
                   b[data + n - 1] == ' '))
    n--;
  memcpy(type, b + data, n);
  type[n] = '\0';
  int id = zumime_type_lookup(type);
  if (id >= 0 && zumime_type_is(id, ZUMIME_T_APPLICATION_ZIP))
    z->mimetype_type = id;
}

static void walk_local(zip_scan *z, const unsigned char *b, size_t len) {
  size_t pos = 0;
  int guard = 0;
  while (pos + 30 <= len && memcmp(b + pos, "PK\x03\x04", 4) == 0 &&
         guard++ < 4096) {
    uint16_t flags = zumime_le16(b + pos + 6);
    uint32_t csize = zumime_le32(b + pos + 18);
    size_t nlen = zumime_le16(b + pos + 26), xlen = zumime_le16(b + pos + 28);
    size_t name = pos + 30;
    if (name + nlen > len) break;
    size_t extra = name + nlen;
    size_t xavail = (extra + xlen <= len) ? xlen : len - extra;
    on_entry(z, b + name, nlen, flags, b + extra, xavail, (int64_t) pos);
    if ((flags & 8u) && csize == 0) break; /* size only in a descriptor */
    size_t next = extra + xlen + csize;
    if (next < pos || next > len) break;
    if (flags & 8u) {
      if (next + 4 <= len && memcmp(b + next, "PK\x07\x08", 4) == 0)
        next += 16;
      else
        next += 12;
    }
    pos = next;
  }
}

/* The central directory entries, from whichever buffer holds them. */
static int walk_central(zip_scan *z, const unsigned char *b, size_t len,
                        size_t start, size_t size, unsigned count) {
  if (start > len || len - start < size) return 0;
  size_t pos = start, end = start + size;
  unsigned seen = 0;
  while (pos + 46 <= end && memcmp(b + pos, "PK\x01\x02", 4) == 0 &&
         seen < count && seen < 65535u) {
    uint16_t flags = zumime_le16(b + pos + 8);
    size_t nlen = zumime_le16(b + pos + 28), xlen = zumime_le16(b + pos + 30),
           clen = zumime_le16(b + pos + 32);
    if (pos + 46 + nlen + xlen + clen > end) break;
    on_entry(z, b + pos + 46, nlen, flags, b + pos + 46 + nlen, xlen,
             (int64_t) zumime_le32(b + pos + 42));
    pos += 46 + nlen + xlen + clen;
    seen++;
  }
  return seen > 0;
}

/* Find the end-of-central-directory record in buf, which ends at file
 * offset buf_off + len, and walk the directory if buf (or head) holds it. */
static int from_eocd(zip_scan *z, const unsigned char *buf, size_t len,
                     uint64_t buf_off, const unsigned char *head, size_t hlen) {
  if (len < 22) return 0;
  size_t lo = len > EOCD_SEARCH ? len - EOCD_SEARCH : 0;
  for (size_t i = len - 22 + 1; i-- > lo;) {
    if (memcmp(buf + i, "PK\x05\x06", 4) != 0) continue;
    unsigned count = zumime_le16(buf + i + 10);
    uint32_t cd_size = zumime_le32(buf + i + 12);
    uint32_t cd_off = zumime_le32(buf + i + 16);
    if (cd_off == 0xFFFFFFFFu) return 0; /* Zip64: fall back to the walk */
    if (cd_off >= buf_off && cd_off - buf_off + cd_size <= len)
      return walk_central(z, buf, len, (size_t) (cd_off - buf_off), cd_size,
                          count);
    if (head && cd_off + (uint64_t) cd_size <= hlen)
      return walk_central(z, head, hlen, cd_off, cd_size, count);
    return 0;
  }
  return 0;
}

/* The main part's content type in [Content_Types].xml tells a template, a
 * slideshow or a macro-enabled document from the plain one, as file-type
 * does. The part is usually deflated; its first 8 KiB are inflated from
 * its local header when that is in the head. */
static int ooxml_variant(const unsigned char *b, size_t len, int64_t local) {
  static const struct {
    const char *ct;
    int type;
  } variants[] = {
      {"wordprocessingml.template.main+xml",
       ZUMIME_T_APPLICATION_VND_OPENXMLFORMATS_OFFICEDOCUMENT_WORDPROCESSINGML_TEMPLATE},
      {"ms-word.template.macroEnabledTemplate.main+xml",
       ZUMIME_T_APPLICATION_VND_MS_WORD_TEMPLATE_MACROENABLED_12},
      {"ms-word.document.macroEnabled.main+xml",
       ZUMIME_T_APPLICATION_VND_MS_WORD_DOCUMENT_MACROENABLED_12},
      {"spreadsheetml.template.main+xml",
       ZUMIME_T_APPLICATION_VND_OPENXMLFORMATS_OFFICEDOCUMENT_SPREADSHEETML_TEMPLATE},
      {"ms-excel.template.macroEnabled.main+xml",
       ZUMIME_T_APPLICATION_VND_MS_EXCEL_TEMPLATE_MACROENABLED_12},
      {"ms-excel.sheet.macroEnabled.main+xml",
       ZUMIME_T_APPLICATION_VND_MS_EXCEL_SHEET_MACROENABLED_12},
      {"presentationml.template.main+xml",
       ZUMIME_T_APPLICATION_VND_OPENXMLFORMATS_OFFICEDOCUMENT_PRESENTATIONML_TEMPLATE},
      {"ms-powerpoint.template.macroEnabled.main+xml",
       ZUMIME_T_APPLICATION_VND_MS_POWERPOINT_TEMPLATE_MACROENABLED_12},
      {"presentationml.slideshow.main+xml",
       ZUMIME_T_APPLICATION_VND_OPENXMLFORMATS_OFFICEDOCUMENT_PRESENTATIONML_SLIDESHOW},
      {"ms-powerpoint.slideshow.macroEnabled.main+xml",
       ZUMIME_T_APPLICATION_VND_MS_POWERPOINT_SLIDESHOW_MACROENABLED_12},
      {"ms-powerpoint.presentation.macroEnabled.main+xml",
       ZUMIME_T_APPLICATION_VND_MS_POWERPOINT_PRESENTATION_MACROENABLED_12},
  };
  if (local < 0 || (uint64_t) local + 30 > len) return -1;
  const unsigned char *h = b + local;
  if (memcmp(h, "PK\x03\x04", 4) != 0) return -1;
  uint16_t method = zumime_le16(h + 8);
  size_t data = (size_t) local + 30 + zumime_le16(h + 26) + zumime_le16(h + 28);
  if (data >= len) return -1;
  unsigned char xml[8192];
  size_t n;
  if (method == 8) {
    n = zumime_inflate(b + data, len - data, xml, sizeof(xml));
  } else if (method == 0) {
    n = len - data < sizeof(xml) ? len - data : sizeof(xml);
    memcpy(xml, b + data, n);
  } else {
    return -1;
  }
  for (size_t v = 0; v < sizeof(variants) / sizeof(variants[0]); v++) {
    size_t m = strlen(variants[v].ct);
    for (size_t i = 0; i + m <= n; i++)
      if (memcmp(xml + i, variants[v].ct, m) == 0) return variants[v].type;
  }
  return -1;
}

int zumime_read_zip(const unsigned char *head, size_t hlen, int head_is_whole,
                    const unsigned char *tail, size_t tail_len,
                    uint64_t tail_off, int *encrypted) {
  zip_scan z;
  memset(&z, 0, sizeof(z));
  z.mimetype_type = -1;
  z.ctypes_local = -1;
  read_mimetype(&z, head, hlen);

  int found = 0;
  if (tail != NULL)
    found = from_eocd(&z, tail, tail_len, tail_off, head, hlen);
  else if (head_is_whole)
    found = from_eocd(&z, head, hlen, 0, NULL, 0);
  if (!found) walk_local(&z, head, hlen);

  *encrypted = z.entries > 0 ? z.encrypted : -1;

  if (z.mimetype_type >= 0) return z.mimetype_type;
  if (z.content_types && (z.word || z.xl || z.ppt)) {
    int v = ooxml_variant(head, hlen, z.ctypes_local);
    if (v >= 0) return v;
  }
  if (z.content_types && z.word)
    return z.word_vba ? ZUMIME_T_APPLICATION_VND_MS_WORD_DOCUMENT_MACROENABLED_12
                      : ZUMIME_T_APPLICATION_VND_OPENXMLFORMATS_OFFICEDOCUMENT_WORDPROCESSINGML_DOCUMENT;
  if (z.content_types && z.xl)
    return z.xl_vba ? ZUMIME_T_APPLICATION_VND_MS_EXCEL_SHEET_MACROENABLED_12
                    : ZUMIME_T_APPLICATION_VND_OPENXMLFORMATS_OFFICEDOCUMENT_SPREADSHEETML_SHEET;
  if (z.content_types && z.ppt)
    return z.ppt_vba
               ? ZUMIME_T_APPLICATION_VND_MS_POWERPOINT_PRESENTATION_MACROENABLED_12
               : ZUMIME_T_APPLICATION_VND_OPENXMLFORMATS_OFFICEDOCUMENT_PRESENTATIONML_PRESENTATION;
  if (z.content_types && z.model3mf) return ZUMIME_T_MODEL_3MF;
  if (z.android && z.dex) return ZUMIME_T_APPLICATION_VND_ANDROID_PACKAGE_ARCHIVE;
  if (z.manifest) return ZUMIME_T_APPLICATION_JAVA_ARCHIVE;
  return -1;
}

/* Where the central directory starts, from the end-of-central-directory
 * record in a buffer that ends at file offset buf_off + len. 1 when found. */
int zumime_zip_cd_offset(const unsigned char *buf, size_t len, uint64_t buf_off,
                         uint64_t *cd_off) {
  (void) buf_off;
  if (len < 22) return 0;
  size_t lo = len > EOCD_SEARCH ? len - EOCD_SEARCH : 0;
  for (size_t i = len - 22 + 1; i-- > lo;) {
    if (memcmp(buf + i, "PK\x05\x06", 4) != 0) continue;
    uint32_t off = zumime_le32(buf + i + 16);
    if (off == 0xFFFFFFFFu) return 0;
    *cd_off = off;
    return 1;
  }
  return 0;
}
