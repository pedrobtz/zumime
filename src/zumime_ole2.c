/* OLE2 compound files (design section 6.2), read as libmagic's readcdf.c
 * does and tolerant of truncation: the directory's stream names and the
 * root entry's class id decide .doc, .xls, .ppt, .msg and .msi; an
 * EncryptionInfo stream is encrypted Office.
 *
 * The directory chain is followed through the FAT while the FAT sectors it
 * needs are in hand (the first 109 are listed in the header); past that,
 * only what has been read decides. */

#include <string.h>

#include "zumime_sniff.h"

#define ENDOFCHAIN 0xFFFFFFFEu
#define MAX_DIR_SECTORS 64

typedef struct {
  int word, workbook, powerpoint, outlook, encryption_info;
  unsigned char clsid[16];
  int have_clsid;
} ole_scan;

static int name_is(const char *a, const char *lit) { return strcmp(a, lit) == 0; }

static void on_entry(ole_scan *s, const unsigned char *e, int index) {
  /* The name: UTF-16LE, its byte length (with the terminator) at 64. */
  size_t nbytes = zumime_le16(e + 64);
  if (nbytes > 64) nbytes = 64;
  char name[33];
  size_t n = 0;
  for (size_t i = 0; i + 1 < nbytes && n < 32; i += 2) {
    uint16_t c = zumime_le16(e + i);
    if (c == 0) break;
    name[n++] = (c < 0x80) ? (char) c : '?';
  }
  name[n] = '\0';
  int type = e[66];
  if (index == 0 && type == 5) {
    memcpy(s->clsid, e + 80, 16);
    s->have_clsid = 1;
  }
  if (type != 2 && type != 1) return;
  if (name_is(name, "WordDocument")) s->word = 1;
  if (name_is(name, "Workbook") || name_is(name, "Book")) s->workbook = 1;
  if (name_is(name, "PowerPoint Document")) s->powerpoint = 1;
  if (name_is(name, "__properties_version1.0") ||
      strncmp(name, "__substg1.0_", 12) == 0)
    s->outlook = 1;
  if (name_is(name, "EncryptionInfo")) s->encryption_info = 1;
}

/* Bytes at an offset of the file, through the caller's accessor: a view of
 * a buffer, or a read into `scratch` from a file. NULL when not available. */
typedef struct {
  zumime_ole2_get get;
  void *ctx;
  const unsigned char *header;
} ole_src;

/* The FAT entry for sector `sec`, or ENDOFCHAIN when it is not available. */
static uint32_t fat_next(const ole_src *src, size_t ssz, uint32_t sec) {
  size_t per = ssz / 4;
  size_t idx = sec / per;
  if (idx >= 109) return ENDOFCHAIN;
  uint32_t fat_sec = zumime_le32(src->header + 76 + 4 * idx);
  if (fat_sec >= 0xFFFFFFFAu) return ENDOFCHAIN;
  uint64_t off = ((uint64_t) fat_sec + 1) * ssz + (sec % per) * 4;
  unsigned char scratch[4];
  const unsigned char *p = src->get(src->ctx, off, 4, scratch);
  return p ? zumime_le32(p) : ENDOFCHAIN;
}

/* Class ids of the Windows Installer database, patch and transform. */
static int is_msi_clsid(const unsigned char *c) {
  static const unsigned char tail[13] = {0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x46};
  return c[1] == 0x10 && c[2] == 0x0C && c[3] == 0x00 &&
         (c[0] == 0x84 || c[0] == 0x86 || c[0] == 0x82) &&
         memcmp(c + 3, tail, 13) == 0;
}

int zumime_read_ole2_at(zumime_ole2_get get, void *ctx, int *encrypted) {
  *encrypted = -1;
  unsigned char hbuf[512];
  const unsigned char *h = get(ctx, 0, 512, hbuf);
  if (h == NULL) return -1;
  uint16_t shift = zumime_le16(h + 30);
  if (shift != 9 && shift != 12) return -1;
  size_t ssz = (size_t) 1 << shift;
  /* h stays valid: the header has its own scratch, hbuf. */
  ole_src src = {get, ctx, h};

  ole_scan s;
  memset(&s, 0, sizeof(s));
  uint32_t sec = zumime_le32(h + 48);
  int index = 0;
  unsigned char dbuf[4096];
  for (int k = 0; k < MAX_DIR_SECTORS && sec < 0xFFFFFFFAu; k++) {
    uint64_t off = ((uint64_t) sec + 1) * ssz;
    const unsigned char *d = get(ctx, off, ssz, dbuf);
    if (d == NULL) {
      /* Tolerant of truncation: entries of a partial sector still count. */
      for (size_t e = 0; e < ssz / 128; e++, index++) {
        const unsigned char *one = get(ctx, off + e * 128, 128, dbuf);
        if (one == NULL) goto done;
        on_entry(&s, one, index);
      }
      goto done;
    }
    for (size_t e = 0; e < ssz / 128; e++, index++) on_entry(&s, d + e * 128, index);
    uint32_t next = fat_next(&src, ssz, sec);
    if (next == sec) break;
    sec = next;
  }
done:
  if (s.encryption_info) *encrypted = 1;
  if (s.have_clsid && is_msi_clsid(s.clsid)) return ZUMIME_T_APPLICATION_X_MS_INSTALLER;
  if (s.outlook) return ZUMIME_T_APPLICATION_VND_MS_OUTLOOK;
  if (s.word) return ZUMIME_T_APPLICATION_MSWORD;
  if (s.workbook) return ZUMIME_T_APPLICATION_VND_MS_EXCEL;
  if (s.powerpoint) return ZUMIME_T_APPLICATION_VND_MS_POWERPOINT;
  return -1;
}

typedef struct {
  const unsigned char *b;
  size_t len;
} ole_buf;

static const unsigned char *buf_get(void *ctx, uint64_t off, size_t n,
                                    unsigned char *scratch) {
  (void) scratch;
  const ole_buf *ob = (const ole_buf *) ctx;
  if (off > ob->len || ob->len - off < n) return NULL;
  return ob->b + off;
}

int zumime_read_ole2(const unsigned char *b, size_t len, int *encrypted) {
  ole_buf ob = {b, len};
  return zumime_read_ole2_at(buf_get, &ob, encrypted);
}
