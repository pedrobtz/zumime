/* libFuzzer target for the sniffer core (design section 9), built without
 * R (-DZUMIME_STANDALONE) by .github/workflows/fuzz.yaml and locally by
 * tools/fuzz/run-local. For each input it checks:
 *
 *   - no crash and no read past the buffer, in every context and with
 *     supplied types (the sanitizers report those);
 *   - every type id is in the registry, and every confidence, charset,
 *     newline style and encryption flag in range;
 *   - the incremental property: the type the stream decides on, at the
 *     first prefix the can-decide rule accepts, is the type of the whole.
 *     Prefixes are taken byte by byte up to 64 bytes and then by a stride
 *     of about 1/64 of the prefix, so a long input costs O(n log n) sniffs
 *     rather than O(n^2);
 *   - the sniffer with a separate tail (the path loop's ZIP tail) and in
 *     mime_check()'s base-only first pass;
 *   - the path loop's window arithmetic on the input as an in-memory file:
 *     the tail and central-directory windows stay inside the file;
 *   - the bounded and streaming inflaters and the ZIP reader with a tail
 *     survive arbitrary bytes. */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "zumime_sniff.h"

static void check_result(const zumime_result *r) {
  if (r->type != ZUMIME_SUPPLIED && (r->type < 0 || r->type >= ZUMIME_N_TYPES))
    abort();
  if (r->confidence < ZUMIME_CONF_NONE || r->confidence > ZUMIME_CONF_DEFINITE)
    abort();
  if (r->charset < ZUMIME_CS_NONE || r->charset > ZUMIME_CS_DECLARED) abort();
  if (r->newline < ZUMIME_NL_NONE || r->newline > ZUMIME_NL_MIXED) abort();
  if (r->encrypted < -1 || r->encrypted > 1) abort();
  if (r->charset == ZUMIME_CS_DECLARED &&
      strlen(r->cs_label) > ZUMIME_LABEL_MAX)
    abort();
  if (strlen(r->interpreter) > ZUMIME_INTERP_MAX) abort();
}

static void sniff(const uint8_t *data, size_t size, int context,
                  const char *supplied, int no_sniff, int apache) {
  zumime_input in;
  memset(&in, 0, sizeof(in));
  in.context = context;
  in.supplied = supplied;
  in.supplied_id = supplied ? zumime_type_lookup(supplied) : -1;
  in.no_sniff = no_sniff;
  in.apache_bug = apache;
  zumime_result r;
  zumime_sniff(data, size, &in, &r);
  check_result(&r);
}

typedef struct {
  const uint8_t *p;
  size_t n, pos;
} mem;

static size_t mem_read(void *ctx, unsigned char *buf, size_t n) {
  mem *m = (mem *) ctx;
  size_t k = m->n - m->pos < n ? m->n - m->pos : n;
  memcpy(buf, m->p + m->pos, k);
  m->pos += k;
  return k;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  for (int c = ZUMIME_CTX_NONE; c <= ZUMIME_CTX_FONT; c++)
    sniff(data, size, c, NULL, 0, 0);
  sniff(data, size, ZUMIME_CTX_NONE, "image/png", 0, 0);
  sniff(data, size, ZUMIME_CTX_NONE, "video/mp4", 0, 0);
  sniff(data, size, ZUMIME_CTX_NONE, "text/plain", 0, 1);
  sniff(data, size, ZUMIME_CTX_NONE, "text/html", 1, 0);

  /* The incremental property, with the input's length as the limit. */
  zumime_input in;
  memset(&in, 0, sizeof(in));
  in.context = ZUMIME_CTX_NONE;
  in.truncated = 1;
  zumime_result whole, part;
  zumime_sniff(data, size, &in, &whole);
  check_result(&whole);
  for (size_t k = 1; k < size; k += k < 64 ? 1 : k / 64) {
    zumime_sniff(data, k, &in, &part);
    if (zumime_can_decide(data, k, size, &in, &part)) {
      if (part.type != whole.type) abort();
      break;
    }
  }

  /* The first half as the head and the second as a tail read separately,
   * as the path loop does for a ZIP longer than its head. */
  zumime_input tin;
  memset(&tin, 0, sizeof(tin));
  tin.context = ZUMIME_CTX_NONE;
  tin.truncated = 1;
  tin.tail = data + size / 2;
  tin.tail_len = size - size / 2;
  tin.tail_off = size / 2;
  zumime_sniff(data, size / 2, &tin, &part);
  check_result(&part);

  /* The path loop on the input as a file, with heads of a few lengths:
   * the tail and directory windows it chooses must lie inside the file. */
  size_t heads[3] = {size / 3, size / 2, 4096};
  for (int h = 0; h < 3; h++) {
    size_t head_len = heads[h] < size ? heads[h] : size;
    if (head_len == size || head_len < 4 || memcmp(data, "PK\x03\x04", 4) != 0)
      continue;
    uint64_t at;
    size_t n;
    zumime_zip_tail_window(size, &at, &n);
    if (at + n != size) abort();
    zumime_input pin;
    memset(&pin, 0, sizeof(pin));
    pin.context = ZUMIME_CTX_NONE;
    pin.truncated = 1;
    pin.tail = data + at;
    pin.tail_len = n;
    pin.tail_off = at;
    uint64_t cd;
    size_t m;
    if (zumime_zip_cd_window(data + at, n, at, size, head_len, &cd, &m)) {
      if (cd < head_len || cd >= at || cd + m != size) abort();
      pin.tail = data + cd;
      pin.tail_len = m;
      pin.tail_off = cd;
    }
    zumime_sniff(data, head_len, &pin, &part);
    check_result(&part);
  }

  /* mime_check()'s first pass. */
  zumime_input bin;
  memset(&bin, 0, sizeof(bin));
  bin.context = ZUMIME_CTX_NONE;
  bin.base_only = 1;
  zumime_sniff(data, size, &bin, &part);
  check_result(&part);

  /* The ZIP reader with the input as its own tail. */
  int enc;
  (void) zumime_read_zip(data, size / 2, 0, data + size / 2, size - size / 2,
                         size / 2, &enc);

  /* The inflaters. */
  unsigned char out[256];
  (void) zumime_inflate(data, size, out, sizeof(out));
  mem m = {data, size, 0};
  (void) zumime_gzip_complete(mem_read, &m);
  return 0;
}
