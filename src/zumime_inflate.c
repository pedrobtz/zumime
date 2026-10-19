/* A DEFLATE decoder (RFC 1951), written for zumime. It has two uses: the
 * first bytes of a stream, enough to see an RDS or RData header or an
 * OOXML [Content_Types].xml (design section 6.2), stopping as soon as the
 * caller's buffer is full; and the gzip completeness check of
 * `complete = TRUE` (design section 6.7), which inflates a whole stream
 * through a 32 KiB window, discarding the output, to find its trailer.
 * Stored, fixed and dynamic Huffman blocks; a canonical-code decoder that
 * reads one bit at a time. */

#include <stdlib.h>
#include <string.h>

#include "zumime_sniff.h"

#define MAXBITS 15

#define WSIZE 32768u

typedef struct {
  const unsigned char *in;
  size_t inlen, inpos;
  zumime_reader refill; /* NULL: the input is all in `in` */
  void *ctx;
  unsigned char *inbuf; /* refill target */
  size_t inbuf_cap;
  uint32_t bitbuf;
  int bitcnt;
  unsigned char window[WSIZE];
  uint64_t total;       /* bytes produced */
  unsigned char *out;   /* the first outlen bytes are captured here */
  size_t outlen;
  int stop_when_full;
  int err;  /* input ran out or the stream is invalid */
  int full; /* the capture buffer is full and the caller wants no more */
} state;

static int more_input(state *s) {
  if (s->refill == NULL) return 0;
  size_t n = s->refill(s->ctx, s->inbuf, s->inbuf_cap);
  if (n == 0) return 0;
  s->in = s->inbuf;
  s->inlen = n;
  s->inpos = 0;
  return 1;
}

static int next_byte(state *s, unsigned char *c) {
  if (s->inpos >= s->inlen && !more_input(s)) return 0;
  *c = s->in[s->inpos++];
  return 1;
}

typedef struct {
  short count[MAXBITS + 1];
  short symbol[288];
} huffman;

static int bits(state *s, int need) {
  uint32_t val = s->bitbuf;
  while (s->bitcnt < need) {
    unsigned char c;
    if (!next_byte(s, &c)) {
      s->err = 1;
      return 0;
    }
    val |= (uint32_t) c << s->bitcnt;
    s->bitcnt += 8;
  }
  s->bitbuf = val >> need;
  s->bitcnt -= need;
  return (int) (val & ((1u << need) - 1u));
}

static int construct(huffman *h, const short *length, int n) {
  short offs[MAXBITS + 1];
  for (int len = 0; len <= MAXBITS; len++) h->count[len] = 0;
  for (int sym = 0; sym < n; sym++) h->count[length[sym]]++;
  if (h->count[0] == n) return 0;
  int left = 1;
  for (int len = 1; len <= MAXBITS; len++) {
    left <<= 1;
    left -= h->count[len];
    if (left < 0) return -1; /* over-subscribed */
  }
  offs[1] = 0;
  for (int len = 1; len < MAXBITS; len++) offs[len + 1] = offs[len] + h->count[len];
  for (int sym = 0; sym < n; sym++)
    if (length[sym] != 0) h->symbol[offs[length[sym]]++] = (short) sym;
  return left;
}

static int decode(state *s, const huffman *h) {
  int code = 0, first = 0, index = 0;
  for (int len = 1; len <= MAXBITS; len++) {
    code |= bits(s, 1);
    if (s->err) return -1;
    int count = h->count[len];
    if (code - count < first) return h->symbol[index + (code - first)];
    index += count;
    first += count;
    first <<= 1;
    code <<= 1;
  }
  return -1;
}

static void put(state *s, unsigned char c) {
  s->window[s->total & (WSIZE - 1u)] = c;
  if (s->total < s->outlen) s->out[s->total] = c;
  s->total++;
  if (s->stop_when_full && s->total >= s->outlen) s->full = 1;
}

static const short lbase[29] = {3,  4,  5,  6,  7,  8,  9,  10, 11,  13,
                                15, 17, 19, 23, 27, 31, 35, 43, 51,  59,
                                67, 83, 99, 115, 131, 163, 195, 227, 258};
static const short lext[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
                               2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
static const short dbase[30] = {1,    2,    3,    4,    5,    7,     9,     13,
                                17,   25,   33,   49,   65,   97,    129,   193,
                                257,  385,  513,  769,  1025, 1537,  2049,  3073,
                                4097, 6145, 8193, 12289, 16385, 24577};
static const short dext[30] = {0, 0, 0, 0, 1, 1, 2, 2,  3,  3,  4,  4,  5,  5,  6,
                               6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};

static void codes(state *s, const huffman *lencode, const huffman *distcode) {
  for (;;) {
    int sym = decode(s, lencode);
    if (sym < 0) {
      s->err = 1;
      return;
    }
    if (sym < 256) {
      put(s, (unsigned char) sym);
      if (s->full) return;
    } else if (sym == 256) {
      return;
    } else {
      sym -= 257;
      if (sym >= 29) {
        s->err = 1;
        return;
      }
      int len = lbase[sym] + bits(s, lext[sym]);
      int dsym = decode(s, distcode);
      if (s->err || dsym < 0 || dsym >= 30) {
        s->err = 1;
        return;
      }
      uint64_t dist = (uint64_t) (dbase[dsym] + bits(s, dext[dsym]));
      if (s->err || dist > s->total || dist > WSIZE) {
        s->err = 1;
        return;
      }
      while (len-- > 0) {
        put(s, s->window[(s->total - dist) & (WSIZE - 1u)]);
        if (s->full) return;
      }
    }
  }
}

static void stored(state *s) {
  s->bitbuf = 0;
  s->bitcnt = 0;
  unsigned char h[4];
  for (int i = 0; i < 4; i++) {
    if (!next_byte(s, &h[i])) {
      s->err = 1;
      return;
    }
  }
  unsigned len = h[0] | (h[1] << 8);
  unsigned nlen = h[2] | (h[3] << 8);
  if (len != (~nlen & 0xFFFFu)) {
    s->err = 1;
    return;
  }
  while (len-- > 0) {
    unsigned char c;
    if (!next_byte(s, &c)) {
      s->err = 1;
      return;
    }
    put(s, c);
    if (s->full) return;
  }
}

static void fixed(state *s) {
  static huffman lencode, distcode;
  static int built = 0;
  if (!built) {
    short lengths[288];
    int sym = 0;
    for (; sym < 144; sym++) lengths[sym] = 8;
    for (; sym < 256; sym++) lengths[sym] = 9;
    for (; sym < 280; sym++) lengths[sym] = 7;
    for (; sym < 288; sym++) lengths[sym] = 8;
    construct(&lencode, lengths, 288);
    for (sym = 0; sym < 30; sym++) lengths[sym] = 5;
    construct(&distcode, lengths, 30);
    built = 1;
  }
  codes(s, &lencode, &distcode);
}

static void dynamic(state *s) {
  static const short order[19] = {16, 17, 18, 0, 8,  7, 9,  6, 10, 5,
                                  11, 4,  12, 3, 13, 2, 14, 1, 15};
  short lengths[320];
  huffman lencode, distcode;
  int nlen = bits(s, 5) + 257;
  int ndist = bits(s, 5) + 1;
  int ncode = bits(s, 4) + 4;
  if (s->err || nlen > 286 || ndist > 30) {
    s->err = 1;
    return;
  }
  int index;
  for (index = 0; index < ncode; index++) lengths[order[index]] = (short) bits(s, 3);
  for (; index < 19; index++) lengths[order[index]] = 0;
  if (s->err || construct(&lencode, lengths, 19) != 0) {
    s->err = 1;
    return;
  }
  index = 0;
  while (index < nlen + ndist) {
    int sym = decode(s, &lencode);
    if (sym < 0) {
      s->err = 1;
      return;
    }
    if (sym < 16) {
      lengths[index++] = (short) sym;
      continue;
    }
    short len = 0;
    if (sym == 16) {
      if (index == 0) {
        s->err = 1;
        return;
      }
      len = lengths[index - 1];
      sym = 3 + bits(s, 2);
    } else if (sym == 17) {
      sym = 3 + bits(s, 3);
    } else {
      sym = 11 + bits(s, 7);
    }
    if (s->err || index + sym > nlen + ndist) {
      s->err = 1;
      return;
    }
    while (sym-- > 0) lengths[index++] = len;
  }
  if (lengths[256] == 0) {
    s->err = 1;
    return;
  }
  int err = construct(&lencode, lengths, nlen);
  if (err < 0 || (err > 0 && nlen - lencode.count[0] != 1)) {
    s->err = 1;
    return;
  }
  err = construct(&distcode, lengths + nlen, ndist);
  if (err < 0 || (err > 0 && ndist - distcode.count[0] != 1)) {
    s->err = 1;
    return;
  }
  codes(s, &lencode, &distcode);
}

/* Run blocks until the last one ends, the capture is full (when asked),
 * or an error. Returns 1 when the final block ended cleanly. */
static int run(state *s) {
  int last;
  do {
    last = bits(s, 1);
    int type = bits(s, 2);
    if (s->err) return 0;
    if (type == 0)
      stored(s);
    else if (type == 1)
      fixed(s);
    else if (type == 2)
      dynamic(s);
    else
      s->err = 1;
  } while (!last && !s->err && !s->full);
  return last && !s->err && !s->full;
}

size_t zumime_inflate(const unsigned char *src, size_t slen, unsigned char *dst,
                      size_t dlen) {
  if (dlen == 0) return 0;
  state *s = (state *) calloc(1, sizeof(state));
  if (s == NULL) return 0;
  s->in = src;
  s->inlen = slen;
  s->out = dst;
  s->outlen = dlen;
  s->stop_when_full = 1;
  run(s);
  size_t n = s->total < dlen ? (size_t) s->total : dlen;
  free(s);
  return n;
}

/* --- gzip completeness (RFC 1952) ----------------------------------------- */

static int skip_zstr(state *s) {
  unsigned char c;
  do {
    if (!next_byte(s, &c)) return 0;
  } while (c != 0);
  return 1;
}

/* One member: header, deflate stream, trailer. 1 when complete. */
static int gzip_member(state *s, unsigned char id1) {
  unsigned char h[10];
  h[0] = id1;
  for (int i = 1; i < 10; i++)
    if (!next_byte(s, &h[i])) return 0;
  if (h[0] != 0x1F || h[1] != 0x8B || h[2] != 8) return 0;
  unsigned flg = h[3];
  if (flg & 4u) {
    unsigned char x[2];
    if (!next_byte(s, &x[0]) || !next_byte(s, &x[1])) return 0;
    unsigned xlen = x[0] | (x[1] << 8);
    for (unsigned i = 0; i < xlen; i++) {
      unsigned char c;
      if (!next_byte(s, &c)) return 0;
    }
  }
  if ((flg & 8u) && !skip_zstr(s)) return 0;
  if ((flg & 16u) && !skip_zstr(s)) return 0;
  if (flg & 2u) {
    unsigned char c;
    if (!next_byte(s, &c) || !next_byte(s, &c)) return 0;
  }
  s->bitbuf = 0;
  s->bitcnt = 0;
  s->total = 0;
  if (!run(s)) return 0;
  unsigned char t[8];
  for (int i = 0; i < 8; i++)
    if (!next_byte(s, &t[i])) return 0;
  return zumime_le32(t + 4) == (uint32_t) (s->total & 0xFFFFFFFFu);
}

int zumime_gzip_complete(zumime_reader read, void *ctx) {
  state *s = (state *) calloc(1, sizeof(state));
  unsigned char *buf = (unsigned char *) malloc(65536);
  if (s == NULL || buf == NULL) {
    free(s);
    free(buf);
    return -1;
  }
  s->refill = read;
  s->ctx = ctx;
  s->inbuf = buf;
  s->inbuf_cap = 65536;
  unsigned char c;
  int ok = next_byte(s, &c) && gzip_member(s, c);
  /* Further members must be complete too; trailing zero padding is fine. */
  while (ok && next_byte(s, &c)) {
    if (c == 0) continue;
    ok = gzip_member(s, c);
  }
  free(buf);
  free(s);
  return ok;
}
