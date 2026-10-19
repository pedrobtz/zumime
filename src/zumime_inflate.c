/* A bounded DEFLATE decoder (RFC 1951), written for zumime: it inflates the
 * first few bytes of a gzip member, enough to see an RDS or RData header
 * (design section 6.2), and stops as soon as its small output buffer is
 * full. Stored, fixed and dynamic Huffman blocks; a canonical-code decoder
 * that reads one bit at a time, which is plenty for 64 output bytes. */

#include <string.h>

#include "zumime_sniff.h"

#define MAXBITS 15

typedef struct {
  const unsigned char *in;
  size_t inlen, inpos;
  uint32_t bitbuf;
  int bitcnt;
  unsigned char *out;
  size_t outlen, outpos;
  int err;  /* input ran out or the stream is invalid */
  int full; /* the output buffer is full */
} state;

typedef struct {
  short count[MAXBITS + 1];
  short symbol[288];
} huffman;

static int bits(state *s, int need) {
  uint32_t val = s->bitbuf;
  while (s->bitcnt < need) {
    if (s->inpos >= s->inlen) {
      s->err = 1;
      return 0;
    }
    val |= (uint32_t) s->in[s->inpos++] << s->bitcnt;
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
  if (s->outpos < s->outlen) s->out[s->outpos++] = c;
  if (s->outpos == s->outlen) s->full = 1;
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
      size_t dist = (size_t) (dbase[dsym] + bits(s, dext[dsym]));
      if (s->err || dist > s->outpos) {
        s->err = 1;
        return;
      }
      while (len-- > 0) {
        put(s, s->out[s->outpos - dist]);
        if (s->full) return;
      }
    }
  }
}

static void stored(state *s) {
  s->bitbuf = 0;
  s->bitcnt = 0;
  if (s->inpos + 4 > s->inlen) {
    s->err = 1;
    return;
  }
  unsigned len = s->in[s->inpos] | (s->in[s->inpos + 1] << 8);
  unsigned nlen = s->in[s->inpos + 2] | (s->in[s->inpos + 3] << 8);
  s->inpos += 4;
  if (len != (~nlen & 0xFFFFu)) {
    s->err = 1;
    return;
  }
  while (len-- > 0) {
    if (s->inpos >= s->inlen) {
      s->err = 1;
      return;
    }
    put(s, s->in[s->inpos++]);
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

size_t zumime_inflate(const unsigned char *src, size_t slen, unsigned char *dst,
                      size_t dlen) {
  state s;
  memset(&s, 0, sizeof(s));
  s.in = src;
  s.inlen = slen;
  s.out = dst;
  s.outlen = dlen;
  if (dlen == 0) return 0;
  int last;
  do {
    last = bits(&s, 1);
    int type = bits(&s, 2);
    if (s.err) break;
    if (type == 0)
      stored(&s);
    else if (type == 1)
      fixed(&s);
    else if (type == 2)
      dynamic(&s);
    else
      s.err = 1;
  } while (!last && !s.err && !s.full);
  return s.outpos;
}
