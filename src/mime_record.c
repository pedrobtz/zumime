/* The WHATWG MIME type record (design section 6.8): "parse a MIME type" and
 * "serialize a MIME type" from the MIME Sniffing Standard, over code points.
 *
 * Strings arrive as UTF-8 and are decoded to code points first, because the
 * standard's code point classes reach U+00FF (HTTP quoted-string token code
 * points) and a code point above that must fail them, not pass as two bytes. */

#define R_NO_REMAP
#include <R.h>
#include <Rinternals.h>
#include <stdint.h>
#include <string.h>

#include "zumime_r.h"

typedef struct {
  const uint32_t *cp;
  R_xlen_t start;
  R_xlen_t end; /* exclusive */
} span;

static int is_http_ws(uint32_t c) {
  return c == 0x09 || c == 0x0A || c == 0x0D || c == 0x20;
}

static int is_token(uint32_t c) {
  if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
      (c >= 'A' && c <= 'Z'))
    return 1;
  return c > 0 && c < 0x80 && strchr("!#$%&'*+-.^_`|~", (int) c) != NULL;
}

static int is_quoted_token(uint32_t c) {
  return c == 0x09 || (c >= 0x20 && c <= 0x7E) || (c >= 0x80 && c <= 0xFF);
}

static int all_token(const uint32_t *cp, R_xlen_t n) {
  for (R_xlen_t i = 0; i < n; i++)
    if (!is_token(cp[i])) return 0;
  return 1;
}

static int all_quoted_token(const uint32_t *cp, R_xlen_t n) {
  for (R_xlen_t i = 0; i < n; i++)
    if (!is_quoted_token(cp[i])) return 0;
  return 1;
}

static uint32_t ascii_lower(uint32_t c) {
  return (c >= 'A' && c <= 'Z') ? c + 32 : c;
}

/* UTF-8 to code points; an invalid sequence decodes to U+FFFD, which no
 * code point class here accepts. Returns the number of code points. */
static R_xlen_t utf8_decode(const char *s, R_xlen_t len, uint32_t *out) {
  const unsigned char *p = (const unsigned char *) s;
  R_xlen_t i = 0, n = 0;
  while (i < len) {
    unsigned char b = p[i];
    uint32_t c;
    int extra;
    if (b < 0x80) {
      c = b;
      extra = 0;
    } else if ((b & 0xE0) == 0xC0) {
      c = b & 0x1F;
      extra = 1;
    } else if ((b & 0xF0) == 0xE0) {
      c = b & 0x0F;
      extra = 2;
    } else if ((b & 0xF8) == 0xF0) {
      c = b & 0x07;
      extra = 3;
    } else {
      out[n++] = 0xFFFD;
      i++;
      continue;
    }
    int ok = 1;
    for (int k = 1; k <= extra; k++) {
      if (i + k >= len || (p[i + k] & 0xC0) != 0x80) {
        ok = 0;
        break;
      }
      c = (c << 6) | (p[i + k] & 0x3F);
    }
    if (!ok) {
      out[n++] = 0xFFFD;
      i++;
      continue;
    }
    out[n++] = c;
    i += extra + 1;
  }
  return n;
}

static size_t utf8_encode_one(uint32_t c, char *out) {
  if (c < 0x80) {
    out[0] = (char) c;
    return 1;
  } else if (c < 0x800) {
    out[0] = (char) (0xC0 | (c >> 6));
    out[1] = (char) (0x80 | (c & 0x3F));
    return 2;
  } else if (c < 0x10000) {
    out[0] = (char) (0xE0 | (c >> 12));
    out[1] = (char) (0x80 | ((c >> 6) & 0x3F));
    out[2] = (char) (0x80 | (c & 0x3F));
    return 3;
  }
  out[0] = (char) (0xF0 | (c >> 18));
  out[1] = (char) (0x80 | ((c >> 12) & 0x3F));
  out[2] = (char) (0x80 | ((c >> 6) & 0x3F));
  out[3] = (char) (0x80 | (c & 0x3F));
  return 4;
}

static SEXP mk_utf8(const uint32_t *cp, R_xlen_t n) {
  char *buf = R_alloc((size_t) n * 4 + 1, 1);
  size_t len = 0;
  for (R_xlen_t i = 0; i < n; i++) len += utf8_encode_one(cp[i], buf + len);
  return Rf_mkCharLenCE(buf, (int) len, CE_UTF8);
}

/* Parse one string; returns the record or R_NilValue on failure. */
static SEXP parse_one(const char *s) {
  R_xlen_t len = (R_xlen_t) strlen(s);
  uint32_t *cp = (uint32_t *) R_alloc((size_t) len + 1, sizeof(uint32_t));
  R_xlen_t n = utf8_decode(s, len, cp);

  /* 1. Strip leading and trailing HTTP whitespace. */
  R_xlen_t a = 0, b = n;
  while (a < b && is_http_ws(cp[a])) a++;
  while (b > a && is_http_ws(cp[b - 1])) b--;

  /* 2-3. type: up to '/'. */
  R_xlen_t pos = a;
  R_xlen_t ts = pos;
  while (pos < b && cp[pos] != '/') pos++;
  R_xlen_t te = pos;
  if (te == ts || !all_token(cp + ts, te - ts)) return R_NilValue;
  if (pos >= b) return R_NilValue;
  pos++;

  /* 4. subtype: up to ';', trailing whitespace removed. */
  R_xlen_t ss = pos;
  while (pos < b && cp[pos] != ';') pos++;
  R_xlen_t se = pos;
  while (se > ss && is_http_ws(cp[se - 1])) se--;
  if (se == ss || !all_token(cp + ss, se - ss)) return R_NilValue;

  for (R_xlen_t i = ts; i < te; i++) cp[i] = ascii_lower(cp[i]);
  for (R_xlen_t i = ss; i < se; i++) cp[i] = ascii_lower(cp[i]);

  /* 5. Parameters. Names and values are collected as spans into two
   * scratch arrays; a quoted value is unescaped into its own buffer. */
  R_xlen_t cap = (b - pos) / 2 + 1;
  span *names = (span *) R_alloc((size_t) cap, sizeof(span));
  span *values = (span *) R_alloc((size_t) cap, sizeof(span));
  uint32_t *unq = (uint32_t *) R_alloc((size_t) (b - pos) + 1, sizeof(uint32_t));
  R_xlen_t unq_n = 0;
  R_xlen_t np = 0;

  while (pos < b) {
    pos++; /* past ';' */
    while (pos < b && is_http_ws(cp[pos])) pos++;
    R_xlen_t ns = pos;
    while (pos < b && cp[pos] != ';' && cp[pos] != '=') pos++;
    R_xlen_t ne = pos;
    for (R_xlen_t i = ns; i < ne; i++) cp[i] = ascii_lower(cp[i]);
    if (pos < b) {
      if (cp[pos] == ';') continue;
      pos++; /* past '=' */
    }
    if (pos >= b) break;

    span value;
    if (cp[pos] == '"') {
      /* Collect an HTTP quoted string, extracting the value. */
      R_xlen_t vs = unq_n;
      pos++;
      for (;;) {
        while (pos < b && cp[pos] != '"' && cp[pos] != '\\')
          unq[unq_n++] = cp[pos++];
        if (pos >= b) break;
        uint32_t q = cp[pos++];
        if (q == '\\') {
          if (pos >= b) {
            unq[unq_n++] = '\\';
            break;
          }
          unq[unq_n++] = cp[pos++];
        } else {
          break;
        }
      }
      while (pos < b && cp[pos] != ';') pos++;
      value.cp = unq;
      value.start = vs;
      value.end = unq_n;
    } else {
      R_xlen_t vs = pos;
      while (pos < b && cp[pos] != ';') pos++;
      R_xlen_t ve = pos;
      while (ve > vs && is_http_ws(cp[ve - 1])) ve--;
      if (ve == vs) continue;
      value.cp = cp;
      value.start = vs;
      value.end = ve;
    }

    if (ne == ns || !all_token(cp + ns, ne - ns)) continue;
    if (!all_quoted_token(value.cp + value.start, value.end - value.start))
      continue;
    int dup = 0;
    for (R_xlen_t k = 0; k < np && !dup; k++) {
      R_xlen_t kl = names[k].end - names[k].start;
      if (kl == ne - ns &&
          memcmp(cp + names[k].start, cp + ns, (size_t) kl * sizeof(uint32_t)) == 0)
        dup = 1;
    }
    if (dup) continue;
    names[np].cp = cp;
    names[np].start = ns;
    names[np].end = ne;
    values[np] = value;
    np++;
  }

  SEXP rec = PROTECT(Rf_allocVector(VECSXP, 3));
  SEXP rec_names = PROTECT(Rf_allocVector(STRSXP, 3));
  SET_STRING_ELT(rec_names, 0, Rf_mkChar("type"));
  SET_STRING_ELT(rec_names, 1, Rf_mkChar("subtype"));
  SET_STRING_ELT(rec_names, 2, Rf_mkChar("parameters"));
  Rf_setAttrib(rec, R_NamesSymbol, rec_names);
  SET_VECTOR_ELT(rec, 0, zumime_scalar_string(mk_utf8(cp + ts, te - ts)));
  SET_VECTOR_ELT(rec, 1, zumime_scalar_string(mk_utf8(cp + ss, se - ss)));

  SEXP params = PROTECT(Rf_allocVector(VECSXP, np));
  SEXP pnames = PROTECT(Rf_allocVector(STRSXP, np));
  for (R_xlen_t k = 0; k < np; k++) {
    SET_STRING_ELT(pnames, k,
                   mk_utf8(names[k].cp + names[k].start, names[k].end - names[k].start));
    SET_VECTOR_ELT(params, k, zumime_scalar_string(mk_utf8(
                                  values[k].cp + values[k].start,
                                  values[k].end - values[k].start)));
  }
  Rf_setAttrib(params, R_NamesSymbol, pnames);
  SET_VECTOR_ELT(rec, 2, params);
  UNPROTECT(4);
  return rec;
}

SEXP zumime_mime_parse(SEXP x) {
  R_xlen_t n = XLENGTH(x);
  SEXP out = PROTECT(Rf_allocVector(VECSXP, n));
  for (R_xlen_t i = 0; i < n; i++) {
    SEXP s = STRING_ELT(x, i);
    if (s == NA_STRING) continue;
    const void *vmax = vmaxget();
    SET_VECTOR_ELT(out, i, parse_one(Rf_translateCharUTF8(s)));
    vmaxset(vmax);
  }
  UNPROTECT(1);
  return out;
}

/* Serialize one record given as validated character pieces. */
typedef struct {
  char *buf;
  size_t len;
  size_t cap;
} sbuf;

static void sb_put(sbuf *sb, const char *s, size_t n) {
  if (sb->len + n + 1 > sb->cap) {
    size_t cap = sb->cap ? sb->cap : 64;
    while (sb->len + n + 1 > cap) cap *= 2;
    char *nb = R_alloc(cap, 1);
    if (sb->len) memcpy(nb, sb->buf, sb->len);
    sb->buf = nb;
    sb->cap = cap;
  }
  memcpy(sb->buf + sb->len, s, n);
  sb->len += n;
}

static void sb_value(sbuf *sb, const char *v) {
  R_xlen_t len = (R_xlen_t) strlen(v);
  uint32_t *cp = (uint32_t *) R_alloc((size_t) len + 1, sizeof(uint32_t));
  R_xlen_t n = utf8_decode(v, len, cp);
  if (n > 0 && all_token(cp, n)) {
    sb_put(sb, v, (size_t) len);
    return;
  }
  sb_put(sb, "\"", 1);
  for (R_xlen_t i = 0; i < n; i++) {
    char enc[4];
    if (cp[i] == '"' || cp[i] == '\\') sb_put(sb, "\\", 1);
    sb_put(sb, enc, utf8_encode_one(cp[i], enc));
  }
  sb_put(sb, "\"", 1);
}

/* records: a list of records (type, subtype, parameters) or NULLs, already
 * checked in R. */
SEXP zumime_mime_format(SEXP records) {
  R_xlen_t n = XLENGTH(records);
  SEXP out = PROTECT(Rf_allocVector(STRSXP, n));
  for (R_xlen_t i = 0; i < n; i++) {
    SEXP rec = VECTOR_ELT(records, i);
    if (Rf_isNull(rec)) {
      SET_STRING_ELT(out, i, NA_STRING);
      continue;
    }
    const void *vmax = vmaxget();
    sbuf sb = {NULL, 0, 0};
    const char *type = Rf_translateCharUTF8(STRING_ELT(VECTOR_ELT(rec, 0), 0));
    const char *sub = Rf_translateCharUTF8(STRING_ELT(VECTOR_ELT(rec, 1), 0));
    sb_put(&sb, type, strlen(type));
    sb_put(&sb, "/", 1);
    sb_put(&sb, sub, strlen(sub));
    SEXP params = VECTOR_ELT(rec, 2);
    SEXP pnames = Rf_getAttrib(params, R_NamesSymbol);
    for (R_xlen_t k = 0; k < XLENGTH(params); k++) {
      const char *name = Rf_translateCharUTF8(STRING_ELT(pnames, k));
      const char *value =
          Rf_translateCharUTF8(STRING_ELT(VECTOR_ELT(params, k), 0));
      sb_put(&sb, ";", 1);
      sb_put(&sb, name, strlen(name));
      sb_put(&sb, "=", 1);
      sb_value(&sb, value);
    }
    SET_STRING_ELT(out, i, Rf_mkCharLenCE(sb.buf, (int) sb.len, CE_UTF8));
    vmaxset(vmax);
  }
  UNPROTECT(1);
  return out;
}
