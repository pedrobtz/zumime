/* Charset and line endings of a text result (design section 6.5).
 *
 * The chain stops at the first rule that answers: a byte-order mark; for
 * XML, the declaration's encoding; for HTML, the <meta> prescan of the HTML
 * Standard ("prescan a byte stream to determine its encoding") over the
 * first 1024 bytes; valid UTF-8, ignoring a code point cut by the read
 * limit; the C1 rule. The supplied type's charset parameter, which comes
 * first, is applied in R.
 *
 * Declared labels are reported as written (the prescan lower-cases them, as
 * the HTML Standard does), not resolved through the Encoding Standard's
 * label table, except the two remappings the prescan itself makes. */

#include <string.h>

#include "zumime_sniff.h"

static int is_space(unsigned char c) {
  return c == 0x09 || c == 0x0A || c == 0x0C || c == 0x0D || c == 0x20;
}

static unsigned char lower(unsigned char c) {
  return (c >= 'A' && c <= 'Z') ? (unsigned char) (c + 32) : c;
}

static int ieq(const unsigned char *a, size_t alen, const char *b) {
  size_t blen = strlen(b);
  if (alen != blen) return 0;
  for (size_t i = 0; i < alen; i++)
    if (lower(a[i]) != (unsigned char) b[i]) return 0;
  return 1;
}

static int starts_ci(const unsigned char *buf, size_t len, size_t pos,
                     const char *lit) {
  size_t n = strlen(lit);
  if (pos > len || len - pos < n) return 0;
  for (size_t i = 0; i < n; i++)
    if (lower(buf[pos + i]) != (unsigned char) lit[i]) return 0;
  return 1;
}

/* Store a declared label, trimmed of ASCII whitespace. 0 if empty or too
 * long to be a label. */
static int set_label(zumime_result *out, const unsigned char *s, size_t n) {
  while (n > 0 && is_space(s[0])) {
    s++;
    n--;
  }
  while (n > 0 && is_space(s[n - 1])) n--;
  if (n == 0 || n > ZUMIME_LABEL_MAX) return 0;
  memcpy(out->cs_label, s, n);
  out->cs_label[n] = '\0';
  out->charset = ZUMIME_CS_DECLARED;
  return 1;
}

/* --- XML declaration ------------------------------------------------------- */

static int xml_declaration(const unsigned char *buf, size_t len,
                           zumime_result *out) {
  size_t end = len < 1024 ? len : 1024;
  if (!starts_ci(buf, end, 0, "<?xml") || end < 6 || !is_space(buf[5]))
    return 0;
  for (size_t i = 5; i + 1 < end; i++) {
    if (buf[i] == '?' && buf[i + 1] == '>') return 0;
    if (end - i >= 8 && memcmp(buf + i, "encoding", 8) == 0) {
      size_t p = i + 8;
      while (p < end && is_space(buf[p])) p++;
      if (p >= end || buf[p] != '=') continue;
      p++;
      while (p < end && is_space(buf[p])) p++;
      if (p >= end || (buf[p] != '"' && buf[p] != '\'')) return 0;
      unsigned char q = buf[p++];
      size_t s = p;
      while (p < end && buf[p] != q) p++;
      if (p >= end) return 0;
      return set_label(out, buf + s, p - s);
    }
  }
  return 0;
}

/* --- The HTML <meta> prescan --------------------------------------------- */

typedef struct {
  const unsigned char *buf;
  size_t end;
  size_t pos;
  unsigned char name[64];
  size_t name_len;
  unsigned char value[256];
  size_t value_len;
} prescan;

static void put(unsigned char *dst, size_t *n, size_t cap, unsigned char c) {
  if (*n < cap) dst[(*n)++] = lower(c);
}

/* "Get an attribute". Returns 1 with name/value filled, 0 when there is no
 * attribute (a '>' or the end of the bytes). */
static int get_attribute(prescan *ps) {
  const unsigned char *b = ps->buf;
  ps->name_len = 0;
  ps->value_len = 0;
  while (ps->pos < ps->end && (is_space(b[ps->pos]) || b[ps->pos] == '/'))
    ps->pos++;
  if (ps->pos >= ps->end || b[ps->pos] == '>') return 0;

  /* The name. */
  for (;;) {
    if (ps->pos >= ps->end) return 0;
    unsigned char c = b[ps->pos];
    if (c == '=' && ps->name_len > 0) {
      ps->pos++;
      goto value;
    }
    if (is_space(c)) break;
    if (c == '/' || c == '>') return 1;
    put(ps->name, &ps->name_len, sizeof(ps->name), c);
    ps->pos++;
  }
  while (ps->pos < ps->end && is_space(b[ps->pos])) ps->pos++;
  if (ps->pos >= ps->end) return 0;
  if (b[ps->pos] != '=') return 1;
  ps->pos++;

value:
  while (ps->pos < ps->end && is_space(b[ps->pos])) ps->pos++;
  if (ps->pos >= ps->end) return 0;
  if (b[ps->pos] == '"' || b[ps->pos] == '\'') {
    unsigned char q = b[ps->pos];
    for (;;) {
      ps->pos++;
      if (ps->pos >= ps->end) return 0;
      if (b[ps->pos] == q) {
        ps->pos++;
        return 1;
      }
      put(ps->value, &ps->value_len, sizeof(ps->value), b[ps->pos]);
    }
  }
  if (b[ps->pos] == '>') return 1;
  put(ps->value, &ps->value_len, sizeof(ps->value), b[ps->pos]);
  ps->pos++;
  for (;;) {
    if (ps->pos >= ps->end) return 0;
    unsigned char c = b[ps->pos];
    if (is_space(c) || c == '>') return 1;
    put(ps->value, &ps->value_len, sizeof(ps->value), c);
    ps->pos++;
  }
}

/* "Extract a character encoding from a meta element", on a content
 * attribute's value. Returns the label's span in v, or 0. */
static int extract_from_content(const unsigned char *v, size_t n, size_t *s,
                                size_t *len) {
  size_t pos = 0;
  for (;;) {
    size_t i = pos;
    while (i + 7 <= n && !ieq(v + i, 7, "charset")) i++;
    if (i + 7 > n) return 0;
    pos = i + 7;
    while (pos < n && is_space(v[pos])) pos++;
    if (pos >= n || v[pos] != '=') continue;
    pos++;
    while (pos < n && is_space(v[pos])) pos++;
    if (pos >= n) return 0;
    if (v[pos] == '"' || v[pos] == '\'') {
      unsigned char q = v[pos];
      size_t e = pos + 1;
      while (e < n && v[e] != q) e++;
      if (e >= n) return 0;
      *s = pos + 1;
      *len = e - pos - 1;
      return *len > 0;
    }
    size_t e = pos;
    while (e < n && !is_space(v[e]) && v[e] != ';') e++;
    *s = pos;
    *len = e - pos;
    return *len > 0;
  }
}

static int is_utf16_label(const unsigned char *s, size_t n) {
  static const char *labels[] = {"unicodefffe", "utf-16be", "csunicode",
                                 "iso-10646-ucs-2", "ucs-2", "unicode",
                                 "unicodefeff", "utf-16", "utf-16le"};
  for (size_t i = 0; i < sizeof(labels) / sizeof(labels[0]); i++)
    if (ieq(s, n, labels[i])) return 1;
  return 0;
}

/* Apply the prescan's remappings and store the label. */
static int meta_result(zumime_result *out, const unsigned char *s, size_t n) {
  while (n > 0 && is_space(s[0])) {
    s++;
    n--;
  }
  while (n > 0 && is_space(s[n - 1])) n--;
  if (n == 0) return 0;
  if (is_utf16_label(s, n)) {
    out->charset = ZUMIME_CS_UTF8;
    return 1;
  }
  if (ieq(s, n, "x-user-defined")) {
    out->charset = ZUMIME_CS_WINDOWS_1252;
    return 1;
  }
  return set_label(out, s, n);
}

static void skip_to(prescan *ps, unsigned char c) {
  while (ps->pos < ps->end && ps->buf[ps->pos] != c) ps->pos++;
}

static int is_alpha(unsigned char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static int html_meta(const unsigned char *buf, size_t len, zumime_result *out) {
  prescan ps;
  ps.buf = buf;
  ps.end = len < 1024 ? len : 1024;
  ps.pos = 0;
  const unsigned char *b = buf;

  while (ps.pos < ps.end) {
    if (starts_ci(b, ps.end, ps.pos, "<!--")) {
      /* To the first '>' preceded by "--", which may be the opener's. */
      size_t i = ps.pos + 2;
      while (i < ps.end && !(b[i] == '>' && b[i - 1] == '-' && b[i - 2] == '-'))
        i++;
      ps.pos = i;
    } else if (starts_ci(b, ps.end, ps.pos, "<meta") && ps.pos + 5 < ps.end &&
               (is_space(b[ps.pos + 5]) || b[ps.pos + 5] == '/')) {
      ps.pos += 5;
      unsigned char seen[8][16];
      size_t seen_len[8];
      int n_seen = 0;
      int got_pragma = 0, need_pragma = -1;
      unsigned char cs[ZUMIME_LABEL_MAX + 1];
      size_t cs_len = 0;
      int have_cs = 0;
      while (get_attribute(&ps)) {
        int dup = 0;
        for (int k = 0; k < n_seen; k++)
          if (seen_len[k] == ps.name_len &&
              memcmp(seen[k], ps.name, ps.name_len) == 0)
            dup = 1;
        if (dup) continue;
        if (n_seen < 8 && ps.name_len <= 16) {
          memcpy(seen[n_seen], ps.name, ps.name_len);
          seen_len[n_seen++] = ps.name_len;
        }
        if (ieq(ps.name, ps.name_len, "http-equiv")) {
          if (ieq(ps.value, ps.value_len, "content-type")) got_pragma = 1;
        } else if (ieq(ps.name, ps.name_len, "content")) {
          size_t s, l;
          if (!have_cs && extract_from_content(ps.value, ps.value_len, &s, &l) &&
              l <= ZUMIME_LABEL_MAX) {
            memcpy(cs, ps.value + s, l);
            cs_len = l;
            have_cs = 1;
            need_pragma = 1;
          }
        } else if (ieq(ps.name, ps.name_len, "charset")) {
          if (ps.value_len <= ZUMIME_LABEL_MAX) {
            memcpy(cs, ps.value, ps.value_len);
            cs_len = ps.value_len;
            have_cs = ps.value_len > 0;
          }
          need_pragma = 0;
        }
      }
      if (need_pragma >= 0 && !(need_pragma == 1 && !got_pragma) && have_cs &&
          meta_result(out, cs, cs_len))
        return 1;
    } else if (ps.pos + 1 < ps.end && b[ps.pos] == '<' &&
               (is_alpha(b[ps.pos + 1]) ||
                (b[ps.pos + 1] == '/' && ps.pos + 2 < ps.end &&
                 is_alpha(b[ps.pos + 2])))) {
      while (ps.pos < ps.end && !is_space(b[ps.pos]) && b[ps.pos] != '>')
        ps.pos++;
      while (get_attribute(&ps)) {
      }
    } else if (ps.pos + 1 < ps.end && b[ps.pos] == '<' &&
               (b[ps.pos + 1] == '!' || b[ps.pos + 1] == '/' ||
                b[ps.pos + 1] == '?')) {
      skip_to(&ps, '>');
    }
    ps.pos++;
  }
  return 0;
}

/* --- UTF-8 ----------------------------------------------------------------- */

/* 1 when buf is valid UTF-8. With truncated set, a sequence that is cut by
 * the end of the buffer but valid so far does not count against it. */
static int valid_utf8(const unsigned char *buf, size_t len, int truncated) {
  size_t i = 0;
  while (i < len) {
    unsigned char c = buf[i];
    if (c < 0x80) {
      i++;
      continue;
    }
    size_t need;
    unsigned char lo = 0x80, hi = 0xBF;
    if (c >= 0xC2 && c <= 0xDF) {
      need = 1;
    } else if (c >= 0xE0 && c <= 0xEF) {
      need = 2;
      if (c == 0xE0) lo = 0xA0;
      if (c == 0xED) hi = 0x9F;
    } else if (c >= 0xF0 && c <= 0xF4) {
      need = 3;
      if (c == 0xF0) lo = 0x90;
      if (c == 0xF4) hi = 0x8F;
    } else {
      return 0;
    }
    for (size_t k = 1; k <= need; k++) {
      if (i + k >= len) return truncated;
      unsigned char d = buf[i + k];
      if (k == 1 ? (d < lo || d > hi) : (d < 0x80 || d > 0xBF)) return 0;
    }
    i += need + 1;
  }
  return 1;
}

void zumime_charset(const unsigned char *buf, size_t len, int truncated,
                    int is_xml, int is_html, zumime_result *out) {
  if (len >= 3 && buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF) {
    out->charset = ZUMIME_CS_UTF8;
    return;
  }
  if (len >= 2 && buf[0] == 0xFE && buf[1] == 0xFF) {
    out->charset = ZUMIME_CS_UTF16BE;
    return;
  }
  if (len >= 2 && buf[0] == 0xFF && buf[1] == 0xFE) {
    out->charset = ZUMIME_CS_UTF16LE;
    return;
  }
  if (is_xml && xml_declaration(buf, len, out)) return;
  if (is_html && html_meta(buf, len, out)) return;
  if (valid_utf8(buf, len, truncated)) {
    out->charset = ZUMIME_CS_UTF8;
    return;
  }
  int c1 = 0;
  for (size_t i = 0; i < len && !c1; i++)
    if (buf[i] >= 0x80 && buf[i] <= 0x9F) c1 = 1;
  out->charset = c1 ? ZUMIME_CS_WINDOWS_1252 : ZUMIME_CS_ISO_8859_1;
  if (out->confidence > ZUMIME_CONF_PROBABLE)
    out->confidence = ZUMIME_CONF_PROBABLE;
}

int zumime_newline_style(const unsigned char *buf, size_t len) {
  int lf = 0, crlf = 0, cr = 0;
  for (size_t i = 0; i < len; i++) {
    if (buf[i] == '\r') {
      if (i + 1 < len && buf[i + 1] == '\n') {
        crlf = 1;
        i++;
      } else if (i + 1 < len) {
        cr = 1;
      }
    } else if (buf[i] == '\n') {
      lf = 1;
    }
  }
  int kinds = lf + crlf + cr;
  if (kinds == 0) return ZUMIME_NL_NONE;
  if (kinds > 1) return ZUMIME_NL_MIXED;
  return lf ? ZUMIME_NL_LF : crlf ? ZUMIME_NL_CRLF : ZUMIME_NL_CR;
}
