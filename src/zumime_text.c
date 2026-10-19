/* Structured text (design section 6.4), at the probable level because the
 * evidence is grammar, not magic:
 *
 *   - a shebang's interpreter decides scripts, and fills `interpreter`;
 *   - the first line decides vCard, iCalendar, WebVTT, SubRip, WARC, RTF,
 *     PGP armour and PEM;
 *   - XML: the root element's local name and namespace, after the
 *     declaration, comments, processing instructions and the doctype;
 *   - JSON: a syntax scan of the bytes in hand, the top-level object's keys,
 *     and NDJSON as newline-separated objects.
 *
 * Every answer descends from text/plain; an XML dialect from
 * application/xml. Text that only looks like a format stays text/plain. */

#include <string.h>

#include "zumime_sniff.h"

static int is_ws(unsigned char c) {
  return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f';
}

static unsigned char lower(unsigned char c) {
  return (c >= 'A' && c <= 'Z') ? (unsigned char) (c + 32) : c;
}

static int starts(const unsigned char *b, size_t len, const char *lit) {
  size_t n = strlen(lit);
  return len >= n && memcmp(b, lit, n) == 0;
}

static int starts_ci(const unsigned char *b, size_t len, const char *lit) {
  size_t n = strlen(lit);
  if (len < n) return 0;
  for (size_t i = 0; i < n; i++)
    if (lower(b[i]) != lower((unsigned char) lit[i])) return 0;
  return 1;
}

static int is_digit(unsigned char c) { return c >= '0' && c <= '9'; }

/* --- Shebang ---------------------------------------------------------------- */

static int interpreter_type(const char *p) {
  static const struct {
    const char *name;
    int prefix; /* matches "python3.12" for "python" */
    int type;
  } map[] = {
      {"sh", 0, ZUMIME_T_APPLICATION_X_SH},    {"bash", 0, ZUMIME_T_APPLICATION_X_SH},
      {"zsh", 0, ZUMIME_T_APPLICATION_X_SH},   {"dash", 0, ZUMIME_T_APPLICATION_X_SH},
      {"ksh", 0, ZUMIME_T_APPLICATION_X_SH},   {"ash", 0, ZUMIME_T_APPLICATION_X_SH},
      {"python", 1, ZUMIME_T_TEXT_X_PYTHON},   {"pypy", 1, ZUMIME_T_TEXT_X_PYTHON},
      {"perl", 1, ZUMIME_T_TEXT_X_PERL},       {"php", 1, ZUMIME_T_TEXT_X_PHP},
      {"lua", 1, ZUMIME_T_TEXT_X_LUA},         {"luajit", 0, ZUMIME_T_TEXT_X_LUA},
      {"tclsh", 1, ZUMIME_T_APPLICATION_X_TCL}, {"wish", 1, ZUMIME_T_APPLICATION_X_TCL},
      {"node", 0, ZUMIME_T_TEXT_JAVASCRIPT},   {"nodejs", 0, ZUMIME_T_TEXT_JAVASCRIPT},
      {"deno", 0, ZUMIME_T_TEXT_JAVASCRIPT},   {"bun", 0, ZUMIME_T_TEXT_JAVASCRIPT},
      {"Rscript", 0, ZUMIME_T_TEXT_X_R},       {"R", 0, ZUMIME_T_TEXT_X_R},
  };
  for (size_t i = 0; i < sizeof(map) / sizeof(map[0]); i++) {
    size_t n = strlen(map[i].name);
    if (strncmp(p, map[i].name, n) != 0) continue;
    if (p[n] == '\0') return map[i].type;
    if (map[i].prefix && (is_digit((unsigned char) p[n]) || p[n] == '.'))
      return map[i].type;
  }
  return -1;
}

/* The next space-separated word of the first line, from *pos to end. */
static int next_word(const unsigned char *b, size_t end, size_t *pos,
                     size_t *ws, size_t *we) {
  while (*pos < end && (b[*pos] == ' ' || b[*pos] == '\t')) (*pos)++;
  *ws = *pos;
  while (*pos < end && b[*pos] != ' ' && b[*pos] != '\t') (*pos)++;
  *we = *pos;
  return *we > *ws;
}

/* "#!/usr/bin/env -S python3 -u" -> "python3": the program's base name,
 * through env and past env's options and VAR=value assignments. */
static int shebang(const unsigned char *b, size_t len, char *interp) {
  size_t end = 2;
  while (end < len && end < 256 && b[end] != '\n' && b[end] != '\r') end++;
  size_t pos = 2, ws, we;
  if (!next_word(b, end, &pos, &ws, &we)) return -1;
  size_t base = ws;
  for (size_t i = ws; i < we; i++)
    if (b[i] == '/') base = i + 1;
  if (we - base == 3 && memcmp(b + base, "env", 3) == 0) {
    for (;;) {
      if (!next_word(b, end, &pos, &ws, &we)) return -1;
      if (b[ws] == '-' || memchr(b + ws, '=', we - ws) != NULL) continue;
      break;
    }
    base = ws;
    for (size_t i = ws; i < we; i++)
      if (b[i] == '/') base = i + 1;
  }
  size_t n = we - base;
  if (n == 0 || n > ZUMIME_INTERP_MAX) return -1;
  for (size_t i = base; i < we; i++)
    if (b[i] < 0x21 || b[i] > 0x7E) return -1;
  memcpy(interp, b + base, n);
  interp[n] = '\0';
  return interpreter_type(interp);
}

/* --- First-line formats ------------------------------------------------------ */

static int subrip_time(const unsigned char *p, size_t n) {
  /* HH:MM:SS,mmm */
  static const char shape[] = "dd:dd:dd,ddd";
  if (n < 12) return 0;
  for (int i = 0; i < 12; i++) {
    if (shape[i] == 'd' ? !is_digit(p[i]) : p[i] != (unsigned char) shape[i])
      return 0;
  }
  return 1;
}

static int line_format(const unsigned char *b, size_t len) {
  if (starts_ci(b, len, "BEGIN:VCARD")) return ZUMIME_T_TEXT_VCARD;
  if (starts_ci(b, len, "BEGIN:VCALENDAR")) return ZUMIME_T_TEXT_CALENDAR;
  if (starts(b, len, "WEBVTT") &&
      (len == 6 || b[6] == ' ' || b[6] == '\t' || b[6] == '\r' || b[6] == '\n'))
    return ZUMIME_T_TEXT_VTT;
  if (starts(b, len, "WARC/1.")) return ZUMIME_T_APPLICATION_WARC;
  if (starts(b, len, "{\\rtf")) return ZUMIME_T_APPLICATION_RTF;
  if (starts(b, len, "%!PS")) return ZUMIME_T_APPLICATION_POSTSCRIPT;
  if (starts(b, len, "-----BEGIN PGP MESSAGE-----"))
    return ZUMIME_T_APPLICATION_PGP_ENCRYPTED;
  if (starts(b, len, "-----BEGIN PGP SIGNATURE-----") ||
      starts(b, len, "-----BEGIN PGP SIGNED MESSAGE-----"))
    return ZUMIME_T_APPLICATION_PGP_SIGNATURE;
  if (starts(b, len, "-----BEGIN PGP PUBLIC KEY BLOCK-----") ||
      starts(b, len, "-----BEGIN PGP PRIVATE KEY BLOCK-----"))
    return ZUMIME_T_APPLICATION_PGP_KEYS;
  if (starts(b, len, "-----BEGIN ")) {
    size_t i = 11;
    while (i < len && i < 80 && b[i] != '\n' && b[i] != '-') i++;
    if (i + 5 <= len && memcmp(b + i, "-----", 5) == 0)
      return ZUMIME_T_APPLICATION_X_PEM_FILE;
  }
  /* SubRip: a cue number, then "00:00:01,000 --> 00:00:02,000". */
  size_t i = 0;
  while (i < len && is_digit(b[i])) i++;
  if (i > 0 && i < 10) {
    if (i < len && b[i] == '\r') i++;
    if (i < len && b[i] == '\n') {
      i++;
      if (subrip_time(b + i, len - i) && len - i >= 29 &&
          memcmp(b + i + 12, " --> ", 5) == 0 && subrip_time(b + i + 17, len - i - 17))
        return ZUMIME_T_APPLICATION_X_SUBRIP;
    }
  }
  return -1;
}

/* --- XML ------------------------------------------------------------------- */

typedef struct {
  const unsigned char *b;
  size_t len, pos;
} cursor;

static void skip_ws(cursor *c) {
  while (c->pos < c->len && is_ws(c->b[c->pos])) c->pos++;
}

/* Skip to just past `lit`; 0 when it is not in hand. */
static int skip_past(cursor *c, const char *lit) {
  size_t n = strlen(lit);
  while (c->pos + n <= c->len) {
    if (memcmp(c->b + c->pos, lit, n) == 0) {
      c->pos += n;
      return 1;
    }
    c->pos++;
  }
  return 0;
}

static int name_char(unsigned char ch) {
  return !is_ws(ch) && ch != '>' && ch != '/' && ch != '=' && ch != '"' &&
         ch != '\'' && ch != '<';
}

typedef struct {
  const unsigned char *local;
  size_t local_len;
  const unsigned char *ns; /* the namespace of the root's prefix */
  size_t ns_len;
  const unsigned char *odf_mimetype; /* office:mimetype attribute */
  size_t odf_len;
} xml_root;

static int span_is(const unsigned char *p, size_t n, const char *lit) {
  return n == strlen(lit) && memcmp(p, lit, n) == 0;
}

static int span_starts(const unsigned char *p, size_t n, const char *lit) {
  size_t m = strlen(lit);
  return n >= m && memcmp(p, lit, m) == 0;
}

/* Find the root element. Returns 1 with root filled. */
static int xml_find_root(cursor *c, xml_root *root) {
  for (int guard = 0; guard < 64; guard++) {
    skip_ws(c);
    if (c->pos >= c->len || c->b[c->pos] != '<') return 0;
    const unsigned char *p = c->b + c->pos;
    size_t left = c->len - c->pos;
    if (starts(p, left, "<?")) {
      if (!skip_past(c, "?>")) return 0;
    } else if (starts(p, left, "<!--")) {
      if (!skip_past(c, "-->")) return 0;
    } else if (starts(p, left, "<!")) {
      /* A doctype, perhaps with an internal subset in brackets. */
      int depth = 0;
      while (c->pos < c->len) {
        unsigned char ch = c->b[c->pos++];
        if (ch == '[') depth++;
        if (ch == ']') depth--;
        if (ch == '>' && depth <= 0) break;
      }
      if (c->pos >= c->len) return 0;
    } else {
      break;
    }
  }
  if (c->pos >= c->len || c->b[c->pos] != '<') return 0;
  c->pos++;
  size_t s = c->pos;
  while (c->pos < c->len && name_char(c->b[c->pos])) c->pos++;
  if (c->pos == s || c->pos >= c->len) return 0;
  const unsigned char *qname = c->b + s;
  size_t qlen = c->pos - s;
  const unsigned char *colon = memchr(qname, ':', qlen);
  size_t plen = colon ? (size_t) (colon - qname) : 0;
  root->local = colon ? colon + 1 : qname;
  root->local_len = colon ? qlen - plen - 1 : qlen;
  root->ns = NULL;
  root->ns_len = 0;
  root->odf_mimetype = NULL;
  root->odf_len = 0;

  /* Attributes, for xmlns and office:mimetype. */
  for (int guard = 0; guard < 256; guard++) {
    skip_ws(c);
    if (c->pos >= c->len || c->b[c->pos] == '>' || c->b[c->pos] == '/') break;
    size_t as = c->pos;
    while (c->pos < c->len && name_char(c->b[c->pos])) c->pos++;
    const unsigned char *aname = c->b + as;
    size_t alen = c->pos - as;
    if (alen == 0) break;
    skip_ws(c);
    if (c->pos >= c->len || c->b[c->pos] != '=') continue;
    c->pos++;
    skip_ws(c);
    if (c->pos >= c->len || (c->b[c->pos] != '"' && c->b[c->pos] != '\'')) break;
    unsigned char q = c->b[c->pos++];
    size_t vs = c->pos;
    while (c->pos < c->len && c->b[c->pos] != q) c->pos++;
    if (c->pos >= c->len) break;
    const unsigned char *val = c->b + vs;
    size_t vlen = c->pos - vs;
    c->pos++;
    int default_ns = span_is(aname, alen, "xmlns");
    int prefixed_ns = span_starts(aname, alen, "xmlns:") &&
                      alen - 6 == plen && memcmp(aname + 6, qname, plen) == 0;
    if ((plen == 0 && default_ns) || (plen > 0 && prefixed_ns)) {
      root->ns = val;
      root->ns_len = vlen;
    }
    if (span_is(aname, alen, "office:mimetype")) {
      root->odf_mimetype = val;
      root->odf_len = vlen;
    }
  }
  return 1;
}

/* RSS 1.0 is RDF whose root declares the RSS 1.0 namespace. */
static int mentions_rss1(const unsigned char *b, size_t len) {
  static const char ns[] = "http://purl.org/rss/1.0/";
  size_t n = sizeof(ns) - 1;
  size_t end = len < 2048 ? len : 2048;
  for (size_t i = 0; i + n <= end; i++)
    if (memcmp(b + i, ns, n) == 0) return 1;
  return 0;
}

static int xml_dialect(const unsigned char *b, size_t len, int is_xml) {
  cursor c = {b, len, 0};
  xml_root r;
  if (!xml_find_root(&c, &r)) return -1;
  const unsigned char *ns = r.ns;
  size_t nl = r.ns_len;
#define LOCAL(lit) span_is(r.local, r.local_len, lit)
#define NS(lit) (ns != NULL && span_is(ns, nl, lit))
#define NS_STARTS(lit) (ns != NULL && span_starts(ns, nl, lit))
  if (LOCAL("svg") && (NS("http://www.w3.org/2000/svg") || (is_xml && !ns)))
    return ZUMIME_T_IMAGE_SVG_XML;
  if (LOCAL("feed") && NS("http://www.w3.org/2005/Atom"))
    return ZUMIME_T_APPLICATION_ATOM_XML;
  if ((LOCAL("rss") && is_xml) ||
      (LOCAL("RDF") && is_xml && mentions_rss1(b, len)))
    return ZUMIME_T_APPLICATION_RSS_XML;
  if (LOCAL("kml") && (NS_STARTS("http://www.opengis.net/kml/") ||
                       NS_STARTS("http://earth.google.com/kml/")))
    return ZUMIME_T_APPLICATION_VND_GOOGLE_EARTH_KML_XML;
  if (LOCAL("gpx") && NS_STARTS("http://www.topografix.com/GPX/"))
    return ZUMIME_T_APPLICATION_GPX_XML;
  if (LOCAL("X3D") && (NS_STARTS("http://www.web3d.org/") || is_xml))
    return ZUMIME_T_MODEL_X3D_XML;
  if (LOCAL("xliff") && NS_STARTS("urn:oasis:names:tc:xliff:document:"))
    return ZUMIME_T_APPLICATION_XLIFF_XML;
  if (LOCAL("COLLADA") && NS_STARTS("http://www.collada.org/"))
    return ZUMIME_T_MODEL_VND_COLLADA_XML;
  if (LOCAL("html") && NS("http://www.w3.org/1999/xhtml"))
    return ZUMIME_T_APPLICATION_XHTML_XML;
  if ((LOCAL("book") || LOCAL("article") || LOCAL("chapter")) &&
      NS("http://docbook.org/ns/docbook"))
    return ZUMIME_T_APPLICATION_DOCBOOK_XML;
  if (LOCAL("document") && NS("urn:oasis:names:tc:opendocument:xmlns:office:1.0") &&
      r.odf_mimetype != NULL) {
    const unsigned char *m = r.odf_mimetype;
    size_t ml = r.odf_len;
    if (span_is(m, ml, "application/vnd.oasis.opendocument.text"))
      return ZUMIME_T_APPLICATION_VND_OASIS_OPENDOCUMENT_TEXT_FLAT_XML;
    if (span_is(m, ml, "application/vnd.oasis.opendocument.spreadsheet"))
      return ZUMIME_T_APPLICATION_VND_OASIS_OPENDOCUMENT_SPREADSHEET_FLAT_XML;
    if (span_is(m, ml, "application/vnd.oasis.opendocument.presentation"))
      return ZUMIME_T_APPLICATION_VND_OASIS_OPENDOCUMENT_PRESENTATION_FLAT_XML;
    if (span_is(m, ml, "application/vnd.oasis.opendocument.graphics"))
      return ZUMIME_T_APPLICATION_VND_OASIS_OPENDOCUMENT_GRAPHICS_FLAT_XML;
  }
#undef LOCAL
#undef NS
#undef NS_STARTS
  return -1;
}

/* --- JSON ------------------------------------------------------------------
 * A syntax scan, not a parse: it checks the grammar of the bytes in hand and
 * notes the top-level object's keys. Running out of bytes mid-value is
 * "partial", accepted only when the bytes were cut by the read limit. */

enum { J_INVALID = 0, J_OK = 1, J_PARTIAL = 2 };
enum {
  K_TYPE = 1,
  K_FEATURES = 2,
  K_GEOMETRY = 4,
  K_ASSET = 8,
  K_LOG = 16,
  K_BOMFORMAT = 32
};

typedef struct {
  const unsigned char *b;
  size_t len, pos;
  unsigned keys;
} json;

static void jskip(json *j) {
  while (j->pos < j->len && (j->b[j->pos] == ' ' || j->b[j->pos] == '\t' ||
                             j->b[j->pos] == '\r' || j->b[j->pos] == '\n'))
    j->pos++;
}

static int is_hex(unsigned char c) {
  return is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static int jstring(json *j, size_t *start, size_t *slen) {
  j->pos++; /* the opening quote */
  *start = j->pos;
  while (j->pos < j->len) {
    unsigned char c = j->b[j->pos];
    if (c < 0x20) return J_INVALID;
    if (c == '"') {
      *slen = j->pos - *start;
      j->pos++;
      return J_OK;
    }
    if (c == '\\') {
      if (j->pos + 1 >= j->len) return J_PARTIAL;
      unsigned char e = j->b[j->pos + 1];
      if (e == 'u') {
        for (size_t k = 2; k < 6; k++) {
          if (j->pos + k >= j->len) return J_PARTIAL;
          if (!is_hex(j->b[j->pos + k])) return J_INVALID;
        }
        j->pos += 6;
        continue;
      }
      if (!strchr("\"\\/bfnrt", e)) return J_INVALID;
      j->pos += 2;
      continue;
    }
    j->pos++;
  }
  return J_PARTIAL;
}

static int jdigits(json *j) {
  size_t s = j->pos;
  while (j->pos < j->len && is_digit(j->b[j->pos])) j->pos++;
  return j->pos > s;
}

static int jnumber(json *j) {
  if (j->b[j->pos] == '-') j->pos++;
  if (j->pos >= j->len) return J_PARTIAL;
  if (j->b[j->pos] == '0')
    j->pos++;
  else if (!jdigits(j))
    return J_INVALID;
  if (j->pos < j->len && j->b[j->pos] == '.') {
    j->pos++;
    if (j->pos >= j->len) return J_PARTIAL;
    if (!jdigits(j)) return J_INVALID;
  }
  if (j->pos < j->len && (j->b[j->pos] == 'e' || j->b[j->pos] == 'E')) {
    j->pos++;
    if (j->pos < j->len && (j->b[j->pos] == '+' || j->b[j->pos] == '-')) j->pos++;
    if (j->pos >= j->len) return J_PARTIAL;
    if (!jdigits(j)) return J_INVALID;
  }
  return j->pos >= j->len ? J_PARTIAL : J_OK;
}

static int jliteral(json *j, const char *lit) {
  size_t n = strlen(lit);
  for (size_t i = 0; i < n; i++) {
    if (j->pos + i >= j->len) return J_PARTIAL;
    if (j->b[j->pos + i] != (unsigned char) lit[i]) return J_INVALID;
  }
  j->pos += n;
  return J_OK;
}

static void note_key(json *j, size_t s, size_t n) {
  const unsigned char *k = j->b + s;
  if (span_is(k, n, "type")) j->keys |= K_TYPE;
  if (span_is(k, n, "features")) j->keys |= K_FEATURES;
  if (span_is(k, n, "geometry")) j->keys |= K_GEOMETRY;
  if (span_is(k, n, "asset")) j->keys |= K_ASSET;
  if (span_is(k, n, "log")) j->keys |= K_LOG;
  if (span_is(k, n, "bomFormat")) j->keys |= K_BOMFORMAT;
}

static int jvalue(json *j, int depth);

static int jcontainer(json *j, int depth, int object) {
  unsigned char close = object ? '}' : ']';
  j->pos++;
  jskip(j);
  if (j->pos >= j->len) return J_PARTIAL;
  if (j->b[j->pos] == close) {
    j->pos++;
    return J_OK;
  }
  for (;;) {
    if (object) {
      if (j->b[j->pos] != '"') return J_INVALID;
      size_t ks = 0, kl = 0;
      int r = jstring(j, &ks, &kl);
      if (r != J_OK) return r;
      if (depth == 0) note_key(j, ks, kl);
      jskip(j);
      if (j->pos >= j->len) return J_PARTIAL;
      if (j->b[j->pos] != ':') return J_INVALID;
      j->pos++;
    }
    int r = jvalue(j, depth + 1);
    if (r != J_OK) return r;
    jskip(j);
    if (j->pos >= j->len) return J_PARTIAL;
    if (j->b[j->pos] == close) {
      j->pos++;
      return J_OK;
    }
    if (j->b[j->pos] != ',') return J_INVALID;
    j->pos++;
    jskip(j);
    if (j->pos >= j->len) return J_PARTIAL;
  }
}

static int jvalue(json *j, int depth) {
  if (depth > 64) return J_PARTIAL; /* deep enough: stop looking */
  jskip(j);
  if (j->pos >= j->len) return J_PARTIAL;
  unsigned char c = j->b[j->pos];
  size_t s, n;
  switch (c) {
  case '{':
    return jcontainer(j, depth, 1);
  case '[':
    return jcontainer(j, depth, 0);
  case '"':
    return jstring(j, &s, &n);
  case 't':
    return jliteral(j, "true");
  case 'f':
    return jliteral(j, "false");
  case 'n':
    return jliteral(j, "null");
  default:
    if (c == '-' || is_digit(c)) return jnumber(j);
    return J_INVALID;
  }
}

static int json_type(const unsigned char *b, size_t len, int truncated) {
  json j = {b, len, 0, 0};
  int object = b[0] == '{';
  int r = jvalue(&j, 0);
  if (r == J_INVALID || (r == J_PARTIAL && !truncated)) return -1;

  if (r == J_OK) {
    /* Anything after the first value: NDJSON or not JSON at all. */
    size_t after = j.pos;
    jskip(&j);
    if (j.pos < j.len) {
      int newline = memchr(b + after, '\n', j.pos - after) != NULL;
      if (!object || !newline) return -1;
      for (int k = 0; k < 8 && j.pos < j.len; k++) {
        if (j.b[j.pos] != '{') return -1;
        int rr = jvalue(&j, 1);
        if (rr == J_INVALID || (rr == J_PARTIAL && !truncated)) return -1;
        if (rr == J_PARTIAL) break;
        size_t a = j.pos;
        jskip(&j);
        if (j.pos < j.len && memchr(b + a, '\n', j.pos - a) == NULL) return -1;
      }
      return ZUMIME_T_APPLICATION_X_NDJSON;
    }
  }
  if (object) {
    if ((j.keys & K_TYPE) && (j.keys & (K_FEATURES | K_GEOMETRY)))
      return ZUMIME_T_APPLICATION_GEO_JSON;
    if (j.keys & K_ASSET) return ZUMIME_T_MODEL_GLTF_JSON;
    if (j.keys & K_LOG) return ZUMIME_T_APPLICATION_HAR_JSON;
    if (j.keys & K_BOMFORMAT) return ZUMIME_T_APPLICATION_VND_CYCLONEDX_JSON;
  }
  return ZUMIME_T_APPLICATION_JSON;
}

/* --- Entry point ------------------------------------------------------------ */

int zumime_read_text(const unsigned char *buf, size_t len, int current,
                     int truncated, char *interpreter) {
  const unsigned char *b = buf;
  if (len >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF) {
    b += 3;
    len -= 3;
  } else if (len >= 2 && ((b[0] == 0xFE && b[1] == 0xFF) ||
                          (b[0] == 0xFF && b[1] == 0xFE))) {
    /* UTF-16 text is read no further than an XML declaration. */
    static const unsigned char be[10] = {0, '<', 0, '?', 0, 'x', 0, 'm', 0, 'l'};
    static const unsigned char le[10] = {'<', 0, '?', 0, 'x', 0, 'm', 0, 'l', 0};
    if (len >= 12 && memcmp(b + 2, b[0] == 0xFE ? be : le, 10) == 0)
      return ZUMIME_T_APPLICATION_XML;
    return -1;
  }
  if (current == ZUMIME_T_APPLICATION_XML) return xml_dialect(b, len, 1);
  if (starts(b, len, "<?xml")) {
    int d = xml_dialect(b, len, 1);
    return d >= 0 ? d : ZUMIME_T_APPLICATION_XML;
  }

  if (len >= 2 && b[0] == '#' && b[1] == '!') return shebang(b, len, interpreter);
  int t = line_format(b, len);
  if (t >= 0) return t;

  /* SPSS portable files are text: a 200-byte vanity header and a 256-byte
   * character table, broken into 80-column lines, then "SPSSPORT". */
  size_t pend = len < 600 ? len : 600;
  for (size_t k = 440; k + 8 <= pend; k++)
    if (memcmp(b + k, "SPSSPORT", 8) == 0) return ZUMIME_T_APPLICATION_X_SPSS_POR;

  size_t i = 0;
  while (i < len && is_ws(b[i])) i++;
  if (i >= len) return -1;
  if (b[i] == '<') return xml_dialect(b + i, len - i, 0);
  if (b[i] == '{' || b[i] == '[') return json_type(b + i, len - i, truncated);
  return -1;
}
