/* R glue for the sniffer core. The only place a type id becomes a CHARSXP
 * is zumime_type_charsxp() (design section 4). */

#include <stdint.h>
#include <string.h>

#include "zumime_r.h"
#include "zumime_sniff.h"

SEXP zumime_type_charsxp(int id) {
  const char *name = zumime_type_name(id);
  return name ? Rf_mkChar(name) : NA_STRING;
}

static const char *const confidence_names[] = {"none", "extension",
                                               "probable", "definite"};

SEXP zumime_confidence_charsxp(int confidence) {
  return Rf_mkChar(confidence_names[confidence]);
}

SEXP zumime_charset_charsxp(const zumime_result *r) {
  switch (r->charset) {
  case ZUMIME_CS_UTF8:
    return Rf_mkChar("UTF-8");
  case ZUMIME_CS_UTF16BE:
    return Rf_mkChar("UTF-16BE");
  case ZUMIME_CS_UTF16LE:
    return Rf_mkChar("UTF-16LE");
  case ZUMIME_CS_WINDOWS_1252:
    return Rf_mkChar("windows-1252");
  case ZUMIME_CS_ISO_8859_1:
    return Rf_mkChar("ISO-8859-1");
  case ZUMIME_CS_DECLARED:
    /* A declared label is bytes from the input; keep it only when it is
     * printable ASCII, so no invalid string reaches R. */
    for (const char *p = r->cs_label; *p; p++)
      if ((unsigned char) *p < 0x20 || (unsigned char) *p > 0x7E)
        return NA_STRING;
    return Rf_mkChar(r->cs_label);
  default:
    return NA_STRING;
  }
}

SEXP zumime_newline_charsxp(int nl) {
  switch (nl) {
  case ZUMIME_NL_LF:
    return Rf_mkChar("lf");
  case ZUMIME_NL_CRLF:
    return Rf_mkChar("crlf");
  case ZUMIME_NL_CR:
    return Rf_mkChar("cr");
  case ZUMIME_NL_MIXED:
    return Rf_mkChar("mixed");
  default:
    return NA_STRING;
  }
}

/* x: raw; limit: double (0 = all); supplied: canonical essence or NULL;
 * apache_bug, no_sniff: logical; context: integer (enum zumime_context).
 * Returns list(type, confidence, charset, newline, is_text, encrypted,
 * interpreter); type is NA when the computed type is the supplied one. */
SEXP zumime_sniff_raw(SEXP x, SEXP limit, SEXP supplied, SEXP apache_bug,
                      SEXP no_sniff, SEXP context) {
  size_t len = (size_t) XLENGTH(x);
  double lim = REAL(limit)[0];
  int truncated = 0;
  if (lim > 0 && (double) len > lim) {
    len = (size_t) lim;
    truncated = 1;
  }

  zumime_input in;
  memset(&in, 0, sizeof(in));
  in.supplied = Rf_isNull(supplied) ? NULL : CHAR(STRING_ELT(supplied, 0));
  in.supplied_id = in.supplied ? zumime_type_lookup(in.supplied) : -1;
  in.apache_bug = LOGICAL(apache_bug)[0];
  in.no_sniff = LOGICAL(no_sniff)[0];
  in.context = INTEGER(context)[0];
  in.truncated = truncated;
  in.tail = NULL;
  in.tail_len = 0;
  in.tail_off = 0;

  zumime_result r;
  zumime_sniff(RAW(x), len, &in, &r);

  SEXP out = PROTECT(Rf_allocVector(VECSXP, 7));
  SET_VECTOR_ELT(out, 0,
                 zumime_scalar_string(r.type == ZUMIME_SUPPLIED ? NA_STRING
                                                          : zumime_type_charsxp(r.type)));
  SET_VECTOR_ELT(out, 1, zumime_scalar_string(zumime_confidence_charsxp(r.confidence)));
  SET_VECTOR_ELT(out, 2, zumime_scalar_string(zumime_charset_charsxp(&r)));
  SET_VECTOR_ELT(out, 3, zumime_scalar_string(zumime_newline_charsxp(r.newline)));
  int is_text = r.charset != ZUMIME_CS_NONE || r.newline != ZUMIME_NL_NONE;
  if (r.type == ZUMIME_SUPPLIED)
    is_text = in.supplied_id >= 0
                  ? zumime_type_is(in.supplied_id, ZUMIME_T_TEXT_PLAIN)
                  : strncmp(in.supplied, "text/", 5) == 0;
  else
    is_text = zumime_type_is(r.type, ZUMIME_T_TEXT_PLAIN);
  SET_VECTOR_ELT(out, 4, Rf_ScalarLogical(is_text));
  SET_VECTOR_ELT(out, 5, Rf_ScalarLogical(r.encrypted < 0 ? NA_LOGICAL : r.encrypted));
  SET_VECTOR_ELT(out, 6, zumime_scalar_string(r.interpreter[0] ? Rf_mkChar(r.interpreter)
                                                               : NA_STRING));
  UNPROTECT(1);
  return out;
}

/* The signature table as columns, for tests built from the table. */
SEXP zumime_signature_rows(void) {
  int n = zumime_n_sigs;
  SEXP offset = PROTECT(Rf_allocVector(INTSXP, n));
  SEXP pattern = PROTECT(Rf_allocVector(VECSXP, n));
  SEXP mask = PROTECT(Rf_allocVector(VECSXP, n));
  SEXP type = PROTECT(Rf_allocVector(STRSXP, n));
  SEXP group = PROTECT(Rf_allocVector(INTSXP, n));
  SEXP flags = PROTECT(Rf_allocVector(INTSXP, n));
  for (int i = 0; i < n; i++) {
    const zumime_sig *row = &zumime_sigs[i];
    INTEGER(offset)[i] = (int) row->offset;
    SEXP p = Rf_allocVector(RAWSXP, row->len);
    SET_VECTOR_ELT(pattern, i, p);
    memcpy(RAW(p), row->pattern, row->len);
    SEXP m = Rf_allocVector(RAWSXP, row->len);
    SET_VECTOR_ELT(mask, i, m);
    if (row->mask)
      memcpy(RAW(m), row->mask, row->len);
    else
      memset(RAW(m), 0xFF, row->len);
    SET_STRING_ELT(type, i, zumime_type_charsxp(row->type));
    INTEGER(group)[i] = row->group;
    INTEGER(flags)[i] = (int) row->flags;
  }
  SEXP out = PROTECT(Rf_allocVector(VECSXP, 6));
  SET_VECTOR_ELT(out, 0, offset);
  SET_VECTOR_ELT(out, 1, pattern);
  SET_VECTOR_ELT(out, 2, mask);
  SET_VECTOR_ELT(out, 3, type);
  SET_VECTOR_ELT(out, 4, group);
  SET_VECTOR_ELT(out, 5, flags);
  SEXP names = PROTECT(Rf_allocVector(STRSXP, 6));
  const char *nm[] = {"offset", "pattern", "mask", "type", "group", "flags"};
  for (int i = 0; i < 6; i++) SET_STRING_ELT(names, i, Rf_mkChar(nm[i]));
  Rf_setAttrib(out, R_NamesSymbol, names);
  UNPROTECT(8);
  return out;
}

/* mime_register(): name and parent are canonical; bytes and mask are raw
 * or NULL. Returns the id, or NA when the table is full. */
SEXP zumime_register_type(SEXP name, SEXP parent, SEXP offset, SEXP bytes,
                          SEXP mask) {
  int pid = zumime_type_lookup(CHAR(STRING_ELT(parent, 0)));
  int has_rule = !Rf_isNull(bytes);
  size_t len = has_rule ? (size_t) XLENGTH(bytes) : 0;
  int id = zumime_reg_add(CHAR(STRING_ELT(name, 0)), pid, has_rule,
                          (uint32_t) REAL(offset)[0], has_rule ? RAW(bytes) : NULL,
                          Rf_isNull(mask) ? NULL : RAW(mask), len);
  return Rf_ScalarInteger(id < 0 ? NA_INTEGER : id);
}

SEXP zumime_unregister_type(SEXP name) {
  int id = zumime_type_lookup(CHAR(STRING_ELT(name, 0)));
  if (id >= ZUMIME_N_TYPES) zumime_reg_remove(id);
  return R_NilValue;
}

/* --- The incremental sniffer (design section 6.10, D9) --------------------
 * An external pointer whose protected field, list(buffer, n, result), owns
 * every byte: the buffer is an R raw vector, so nothing is leaked across a
 * longjmp. Its address holds only the state, which R does not serialise: a
 * restored sniffer has a NULL address and is undecided again, with the
 * bytes it had. */

enum { ST_UNDECIDED = 1, ST_DECIDED = 2, ST_FINISHED = 3 };

static int stream_state(SEXP s) {
  void *p = R_ExternalPtrAddr(s);
  return p == NULL ? ST_UNDECIDED : (int) (intptr_t) p;
}

static void set_state(SEXP s, int state) {
  R_SetExternalPtrAddr(s, (void *) (intptr_t) state);
}

SEXP zumime_stream_new(SEXP limit) {
  double lim = REAL(limit)[0];
  R_xlen_t cap = lim > 0 ? (R_xlen_t) lim : 4096;
  SEXP prot = PROTECT(Rf_allocVector(VECSXP, 4));
  SET_VECTOR_ELT(prot, 0, Rf_allocVector(RAWSXP, cap));
  SET_VECTOR_ELT(prot, 1, Rf_ScalarInteger(0));
  /* 1 once nothing can decide before the limit: the answer is text, or a
   * reader that settles only at the limit, with the resource header full. */
  SET_VECTOR_ELT(prot, 3, Rf_ScalarInteger(0));
  SEXP s = PROTECT(R_MakeExternalPtr((void *) (intptr_t) ST_UNDECIDED, R_NilValue, prot));
  UNPROTECT(2);
  return s;
}

SEXP zumime_stream_buffer(SEXP s) {
  return VECTOR_ELT(R_ExternalPtrProtected(s), 0);
}

SEXP zumime_stream_state(SEXP s) {
  SEXP prot = R_ExternalPtrProtected(s);
  SEXP out = PROTECT(Rf_allocVector(INTSXP, 2));
  INTEGER(out)[0] = stream_state(s);
  INTEGER(out)[1] = INTEGER(VECTOR_ELT(prot, 1))[0];
  UNPROTECT(1);
  return out;
}

/* Append chunk (unless decided), then sniff what is buffered. final forces
 * an answer. hold: names of types a registered function rule refines,
 * which stay undecided until the limit or the finish. Returns the cached
 * or new answer as zumime_sniff_raw() does, or NULL while undecided. */
SEXP zumime_stream_push(SEXP s, SEXP chunk, SEXP final, SEXP limit,
                        SEXP supplied, SEXP apache_bug, SEXP no_sniff,
                        SEXP context, SEXP hold) {
  SEXP prot = R_ExternalPtrProtected(s);
  int state = stream_state(s);
  if (state != ST_UNDECIDED) {
    if (LOGICAL(final)[0]) set_state(s, ST_FINISHED);
    return VECTOR_ELT(prot, 2);
  }
  double lim = REAL(limit)[0];
  SEXP buf = VECTOR_ELT(prot, 0);
  R_xlen_t n = INTEGER(VECTOR_ELT(prot, 1))[0];
  R_xlen_t add = Rf_isNull(chunk) ? 0 : XLENGTH(chunk);
  if (lim > 0 && n + add > (R_xlen_t) lim) add = (R_xlen_t) lim - n;
  if (add > 0 && n + add > XLENGTH(buf)) {
    /* No limit: grow the buffer, doubling, still owned by R. */
    R_xlen_t cap = XLENGTH(buf);
    while (cap < n + add) cap *= 2;
    SEXP bigger = PROTECT(Rf_allocVector(RAWSXP, cap));
    memcpy(RAW(bigger), RAW(buf), (size_t) n);
    SET_VECTOR_ELT(prot, 0, bigger);
    UNPROTECT(1);
    buf = bigger;
  }
  if (add > 0) memcpy(RAW(buf) + n, RAW(chunk), (size_t) add);
  n += add;
  INTEGER(VECTOR_ELT(prot, 1))[0] = (int) n;

  int is_final = LOGICAL(final)[0];
  int frozen = INTEGER(VECTOR_ELT(prot, 3))[0];
  if (frozen && !is_final && !(lim > 0 && (double) n >= lim)) return R_NilValue;
  zumime_input in;
  memset(&in, 0, sizeof(in));
  in.supplied = Rf_isNull(supplied) ? NULL : CHAR(STRING_ELT(supplied, 0));
  in.supplied_id = in.supplied ? zumime_type_lookup(in.supplied) : -1;
  in.apache_bug = LOGICAL(apache_bug)[0];
  in.no_sniff = LOGICAL(no_sniff)[0];
  in.context = INTEGER(context)[0];
  in.truncated = !is_final;

  zumime_result r;
  zumime_sniff(RAW(buf), (size_t) n, &in, &r);
  size_t ulim = lim > 0 ? (size_t) lim : 0;
  int decide = is_final || zumime_can_decide(RAW(buf), (size_t) n, ulim, &in, &r);
  if (decide && !is_final && !(ulim > 0 && (size_t) n >= ulim)) {
    const char *name = zumime_type_name(r.type);
    for (R_xlen_t k = 0; name && k < XLENGTH(hold); k++)
      if (strcmp(CHAR(STRING_ELT(hold, k)), name) == 0) decide = 0;
  }
  if (!decide) {
    /* Past the resource header, a text answer and the readers that wait
     * for the limit cannot change into a decidable one: the standard's
     * rows and algorithms read only the header, and zumime's rows only
     * binary bytes within it. */
    if (n >= ZUMIME_HEADER_LEN && r.type != ZUMIME_SUPPLIED &&
        (zumime_type_is(r.type, ZUMIME_T_TEXT_PLAIN) ||
         zumime_type_is(r.type, ZUMIME_T_APPLICATION_ZIP) ||
         zumime_type_is(r.type, ZUMIME_T_APPLICATION_X_OLE_STORAGE) ||
         zumime_type_is(r.type, ZUMIME_T_VIDEO_X_MATROSKA) ||
         r.type == ZUMIME_T_APPLICATION_GZIP))
      INTEGER(VECTOR_ELT(prot, 3))[0] = 1;
    return R_NilValue;
  }

  SEXP out = PROTECT(Rf_allocVector(VECSXP, 7));
  SET_VECTOR_ELT(out, 0,
                 zumime_scalar_string(r.type == ZUMIME_SUPPLIED
                                          ? NA_STRING
                                          : zumime_type_charsxp(r.type)));
  SET_VECTOR_ELT(out, 1, zumime_scalar_string(zumime_confidence_charsxp(r.confidence)));
  SET_VECTOR_ELT(out, 2, zumime_scalar_string(zumime_charset_charsxp(&r)));
  SET_VECTOR_ELT(out, 3, zumime_scalar_string(zumime_newline_charsxp(r.newline)));
  int is_text = r.type == ZUMIME_SUPPLIED
                    ? (in.supplied_id >= 0
                           ? zumime_type_is(in.supplied_id, ZUMIME_T_TEXT_PLAIN)
                           : strncmp(in.supplied, "text/", 5) == 0)
                    : zumime_type_is(r.type, ZUMIME_T_TEXT_PLAIN);
  SET_VECTOR_ELT(out, 4, Rf_ScalarLogical(is_text));
  SET_VECTOR_ELT(out, 5, Rf_ScalarLogical(r.encrypted < 0 ? NA_LOGICAL : r.encrypted));
  SET_VECTOR_ELT(out, 6, zumime_scalar_string(r.interpreter[0] ? Rf_mkChar(r.interpreter)
                                                               : NA_STRING));
  SET_VECTOR_ELT(prot, 2, out);
  set_state(s, is_final ? ST_FINISHED : ST_DECIDED);
  UNPROTECT(1);
  return out;
}

/* Test support: feed `x` one byte at a time to a fresh sniffer, in C, and
 * report how many bytes it took to decide and what it decided. */
SEXP zumime_stream_bytewise(SEXP x, SEXP limit) {
  double lim = REAL(limit)[0];
  size_t ulim = lim > 0 ? (size_t) lim : 0;
  size_t len = (size_t) XLENGTH(x);
  zumime_input in;
  memset(&in, 0, sizeof(in));
  in.context = ZUMIME_CTX_NONE;
  zumime_result r;
  size_t n = 0;
  int decided = 0;
  while (n < len && !(ulim > 0 && n >= ulim)) {
    n++;
    in.truncated = 1;
    zumime_sniff(RAW(x), n, &in, &r);
    if (zumime_can_decide(RAW(x), n, ulim, &in, &r)) {
      decided = 1;
      break;
    }
  }
  if (!decided) {
    in.truncated = 0;
    zumime_sniff(RAW(x), n, &in, &r);
  }
  SEXP out = PROTECT(Rf_allocVector(VECSXP, 3));
  SET_VECTOR_ELT(out, 0, Rf_ScalarReal((double) n));
  SET_VECTOR_ELT(out, 1, zumime_scalar_string(zumime_type_charsxp(r.type)));
  SET_VECTOR_ELT(out, 2, Rf_ScalarLogical(decided));
  UNPROTECT(1);
  return out;
}
