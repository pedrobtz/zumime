/* R glue for the sniffer core. The only place a type id becomes a CHARSXP
 * is type_charsxp() (design section 4). */

#include <string.h>

#include "zumime_r.h"
#include "zumime_sniff.h"

static SEXP type_charsxp(int id) {
  if (id < 0 || id >= ZUMIME_N_TYPES) return NA_STRING;
  return Rf_mkChar(zumime_type_names[id]);
}

static const char *const confidence_names[] = {"none", "extension",
                                               "probable", "definite"};

static SEXP charset_charsxp(const zumime_result *r) {
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

static SEXP newline_charsxp(int nl) {
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
                                                          : type_charsxp(r.type)));
  SET_VECTOR_ELT(out, 1, Rf_mkString(confidence_names[r.confidence]));
  SET_VECTOR_ELT(out, 2, zumime_scalar_string(charset_charsxp(&r)));
  SET_VECTOR_ELT(out, 3, zumime_scalar_string(newline_charsxp(r.newline)));
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
    SET_STRING_ELT(type, i, type_charsxp(row->type));
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
