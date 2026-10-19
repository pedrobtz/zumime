#ifndef ZUMIME_R_H
#define ZUMIME_R_H

#define R_NO_REMAP
#include <R.h>
#include <Rinternals.h>

/* A length-one character vector from a fresh CHARSXP, protecting it across
 * the allocation. */
static inline SEXP zumime_scalar_string(SEXP ch) {
  PROTECT(ch);
  SEXP out = Rf_ScalarString(ch);
  UNPROTECT(1);
  return out;
}

/* .Call entry points, registered in init.c. */
SEXP zumime_mime_parse(SEXP x);
SEXP zumime_mime_format(SEXP records);
SEXP zumime_suffixes(SEXP x);
SEXP zumime_sniff_raw(SEXP x, SEXP limit, SEXP supplied, SEXP apache_bug,
                      SEXP no_sniff, SEXP context);
SEXP zumime_signature_rows(void);

#endif
