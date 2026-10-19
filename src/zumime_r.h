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

#include "zumime_sniff.h"

/* CHARSXPs for core results (zumime_r.c). zumime_type_charsxp() is the
 * one place a type id becomes a string. */
SEXP zumime_type_charsxp(int id);
SEXP zumime_charset_charsxp(const zumime_result *r);
SEXP zumime_confidence_charsxp(int confidence);
SEXP zumime_newline_charsxp(int newline);

/* .Call entry points, registered in init.c. */
SEXP zumime_mime_parse(SEXP x);
SEXP zumime_mime_format(SEXP records);
SEXP zumime_suffixes(SEXP x);
SEXP zumime_sniff_raw(SEXP x, SEXP limit, SEXP supplied, SEXP apache_bug,
                      SEXP no_sniff, SEXP context);
SEXP zumime_signature_rows(void);
SEXP zumime_sniff_paths(SEXP paths, SEXP limit, SEXP complete, SEXP supplied,
                        SEXP apache_bug, SEXP no_sniff, SEXP context);
SEXP zumime_register_type(SEXP name, SEXP parent, SEXP offset, SEXP bytes,
                          SEXP mask);
SEXP zumime_unregister_type(SEXP name);
SEXP zumime_check(SEXP x, SEXP limit, SEXP related);
SEXP zumime_probe_count(void);

#endif
