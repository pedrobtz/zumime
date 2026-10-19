/* Suffix extraction for mime_guess() (design section 6.6): the last one and
 * the last two dot-separated suffixes of the final path component,
 * lower-cased. A leading dot names a hidden file, not an extension. The R
 * side looks both up in the extension table, the compound first. */

#include <string.h>

#include "zumime_r.h"

static SEXP lower_char(const char *s, size_t n) {
  char buf[64];
  if (n >= sizeof(buf)) return NA_STRING; /* no known suffix is that long */
  for (size_t i = 0; i < n; i++) {
    char c = s[i];
    buf[i] = (c >= 'A' && c <= 'Z') ? (char) (c + 32) : c;
  }
  return Rf_mkCharLenCE(buf, (int) n, CE_UTF8);
}

SEXP zumime_suffixes(SEXP x) {
  R_xlen_t n = XLENGTH(x);
  SEXP one = PROTECT(Rf_allocVector(STRSXP, n));
  SEXP two = PROTECT(Rf_allocVector(STRSXP, n));
  for (R_xlen_t i = 0; i < n; i++) {
    SET_STRING_ELT(one, i, NA_STRING);
    SET_STRING_ELT(two, i, NA_STRING);
    SEXP el = STRING_ELT(x, i);
    if (el == NA_STRING) continue;
    const char *s = CHAR(el);
    size_t len = strlen(s);
    size_t base = 0;
    for (size_t k = 0; k < len; k++)
      if (s[k] == '/' || s[k] == '\\') base = k + 1;
    while (base < len && s[base] == '.') base++;
    const char *last = NULL, *prev = NULL;
    for (size_t k = base; k < len; k++) {
      if (s[k] == '.') {
        prev = last;
        last = s + k;
      }
    }
    if (last == NULL) continue;
    SET_STRING_ELT(one, i, lower_char(last + 1, (size_t) (s + len - last - 1)));
    if (prev != NULL)
      SET_STRING_ELT(two, i, lower_char(prev + 1, (size_t) (s + len - prev - 1)));
  }
  SEXP out = PROTECT(Rf_allocVector(VECSXP, 2));
  SET_VECTOR_ELT(out, 0, one);
  SET_VECTOR_ELT(out, 1, two);
  UNPROTECT(3);
  return out;
}
