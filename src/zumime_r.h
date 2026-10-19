#ifndef ZUMIME_R_H
#define ZUMIME_R_H

#define R_NO_REMAP
#include <R.h>
#include <Rinternals.h>

/* .Call entry points, registered in init.c. */
SEXP zumime_mime_parse(SEXP x);
SEXP zumime_mime_format(SEXP records);
SEXP zumime_suffixes(SEXP x);

#endif
