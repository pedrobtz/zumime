#define R_NO_REMAP
#include <R.h>
#include <Rinternals.h>
#include <R_ext/Rdynload.h>
#include <R_ext/Visibility.h>
#include <string.h>

#include "zumime_r.h"

static const R_CallMethodDef call_methods[] = {
  {"zumime_mime_parse", (DL_FUNC) &zumime_mime_parse, 1},
  {"zumime_mime_format", (DL_FUNC) &zumime_mime_format, 1},
  {"zumime_suffixes", (DL_FUNC) &zumime_suffixes, 1},
  {"zumime_sniff_raw", (DL_FUNC) &zumime_sniff_raw, 6},
  {"zumime_signature_rows", (DL_FUNC) &zumime_signature_rows, 0},
  {"zumime_sniff_paths", (DL_FUNC) &zumime_sniff_paths, 7},
  {"zumime_register_type", (DL_FUNC) &zumime_register_type, 5},
  {"zumime_unregister_type", (DL_FUNC) &zumime_unregister_type, 1},
  {"zumime_check", (DL_FUNC) &zumime_check, 5},
  {"zumime_probe_count", (DL_FUNC) &zumime_probe_count, 0},
  {"zumime_stream_new", (DL_FUNC) &zumime_stream_new, 1},
  {"zumime_stream_state", (DL_FUNC) &zumime_stream_state, 1},
  {"zumime_stream_buffer", (DL_FUNC) &zumime_stream_buffer, 1},
  {"zumime_stream_push", (DL_FUNC) &zumime_stream_push, 9},
  {"zumime_stream_bytewise", (DL_FUNC) &zumime_stream_bytewise, 2},
  {NULL, NULL, 0}
};

/* The only symbol the shared object exports: everything else is reached
 * through the registration table (alignment R3, test-abi.R). */
void attribute_visible R_init_zumime(DllInfo *dll) {
  /* The R side of the session registry starts empty with each load of the
   * namespace, so the C side must too: a platform may keep the library
   * mapped across library.dynam.unload(). */
  memset(zumime_reg, 0, sizeof(zumime_reg));
  R_registerRoutines(dll, NULL, call_methods, NULL, NULL);
  R_useDynamicSymbols(dll, FALSE);
  R_forceSymbols(dll, TRUE);
}
