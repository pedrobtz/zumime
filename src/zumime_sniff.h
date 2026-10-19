/* The sniffer core (design section 4, layers 2 and 3): the WHATWG MIME type
 * sniffing algorithm over a byte buffer, the signature table, and the
 * charset chain. Pure C11; nothing here includes an R header, so the core
 * compiles without R (-DZUMIME_STANDALONE), which is how the fuzz target
 * builds it. src/zumime_r.c is the R glue. */

#ifndef ZUMIME_SNIFF_H
#define ZUMIME_SNIFF_H

#include <stddef.h>
#include <stdint.h>

#include "zumime_types.h"

/* The resource header: the standard reads at most this many bytes. */
#define ZUMIME_HEADER_LEN 1445

/* --- Signature table (zumime_table.c) ------------------------------------ */

enum zumime_sig_flag {
  ZUMIME_SIG_WS = 1u << 0,  /* skip leading whitespace bytes */
  ZUMIME_SIG_TT = 1u << 1,  /* the last byte is a tag-terminating byte */
  ZUMIME_SIG_TAR = 1u << 2  /* the tar header checksum at 148 must verify */
};

/* Groups, in the order the algorithm consults them. EXTRA is zumime's own
 * rows, consulted only in the "none" context, after the standard's. */
enum zumime_sig_group {
  ZUMIME_GROUP_SCRIPTABLE = 0,
  ZUMIME_GROUP_NONSCRIPTABLE,
  ZUMIME_GROUP_IMAGE,
  ZUMIME_GROUP_AUDIO_VIDEO,
  ZUMIME_GROUP_FONT,
  ZUMIME_GROUP_ARCHIVE,
  ZUMIME_GROUP_EXTRA,
  ZUMIME_N_GROUPS
};

typedef struct {
  uint32_t offset;
  const char *pattern; /* bytes, already masked */
  const char *mask;    /* NULL: every byte significant */
  uint8_t len;
  int type;
  int parent; /* -1: none; else the row runs only after this type matched */
  unsigned flags;
  uint8_t group;
} zumime_sig;

extern const zumime_sig zumime_sigs[];
extern const int zumime_n_sigs;

/* 1 when the row matches buf, per the standard's pattern matching
 * algorithm with the row's offset and flags. */
int zumime_match_row(const zumime_sig *row, const unsigned char *buf,
                     size_t len);

/* --- The algorithm (zumime_sniff.c) --------------------------------------- */

enum zumime_context {
  ZUMIME_CTX_NONE = 0,
  ZUMIME_CTX_BROWSING,
  ZUMIME_CTX_IMAGE,
  ZUMIME_CTX_AUDIO_VIDEO,
  ZUMIME_CTX_FONT
};

/* Confidence levels of design D3, in ascending order. */
enum zumime_confidence {
  ZUMIME_CONF_NONE = 0,
  ZUMIME_CONF_EXTENSION,
  ZUMIME_CONF_PROBABLE,
  ZUMIME_CONF_DEFINITE
};

/* The longest charset label kept; the Encoding Standard's longest is 23. */
#define ZUMIME_LABEL_MAX 63

/* Result type ids that are not registry ids. */
#define ZUMIME_SUPPLIED (-2) /* the computed type is the supplied type */

enum zumime_charset {
  ZUMIME_CS_NONE = 0,  /* not text, or nothing answered */
  ZUMIME_CS_UTF8,
  ZUMIME_CS_UTF16BE,
  ZUMIME_CS_UTF16LE,
  ZUMIME_CS_WINDOWS_1252,
  ZUMIME_CS_ISO_8859_1,
  ZUMIME_CS_DECLARED   /* a declared label, in cs_label */
};

enum zumime_newline {
  ZUMIME_NL_NONE = 0,
  ZUMIME_NL_LF,
  ZUMIME_NL_CRLF,
  ZUMIME_NL_CR,
  ZUMIME_NL_MIXED
};

typedef struct {
  /* The supplied type's essence, lower-case and canonical, or NULL when it
   * is undefined. supplied_id is its registry id, or -1 when unknown. */
  const char *supplied;
  int supplied_id;
  int apache_bug; /* the check-for-apache-bug flag */
  int no_sniff;
  int context;    /* enum zumime_context */
  int truncated;  /* the buffer was cut by the read limit */
} zumime_input;

typedef struct {
  int type;       /* registry id or ZUMIME_SUPPLIED */
  int confidence; /* enum zumime_confidence */
  int charset;    /* enum zumime_charset */
  char cs_label[ZUMIME_LABEL_MAX + 1]; /* for ZUMIME_CS_DECLARED */
  int newline;    /* enum zumime_newline */
} zumime_result;

void zumime_sniff(const unsigned char *buf, size_t len, const zumime_input *in,
                  zumime_result *out);

/* Exposed for tests and the incremental sniffer. */
int zumime_match_mp4(const unsigned char *buf, size_t len);
int zumime_match_webm(const unsigned char *buf, size_t len);
int zumime_match_mp3(const unsigned char *buf, size_t len);

/* 1 when type descends from (or is) ancestor. */
int zumime_type_is(int type, int ancestor);

/* Registry id of a canonical type name, or -1. */
int zumime_type_lookup(const char *name);

/* --- Charset and newlines (zumime_text.c) -------------------------------- */

/* Fill out->charset (and cs_label) and may lower out->confidence to
 * probable for the C1 guess. is_xml/is_html select the declaration rules. */
void zumime_charset(const unsigned char *buf, size_t len, int truncated,
                    int is_xml, int is_html, zumime_result *out);

int zumime_newline_style(const unsigned char *buf, size_t len);

#endif
