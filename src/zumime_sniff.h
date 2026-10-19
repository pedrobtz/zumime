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

/* The longest interpreter name kept from a shebang. */
#define ZUMIME_INTERP_MAX 31

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
  /* Optional: the end of the file, read separately (design section 6.2,
   * the ZIP tail). tail_off is its offset in the file. NULL for none. */
  const unsigned char *tail;
  size_t tail_len;
  uint64_t tail_off;
  /* mime_check()'s first pass: the standard's answer and the extra rows
   * only, without readers, registered rules, charset or tail reads. */
  int base_only;
} zumime_input;

typedef struct {
  int type;       /* registry id or ZUMIME_SUPPLIED */
  int confidence; /* enum zumime_confidence */
  int charset;    /* enum zumime_charset */
  char cs_label[ZUMIME_LABEL_MAX + 1]; /* for ZUMIME_CS_DECLARED */
  int newline;    /* enum zumime_newline */
  int encrypted;  /* -1 unknown, 0 no, 1 yes */
  char interpreter[ZUMIME_INTERP_MAX + 1]; /* a shebang's program, or "" */
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

/* --- Registered types (registry.c) ---------------------------------------- */

#define ZUMIME_MAX_REGISTERED 256
#define ZUMIME_RULE_MAX 64

typedef struct {
  char name[128];
  int parent;
  int has_rule; /* a data rule; function rules live in R */
  uint32_t offset;
  uint8_t len;
  unsigned char bytes[ZUMIME_RULE_MAX]; /* stored masked */
  unsigned char mask[ZUMIME_RULE_MAX];
  int active;
} zumime_registered;

extern zumime_registered zumime_reg[ZUMIME_MAX_REGISTERED];

/* Returns the new id, or -1 when the table is full or the rule too long. */
int zumime_reg_add(const char *name, int parent, int has_rule, uint32_t offset,
                   const unsigned char *bytes, const unsigned char *mask,
                   size_t len);
void zumime_reg_remove(int id);
int zumime_type_parent(int id);     /* generated or registered; -1 for none */
const char *zumime_type_name(int id); /* generated or registered; NULL */
void zumime_apply_registered(const unsigned char *buf, size_t len,
                             zumime_result *out);

/* --- Container and text readers (design section 4, layer 3) -------------
 * Each takes the bytes in hand and returns a registry id that refines the
 * current type, or -1. zumime_refine() (zumime_refine.c) chooses the reader
 * and accepts only an answer that descends from the current type. */

void zumime_refine(const unsigned char *buf, size_t len, const zumime_input *in,
                   zumime_result *out);

int zumime_read_zip(const unsigned char *head, size_t hlen, int head_is_whole,
                    const unsigned char *tail, size_t tail_len,
                    uint64_t tail_off, int *encrypted);
int zumime_zip_cd_offset(const unsigned char *buf, size_t len, uint64_t buf_off,
                         uint64_t *cd_off);
int zumime_read_ole2(const unsigned char *buf, size_t len, int *encrypted);
int zumime_read_bmff(const unsigned char *buf, size_t len);
int zumime_read_png(const unsigned char *buf, size_t len);
int zumime_read_ebml(const unsigned char *buf, size_t len);
int zumime_read_ogg(const unsigned char *buf, size_t len);
int zumime_read_gzip_rdata(const unsigned char *buf, size_t len);
int zumime_read_text(const unsigned char *buf, size_t len, int current,
                     int truncated, char *interpreter);

/* Inflate a raw DEFLATE stream into dst, stopping when dst is full, the
 * stream ends, or the input runs out. Returns the bytes written. */
size_t zumime_inflate(const unsigned char *src, size_t slen, unsigned char *dst,
                      size_t dlen);

/* A pull-based byte source: fill buf with up to n bytes, return how many;
 * 0 at the end. */
typedef size_t (*zumime_reader)(void *ctx, unsigned char *buf, size_t n);

/* 1 when every gzip member read from `read` inflates to its end and its
 * trailer's size matches; 0 when cut or corrupt; -1 out of memory. */
int zumime_gzip_complete(zumime_reader read, void *ctx);

/* Little helpers shared by the readers. */
static inline uint16_t zumime_le16(const unsigned char *p) {
  return (uint16_t) (p[0] | (p[1] << 8));
}
static inline uint32_t zumime_le32(const unsigned char *p) {
  return (uint32_t) p[0] | ((uint32_t) p[1] << 8) | ((uint32_t) p[2] << 16) |
         ((uint32_t) p[3] << 24);
}

/* --- The incremental sniffer (zumime_stream.c) ---------------------------- */

/* 1 when the type of buf can no longer change as bytes are appended; at
 * most `limit` bytes will ever be read (0: no limit). */
int zumime_can_decide(const unsigned char *buf, size_t len, size_t limit,
                      const zumime_input *in, const zumime_result *r);

/* --- Charset and newlines (zumime_charset.c) ----------------------------- */

/* Fill out->charset (and cs_label) and may lower out->confidence to
 * probable for the C1 guess. is_xml/is_html select the declaration rules. */
void zumime_charset(const unsigned char *buf, size_t len, int truncated,
                    int is_xml, int is_html, zumime_result *out);

int zumime_newline_style(const unsigned char *buf, size_t len);

#endif
