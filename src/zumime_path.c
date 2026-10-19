/* The loop over paths (design section 6.7): open, read `limit` bytes, sniff,
 * probe, close, once per path, filling parallel result vectors that R turns
 * into the frame. Every 256 paths it checks for a user interrupt, with no
 * file open and nothing allocated outside R.
 *
 * Deep probes read past the head when a result asks for it: the last
 * 66 KiB of a ZIP for its central directory, the signature rows whose
 * offsets lie beyond the head (ISO 9660 at 32769, HDF5 superblocks), and,
 * with complete = TRUE, the end of the file for the completeness check. */

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wchar.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "zumime_r.h"
#include "zumime_sniff.h"

#define TAIL_LEN (22u + 65535u)
#define CD_MAX (8u * 1024u * 1024u)

/* --- Files ------------------------------------------------------------------ */

#ifdef _WIN32
typedef __int64 foff;
#define fseek64 _fseeki64
#define ftell64 _ftelli64
#else
typedef off_t foff;
#define fseek64 fseeko
#define ftell64 ftello
#endif

/* Open `path` (UTF-8 on Windows, native elsewhere) for binary reading.
 * Anything that is not a regular file is not opened: *special is set to its
 * inode type (a directory, a FIFO, a device, a socket), as libmagic reports
 * them, because opening a FIFO blocks until a writer comes and a device can
 * be read forever. Otherwise *special is -1. Returns NULL with errno set on
 * failure. */
static FILE *open_path(const char *path, int *special) {
  *special = -1;
#ifdef _WIN32
  int n = MultiByteToWideChar(CP_UTF8, 0, path, -1, NULL, 0);
  if (n <= 0) {
    errno = EINVAL;
    return NULL;
  }
  wchar_t *w = (wchar_t *) malloc((size_t) n * sizeof(wchar_t));
  if (w == NULL) {
    errno = ENOMEM;
    return NULL;
  }
  MultiByteToWideChar(CP_UTF8, 0, path, -1, w, n);
  struct _stat64 st;
  if (_wstat64(w, &st) == 0) {
    if (st.st_mode & _S_IFDIR)
      *special = ZUMIME_T_INODE_DIRECTORY;
    else if (st.st_mode & _S_IFCHR)
      *special = ZUMIME_T_INODE_CHARDEVICE;
    else if (st.st_mode & _S_IFIFO)
      *special = ZUMIME_T_INODE_FIFO;
    if (*special >= 0) {
      free(w);
      return NULL;
    }
  }
  FILE *f = _wfopen(w, L"rb");
  free(w);
  return f;
#else
  struct stat st;
  if (stat(path, &st) == 0 && !S_ISREG(st.st_mode)) {
    if (S_ISDIR(st.st_mode))
      *special = ZUMIME_T_INODE_DIRECTORY;
    else if (S_ISFIFO(st.st_mode))
      *special = ZUMIME_T_INODE_FIFO;
    else if (S_ISCHR(st.st_mode))
      *special = ZUMIME_T_INODE_CHARDEVICE;
    else if (S_ISBLK(st.st_mode))
      *special = ZUMIME_T_INODE_BLOCKDEVICE;
    else if (S_ISSOCK(st.st_mode))
      *special = ZUMIME_T_INODE_SOCKET;
    else
      *special = ZUMIME_T_APPLICATION_OCTET_STREAM;
    return NULL;
  }
  return fopen(path, "rb");
#endif
}

/* The size of a regular file at `path` by stat, or -1. Asked before the
 * file is opened, so the head buffer can grow while nothing is open. */
static int64_t path_size(const char *path) {
#ifdef _WIN32
  int n = MultiByteToWideChar(CP_UTF8, 0, path, -1, NULL, 0);
  if (n <= 0) return -1;
  wchar_t *w = (wchar_t *) malloc((size_t) n * sizeof(wchar_t));
  if (w == NULL) return -1;
  MultiByteToWideChar(CP_UTF8, 0, path, -1, w, n);
  struct _stat64 st;
  int ok = _wstat64(w, &st) == 0;
  free(w);
  return ok ? (int64_t) st.st_size : -1;
#else
  struct stat st;
  return stat(path, &st) == 0 && S_ISREG(st.st_mode) ? (int64_t) st.st_size
                                                       : -1;
#endif
}

static int64_t file_size(FILE *f) {
  if (fseek64(f, 0, SEEK_END) != 0) return -1;
  foff n = ftell64(f);
  if (fseek64(f, 0, SEEK_SET) != 0) return -1;
  return (int64_t) n;
}

/* Read up to n bytes at offset into buf; returns the count read. */
static size_t read_at(FILE *f, int64_t offset, unsigned char *buf, size_t n) {
  if (fseek64(f, (foff) offset, SEEK_SET) != 0) return 0;
  return fread(buf, 1, n, f);
}

/* A file read by the streaming inflater, which can run for minutes on a
 * large file. Every few MiB it lets R check for an interrupt inside
 * R_ToplevelExec(), so no longjmp passes the open file or the inflater's
 * buffers; on an interrupt it reports the end of the file, the inflater
 * returns, and the caller raises the interrupt after cleaning up. */
typedef struct {
  FILE *f;
  size_t since_check;
  int interrupted;
} interruptible_file;

#define INTERRUPT_EVERY (4u * 1024u * 1024u)

static void check_interrupt(void *data) {
  (void) data;
  R_CheckUserInterrupt();
}

static size_t file_reader(void *ctx, unsigned char *buf, size_t n) {
  interruptible_file *r = (interruptible_file *) ctx;
  if (r->interrupted) return 0;
  r->since_check += n;
  if (r->since_check >= INTERRUPT_EVERY) {
    r->since_check = 0;
    if (!R_ToplevelExec(check_interrupt, NULL)) {
      r->interrupted = 1;
      return 0;
    }
  }
  return fread(buf, 1, n, r->f);
}

static int find(const unsigned char *b, size_t len, const char *lit) {
  size_t n = strlen(lit);
  for (size_t i = 0; i + n <= len; i++)
    if (memcmp(b + i, lit, n) == 0) return 1;
  return 0;
}

/* The offset of the last occurrence of lit in b, or len when it is absent. */
static size_t rfind(const unsigned char *b, size_t len, const char *lit) {
  size_t n = strlen(lit);
  for (size_t i = len >= n ? len - n + 1 : 0; i-- > 0;)
    if (memcmp(b + i, lit, n) == 0) return i;
  return len;
}

/* Does the PDF's trailer dictionary hold /Encrypt? A classic file's
 * dictionary follows the last "trailer" keyword; a PDF 1.5 cross-reference
 * stream's dictionary runs from its "obj" keyword to its "stream" keyword.
 * Searching only there keeps a literal /Encrypt in page content from
 * counting. When neither is in the tail, the whole tail is searched. */
static int pdf_encrypted(const unsigned char *tail, size_t got) {
  size_t at = rfind(tail, got, "trailer");
  if (at < got) return find(tail + at, got - at, "/Encrypt");
  size_t x = rfind(tail, got, "/XRef");
  if (x < got) {
    size_t from = rfind(tail, x, "obj");
    if (from == x) from = 0;
    size_t to = x + rfind(tail + x, got - x, "stream");
    return find(tail + from, to - from, "/Encrypt");
  }
  return find(tail, got, "/Encrypt");
}

/* --- One path ---------------------------------------------------------------- */

typedef struct {
  zumime_result r;
  int complete; /* -1 NA, 0, 1 */
  int is_dir;
  int failed;
  int interrupted; /* the user interrupted the completeness read */
  char error[128];
} path_result;

/* Signature rows beyond the head: read each one's bytes at its offset. */
static void offset_rows(FILE *f, int64_t size, size_t head_len,
                        zumime_result *r) {
  if (r->type != ZUMIME_T_APPLICATION_OCTET_STREAM) return;
  unsigned char probe[256];
  for (int i = 0; i < zumime_n_sigs; i++) {
    const zumime_sig *row = &zumime_sigs[i];
    if (row->group != ZUMIME_GROUP_EXTRA || row->offset == 0 || row->len == 0)
      continue;
    uint64_t end = (uint64_t) row->offset + row->len;
    if (end <= head_len || (int64_t) end > size)
      continue;
    if (read_at(f, row->offset, probe, row->len) != row->len) continue;
    int ok = 1;
    for (size_t k = 0; k < row->len && ok; k++) {
      unsigned char m = row->mask ? (unsigned char) row->mask[k] : 0xFF;
      ok = (probe[k] & m) == (unsigned char) row->pattern[k];
    }
    if (ok) {
      r->type = row->type;
      r->confidence = ZUMIME_CONF_DEFINITE;
      return;
    }
  }
}

/* The OLE2 directory sits near the end of an Office file, past the head:
 * read the header, FAT and directory sectors by seeking. */
typedef struct {
  FILE *f;
  int64_t size;
} ole_file;

static const unsigned char *file_get(void *ctx, uint64_t off, size_t n,
                                     unsigned char *scratch) {
  const ole_file *of = (const ole_file *) ctx;
  if ((int64_t) off > of->size || (uint64_t) of->size - off < n) return NULL;
  return read_at(of->f, (int64_t) off, scratch, n) == n ? scratch : NULL;
}

/* complete = TRUE: does the file end as its format says it must? */
static int completeness(FILE *f, int64_t size, const unsigned char *head,
                        size_t head_len, zumime_result *r, int *interrupted) {
  int t = r->type;
  unsigned char tail[4096];
  if (zumime_type_is(t, ZUMIME_T_APPLICATION_ZIP)) {
    size_t n = size < (int64_t) TAIL_LEN ? (size_t) size : TAIL_LEN;
    unsigned char *buf = (unsigned char *) malloc(n ? n : 1);
    if (buf == NULL) return -1;
    size_t got = read_at(f, size - (int64_t) n, buf, n);
    int ok = 0;
    for (size_t i = got >= 22 ? got - 22 + 1 : 0; i-- > 0;)
      if (memcmp(buf + i, "PK\x05\x06", 4) == 0) {
        ok = 1;
        break;
      }
    free(buf);
    return ok;
  }
  if (t == ZUMIME_T_APPLICATION_PDF) {
    size_t n = size < 4096 ? (size_t) size : 4096;
    size_t got = read_at(f, size - (int64_t) n, tail, n);
    size_t last = got < 1024 ? got : 1024;
    r->encrypted = pdf_encrypted(tail, got);
    return find(tail + got - last, last, "%%EOF");
  }
  if (t == ZUMIME_T_APPLICATION_VND_APACHE_PARQUET) {
    if (size < 8) return 0;
    return read_at(f, size - 4, tail, 4) == 4 && memcmp(tail, "PAR1", 4) == 0;
  }
  if (head_len >= 2 && head[0] == 0x1F && head[1] == 0x8B &&
      (t == ZUMIME_T_APPLICATION_GZIP || t == ZUMIME_T_APPLICATION_X_RDS ||
       t == ZUMIME_T_APPLICATION_X_RDATA)) {
    if (fseek64(f, 0, SEEK_SET) != 0) return -1;
    interruptible_file rf = {f, 0, 0};
    int ok = zumime_gzip_complete(file_reader, &rf);
    *interrupted = rf.interrupted;
    return rf.interrupted ? -1 : ok;
  }
  return -1;
}

/* Sniff one path into *out. head is a buffer of head_cap bytes, which
 * reserve_head() sized for this file (limit > 0); with limit 0 the whole
 * file is read into a buffer of its own. */
typedef int (*base_gate)(void *ctx, int base);

static void sniff_path(const char *path, size_t limit, int want_complete,
                       const zumime_input *proto, unsigned char *head,
                       size_t head_cap, path_result *out, base_gate gate,
                       void *gate_ctx, int *gated_out) {
  memset(out, 0, sizeof(*out));
  out->complete = -1;
  out->r.encrypted = -1;
  int special = -1;
  errno = 0;
  FILE *f = open_path(path, &special);
  if (special >= 0) {
    out->is_dir = 1;
    out->r.type = special;
    /* An inode of no known kind is the floor, which carries no evidence. */
    out->r.confidence = special == ZUMIME_T_APPLICATION_OCTET_STREAM
                            ? ZUMIME_CONF_NONE
                            : ZUMIME_CONF_DEFINITE;
    return;
  }
  if (f == NULL) {
    out->failed = 1;
    snprintf(out->error, sizeof(out->error), "%s",
             errno ? strerror(errno) : "cannot open");
    return;
  }
  /* Not reachable from the tests: seeking a regular file that opened fails
   * only on an I/O error or a file over the platform's off_t. */
  int64_t size = file_size(f);
  if (size < 0) {
    out->failed = 1;
    snprintf(out->error, sizeof(out->error), "cannot seek");
    fclose(f);
    return;
  }

  unsigned char *own = NULL;
  /* The buffer holds the head stat saw; a file that grew since is read to
   * that size and sniffed as truncated. */
  size_t cap = limit < head_cap ? limit : head_cap;
  if (limit == 0) {
    cap = (size_t) size;
    /* Allocation failure is not provoked by the tests; the alloc-failure
     * workflow of r-actions is where it would be exercised. */
    own = (unsigned char *) malloc(cap ? cap : 1);
    if (own == NULL) {
      out->failed = 1;
      snprintf(out->error, sizeof(out->error), "cannot allocate %.0f bytes",
               (double) size);
      fclose(f);
      return;
    }
    head = own;
  }
  size_t head_len = fread(head, 1, cap, f);
  /* Not reachable from the tests: a read error on an open regular file
   * needs failing hardware or a vanished network share. */
  if (ferror(f)) {
    out->failed = 1;
    snprintf(out->error, sizeof(out->error), "read error");
    free(own);
    fclose(f);
    return;
  }

  zumime_input in = *proto;
  in.truncated = (int64_t) head_len < size;
  if (gate != NULL) {
    zumime_input b = in;
    b.base_only = 1;
    zumime_sniff(head, head_len, &b, &out->r);
    if (!gate(gate_ctx, out->r.type)) {
      *gated_out = 1;
      free(own);
      fclose(f);
      return;
    }
  }
  unsigned char *tail = NULL;
  if (in.truncated && proto->context == ZUMIME_CTX_NONE && !proto->base_only &&
      head_len >= 4 && memcmp(head, "PK\x03\x04", 4) == 0) {
    size_t n = size < (int64_t) TAIL_LEN ? (size_t) size : TAIL_LEN;
    tail = (unsigned char *) malloc(n);
    if (tail != NULL) {
      in.tail = tail;
      in.tail_len = read_at(f, size - (int64_t) n, tail, n);
      in.tail_off = (uint64_t) (size - (int64_t) n);
      /* A central directory that starts before the tail (an archive of
       * many entries) is read from its start, up to CD_MAX bytes. */
      uint64_t cd = 0;
      if (zumime_zip_cd_offset(tail, in.tail_len, in.tail_off, &cd) &&
          cd < in.tail_off && cd >= head_len && (uint64_t) size - cd <= CD_MAX) {
        size_t m = (size_t) ((uint64_t) size - cd);
        unsigned char *wide = (unsigned char *) malloc(m);
        if (wide != NULL) {
          free(tail);
          tail = wide;
          in.tail = tail;
          in.tail_len = read_at(f, (int64_t) cd, tail, m);
          in.tail_off = cd;
        }
      }
    }
  }
  zumime_sniff(head, head_len, &in, &out->r);
  if (proto->context == ZUMIME_CTX_NONE && out->r.type != ZUMIME_SUPPLIED &&
      in.truncated && !proto->base_only)
    offset_rows(f, size, head_len, &out->r);
  if (proto->context == ZUMIME_CTX_NONE && in.truncated && !proto->base_only &&
      out->r.type == ZUMIME_T_APPLICATION_X_OLE_STORAGE) {
    ole_file of = {f, size};
    int enc = -1;
    int t = zumime_read_ole2_at(file_get, &of, &enc);
    if (t >= 0) out->r.type = t;
    out->r.encrypted = enc;
  }
  if (want_complete && out->r.type != ZUMIME_SUPPLIED)
    out->complete =
        completeness(f, size, head, head_len, &out->r, &out->interrupted);

  free(tail);
  free(own);
  fclose(f);
}

/* --- The loop ---------------------------------------------------------------- */

/* The head buffer, sized by need: the largest head read so far, never more
 * than the limit, so a large limit costs nothing for small files. It grows
 * by doubling with R_alloc() between files, while nothing is open. */
typedef struct {
  unsigned char *p;
  size_t cap;
} head_buf;

static void reserve_head(head_buf *hb, const char *path, size_t limit) {
  if (limit == 0) return;
  int64_t size = path_size(path);
  size_t need = size < 0 || (uint64_t) size > limit ? limit : (size_t) size;
  if (need == 0) need = 1;
  if (need <= hb->cap) return;
  size_t cap = hb->cap ? hb->cap : 4096;
  while (cap < need) cap = cap > limit / 2 ? limit : cap * 2;
  if (cap > limit) cap = limit;
  hb->p = (unsigned char *) R_alloc(cap, 1);
  hb->cap = cap;
}


/* paths: character (UTF-8, expanded); limit: double; complete: logical;
 * supplied, apache_bug, no_sniff, context as in zumime_sniff_raw().
 * Returns list(type, confidence, charset, encrypted, complete, newline,
 * interpreter, error); type is NA for a failed path and for a supplied
 * type returned as is (error tells the two apart). */
SEXP zumime_sniff_paths(SEXP paths, SEXP limit, SEXP complete, SEXP supplied,
                        SEXP apache_bug, SEXP no_sniff, SEXP context) {
  R_xlen_t n = XLENGTH(paths);
  size_t lim = (size_t) REAL(limit)[0];
  int want_complete = LOGICAL(complete)[0];

  zumime_input proto;
  memset(&proto, 0, sizeof(proto));
  proto.supplied = Rf_isNull(supplied) ? NULL : CHAR(STRING_ELT(supplied, 0));
  proto.supplied_id = proto.supplied ? zumime_type_lookup(proto.supplied) : -1;
  proto.apache_bug = LOGICAL(apache_bug)[0];
  proto.no_sniff = LOGICAL(no_sniff)[0];
  proto.context = INTEGER(context)[0];

  SEXP type = PROTECT(Rf_allocVector(STRSXP, n));
  SEXP conf = PROTECT(Rf_allocVector(STRSXP, n));
  SEXP charset = PROTECT(Rf_allocVector(STRSXP, n));
  SEXP encrypted = PROTECT(Rf_allocVector(LGLSXP, n));
  SEXP complete_v = PROTECT(Rf_allocVector(LGLSXP, n));
  SEXP newline = PROTECT(Rf_allocVector(STRSXP, n));
  SEXP interp = PROTECT(Rf_allocVector(STRSXP, n));
  SEXP error = PROTECT(Rf_allocVector(STRSXP, n));
  head_buf hb = {NULL, 0};
  int interrupted = 0;

  for (R_xlen_t i = 0; i < n; i++) {
    /* testthat cannot send an interrupt; the check runs between files with
     * nothing open, which is what makes it safe. */
    if (i > 0 && i % 256 == 0) R_CheckUserInterrupt();
    SEXP s = STRING_ELT(paths, i);
    path_result pr;
    if (s == NA_STRING) {
      memset(&pr, 0, sizeof(pr));
      pr.failed = 1;
      pr.complete = -1;
      pr.r.encrypted = -1;
      snprintf(pr.error, sizeof(pr.error), "missing path");
    } else {
#ifdef _WIN32
      const char *p = Rf_translateCharUTF8(s); /* opened as UTF-16 */
#else
      const char *p = Rf_translateChar(s); /* the native encoding */
#endif
      reserve_head(&hb, p, lim);
      sniff_path(p, lim, want_complete, &proto, hb.p, hb.cap, &pr, NULL, NULL,
                 NULL);
      if (pr.interrupted) {
        interrupted = 1;
        break;
      }
    }
    const zumime_result *r = &pr.r;
    if (pr.failed) {
      SET_STRING_ELT(type, i, NA_STRING);
      SET_STRING_ELT(conf, i, Rf_mkChar("none"));
      SET_STRING_ELT(charset, i, NA_STRING);
      LOGICAL(encrypted)[i] = NA_LOGICAL;
      LOGICAL(complete_v)[i] = NA_LOGICAL;
      SET_STRING_ELT(newline, i, NA_STRING);
      SET_STRING_ELT(interp, i, NA_STRING);
      SET_STRING_ELT(error, i, Rf_mkChar(pr.error));
      continue;
    }
    SET_STRING_ELT(type, i, zumime_type_charsxp(r->type));
    SET_STRING_ELT(conf, i, zumime_confidence_charsxp(r->confidence));
    SET_STRING_ELT(charset, i, zumime_charset_charsxp(r));
    LOGICAL(encrypted)[i] = r->encrypted < 0 ? NA_LOGICAL : r->encrypted;
    LOGICAL(complete_v)[i] = pr.complete < 0 ? NA_LOGICAL : pr.complete;
    SET_STRING_ELT(newline, i, zumime_newline_charsxp(r->newline));
    SET_STRING_ELT(interp, i, r->interpreter[0] ? Rf_mkChar(r->interpreter)
                                                : NA_STRING);
    SET_STRING_ELT(error, i, NA_STRING);
  }

  SEXP out = PROTECT(Rf_allocVector(VECSXP, 8));
  SET_VECTOR_ELT(out, 0, type);
  SET_VECTOR_ELT(out, 1, conf);
  SET_VECTOR_ELT(out, 2, charset);
  SET_VECTOR_ELT(out, 3, encrypted);
  SET_VECTOR_ELT(out, 4, complete_v);
  SET_VECTOR_ELT(out, 5, newline);
  SET_VECTOR_ELT(out, 6, interp);
  SET_VECTOR_ELT(out, 7, error);
  /* The file is closed; R raises the interrupt R_ToplevelExec() caught. */
  if (interrupted) {
    SEXP flag = PROTECT(Rf_ScalarLogical(1));
    Rf_setAttrib(out, Rf_install("interrupted"), flag);
    UNPROTECT(1);
  }
  UNPROTECT(9);
  return out;
}

/* --- mime_check() (design D15) ---------------------------------------------
 * For each input, the type the standard and the extra rows give before any
 * reader runs. A reader only ever refines that type into a descendant (or
 * gzip into R's formats), so an input whose first answer is related to no
 * allowed type cannot end as one: it is FALSE without the readers, the tail
 * reads or the frame. For the others the full answer is computed in the
 * same pass and tested against the allowed types.
 *
 * `related` holds, per allowed type, the sorted ids of the types related to
 * it; `within`, the sorted ids of the types that are it or descend from it.
 * One probe is counted per allowed type tested, in a static counter. */

static double probes = 0;

SEXP zumime_probe_count(void) { return Rf_ScalarReal(probes); }

static int in_sorted(SEXP ids, int x) {
  const int *p = INTEGER(ids);
  R_xlen_t lo = 0, hi = XLENGTH(ids) - 1;
  while (lo <= hi) {
    R_xlen_t mid = lo + (hi - lo) / 2;
    if (p[mid] == x) return 1;
    if (p[mid] < x)
      lo = mid + 1;
    else
      hi = mid - 1;
  }
  return 0;
}

static int related_to_any(void *ctx, int base) {
  SEXP related = (SEXP) ctx;
  R_xlen_t na = XLENGTH(related);
  for (R_xlen_t a = 0; a < na; a++) {
    probes++;
    if (in_sorted(VECTOR_ELT(related, a), base)) return 1;
  }
  return 0;
}

static int allowed(SEXP within, int type, int confidence, int min_conf) {
  if (confidence < min_conf) return 0;
  for (R_xlen_t a = 0; a < XLENGTH(within); a++)
    if (in_sorted(VECTOR_ELT(within, a), type)) return 1;
  return 0;
}

/* x: character paths or one raw vector. Returns a logical per input; NA
 * for an unreadable path (R applies the confidence floor). */
SEXP zumime_check(SEXP x, SEXP limit, SEXP related, SEXP within,
                  SEXP min_confidence) {
  size_t lim = (size_t) REAL(limit)[0];
  int min_conf = INTEGER(min_confidence)[0];
  zumime_input proto;
  memset(&proto, 0, sizeof(proto));
  proto.context = ZUMIME_CTX_NONE;

  if (TYPEOF(x) == RAWSXP) {
    size_t len = (size_t) XLENGTH(x);
    zumime_input in = proto;
    if (lim > 0 && len > lim) {
      len = lim;
      in.truncated = 1;
    }
    zumime_input b = in;
    b.base_only = 1;
    zumime_result r;
    zumime_sniff(RAW(x), len, &b, &r);
    if (!related_to_any(related, r.type)) return Rf_ScalarLogical(0);
    zumime_sniff(RAW(x), len, &in, &r);
    return Rf_ScalarLogical(allowed(within, r.type, r.confidence, min_conf));
  }

  R_xlen_t n = XLENGTH(x);
  SEXP out = PROTECT(Rf_allocVector(LGLSXP, n));
  head_buf hb = {NULL, 0};
  for (R_xlen_t i = 0; i < n; i++) {
    if (i > 0 && i % 256 == 0) R_CheckUserInterrupt();
    SEXP s = STRING_ELT(x, i);
    if (s == NA_STRING) {
      LOGICAL(out)[i] = NA_LOGICAL;
      continue;
    }
#ifdef _WIN32
    const char *p = Rf_translateCharUTF8(s);
#else
    const char *p = Rf_translateChar(s);
#endif
    path_result pr;
    int gated = 0;
    reserve_head(&hb, p, lim);
    sniff_path(p, lim, 0, &proto, hb.p, hb.cap, &pr, related_to_any,
               (void *) related, &gated);
    if (pr.failed)
      LOGICAL(out)[i] = NA_LOGICAL;
    else if (gated)
      LOGICAL(out)[i] = 0;
    else
      LOGICAL(out)[i] = allowed(within, pr.r.type, pr.r.confidence, min_conf);
  }
  UNPROTECT(1);
  return out;
}
