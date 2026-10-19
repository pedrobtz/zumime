/* Refinement (design section 6.1, last paragraph): in the "none" context,
 * the container and text readers look further at the bytes the standard
 * already typed, and are more specific than a browser.
 *
 * A reader's answer is accepted only when it descends from the type it
 * refines, so the type of a prefix of a file is always an ancestor of the
 * type of the whole (design section 9). The one exception is an RDS or
 * RData stream inside gzip: R's own files are typed as such whatever
 * wrapper saveRDS() and save() chose, and that is what a consumer asks. */

#include <string.h>

#include "zumime_sniff.h"

void zumime_refine(const unsigned char *buf, size_t len, const zumime_input *in,
                   zumime_result *out) {
  int cur = out->type;
  int t = -1;
  int probable = 0;
  int sideways = 0;

  if (cur == ZUMIME_T_APPLICATION_ZIP) {
    int enc = -1;
    t = zumime_read_zip(buf, len, !in->truncated, in->tail, in->tail_len,
                        in->tail_off, &enc);
    out->encrypted = enc;
  } else if (cur == ZUMIME_T_APPLICATION_X_OLE_STORAGE) {
    int enc = -1;
    t = zumime_read_ole2(buf, len, &enc);
    out->encrypted = enc;
  } else if (cur == ZUMIME_T_VIDEO_MP4 ||
             (cur == ZUMIME_T_APPLICATION_OCTET_STREAM && len >= 12)) {
    t = zumime_read_bmff(buf, len);
  } else if (cur == ZUMIME_T_IMAGE_PNG) {
    t = zumime_read_png(buf, len);
  } else if (cur == ZUMIME_T_IMAGE_JPEG) {
    if (len >= 4 && buf[3] == 0xF7) t = ZUMIME_T_IMAGE_JLS;
  } else if (cur == ZUMIME_T_VIDEO_X_MATROSKA) {
    t = zumime_read_ebml(buf, len);
  } else if (cur == ZUMIME_T_APPLICATION_OGG) {
    t = zumime_read_ogg(buf, len);
  } else if (cur == ZUMIME_T_APPLICATION_GZIP) {
    t = zumime_read_gzip_rdata(buf, len);
    sideways = 1;
  } else if (cur == ZUMIME_T_TEXT_PLAIN || cur == ZUMIME_T_APPLICATION_XML) {
    t = zumime_read_text(buf, len, cur, in->truncated, out->interpreter);
    probable = 1;
  }

  if (t < 0 || t == cur) return;
  if (!sideways && !zumime_type_is(t, cur)) return;
  out->type = t;
  if (probable && out->confidence > ZUMIME_CONF_PROBABLE)
    out->confidence = ZUMIME_CONF_PROBABLE;
  else if (!probable)
    out->confidence = ZUMIME_CONF_DEFINITE;
}
