/* Ogg (design section 6.2): the first packet's codec header decides Vorbis,
 * Opus, FLAC and Speex audio against Theora and OGM video. A skeleton
 * stream (fishead) comes first in some files, so a few pages are read. */

#include <string.h>

#include "zumime_sniff.h"

static int codec(const unsigned char *p, size_t n) {
  if (n >= 7 && memcmp(p, "\x01vorbis", 7) == 0) return ZUMIME_T_AUDIO_OGG;
  if (n >= 8 && memcmp(p, "OpusHead", 8) == 0) return ZUMIME_T_AUDIO_OPUS;
  if (n >= 5 && memcmp(p, "\x7f" "FLAC", 5) == 0) return ZUMIME_T_AUDIO_OGG;
  if (n >= 8 && memcmp(p, "Speex   ", 8) == 0) return ZUMIME_T_AUDIO_OGG;
  if (n >= 7 && memcmp(p, "\x80theora", 7) == 0) return ZUMIME_T_VIDEO_OGG;
  if (n >= 6 && memcmp(p, "\x01video", 6) == 0) return ZUMIME_T_VIDEO_OGG;
  return -1;
}

int zumime_read_ogg(const unsigned char *buf, size_t len) {
  size_t pos = 0;
  for (int page = 0; page < 4; page++) {
    if (pos + 27 > len || memcmp(buf + pos, "OggS", 4) != 0) return -1;
    size_t nseg = buf[pos + 26];
    size_t data = pos + 27 + nseg;
    if (data > len) return -1;
    size_t body = 0;
    for (size_t i = 0; i < nseg; i++) body += buf[pos + 27 + i];
    size_t avail = len - data;
    int t = codec(buf + data, avail < body ? avail : body);
    if (t >= 0) return t;
    pos = data + body;
  }
  return -1;
}
