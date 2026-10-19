/* The signature table (design section 4, layer 2): data rows of
 * {offset, pattern, mask, type, parent, flags, group}.
 *
 * The WHATWG MIME Sniffing Standard's tables come first, in its order, with
 * its masks and its leading-bytes-to-ignore rule, so a test written against
 * the standard passes unchanged: the two tables of "identifying a resource
 * with an unknown MIME type" (section 7.1), then the image (6.1), audio or
 * video (6.2), font (6.3) and archive (6.4) tables. Patterns are stored
 * already masked: a byte under mask 0xDF holds the upper-case letter.
 *
 * zumime's own rows (EXTRA) follow. The algorithm consults them only in the
 * "none" context, after the standard's tables and before the text-or-binary
 * rule, so they never override the standard and never yield a scriptable
 * type. Go's net/http sniffer adds the RAR 5, font and WebAssembly rows too.
 * Every byte is a hex escape: C's \x escapes are greedy. */

#include "zumime_sniff.h"

const zumime_sig zumime_sigs[] = {

  /* --- SCRIPTABLE --- */
  /* "<!DOCTYPE HTML" and a tag-terminating byte */
  {0, "\x3C\x21\x44\x4F\x43\x54\x59\x50\x45\x20\x48\x54\x4D\x4C\x20", "\xFF\xFF\xDF\xDF\xDF\xDF\xDF\xDF\xDF\xFF\xDF\xDF\xDF\xDF\xFF", 15, ZUMIME_T_TEXT_HTML, -1, ZUMIME_SIG_WS | ZUMIME_SIG_TT, ZUMIME_GROUP_SCRIPTABLE},
  /* "<HTML" and a tag-terminating byte */
  {0, "\x3C\x48\x54\x4D\x4C\x20", "\xFF\xDF\xDF\xDF\xDF\xFF", 6, ZUMIME_T_TEXT_HTML, -1, ZUMIME_SIG_WS | ZUMIME_SIG_TT, ZUMIME_GROUP_SCRIPTABLE},
  /* "<HEAD" and a tag-terminating byte */
  {0, "\x3C\x48\x45\x41\x44\x20", "\xFF\xDF\xDF\xDF\xDF\xFF", 6, ZUMIME_T_TEXT_HTML, -1, ZUMIME_SIG_WS | ZUMIME_SIG_TT, ZUMIME_GROUP_SCRIPTABLE},
  /* "<SCRIPT" and a tag-terminating byte */
  {0, "\x3C\x53\x43\x52\x49\x50\x54\x20", "\xFF\xDF\xDF\xDF\xDF\xDF\xDF\xFF", 8, ZUMIME_T_TEXT_HTML, -1, ZUMIME_SIG_WS | ZUMIME_SIG_TT, ZUMIME_GROUP_SCRIPTABLE},
  /* "<IFRAME" and a tag-terminating byte */
  {0, "\x3C\x49\x46\x52\x41\x4D\x45\x20", "\xFF\xDF\xDF\xDF\xDF\xDF\xDF\xFF", 8, ZUMIME_T_TEXT_HTML, -1, ZUMIME_SIG_WS | ZUMIME_SIG_TT, ZUMIME_GROUP_SCRIPTABLE},
  /* "<H1" and a tag-terminating byte */
  {0, "\x3C\x48\x31\x20", "\xFF\xDF\xFF\xFF", 4, ZUMIME_T_TEXT_HTML, -1, ZUMIME_SIG_WS | ZUMIME_SIG_TT, ZUMIME_GROUP_SCRIPTABLE},
  /* "<DIV" and a tag-terminating byte */
  {0, "\x3C\x44\x49\x56\x20", "\xFF\xDF\xDF\xDF\xFF", 5, ZUMIME_T_TEXT_HTML, -1, ZUMIME_SIG_WS | ZUMIME_SIG_TT, ZUMIME_GROUP_SCRIPTABLE},
  /* "<FONT" and a tag-terminating byte */
  {0, "\x3C\x46\x4F\x4E\x54\x20", "\xFF\xDF\xDF\xDF\xDF\xFF", 6, ZUMIME_T_TEXT_HTML, -1, ZUMIME_SIG_WS | ZUMIME_SIG_TT, ZUMIME_GROUP_SCRIPTABLE},
  /* "<TABLE" and a tag-terminating byte */
  {0, "\x3C\x54\x41\x42\x4C\x45\x20", "\xFF\xDF\xDF\xDF\xDF\xDF\xFF", 7, ZUMIME_T_TEXT_HTML, -1, ZUMIME_SIG_WS | ZUMIME_SIG_TT, ZUMIME_GROUP_SCRIPTABLE},
  /* "<A" and a tag-terminating byte */
  {0, "\x3C\x41\x20", "\xFF\xDF\xFF", 3, ZUMIME_T_TEXT_HTML, -1, ZUMIME_SIG_WS | ZUMIME_SIG_TT, ZUMIME_GROUP_SCRIPTABLE},
  /* "<STYLE" and a tag-terminating byte */
  {0, "\x3C\x53\x54\x59\x4C\x45\x20", "\xFF\xDF\xDF\xDF\xDF\xDF\xFF", 7, ZUMIME_T_TEXT_HTML, -1, ZUMIME_SIG_WS | ZUMIME_SIG_TT, ZUMIME_GROUP_SCRIPTABLE},
  /* "<TITLE" and a tag-terminating byte */
  {0, "\x3C\x54\x49\x54\x4C\x45\x20", "\xFF\xDF\xDF\xDF\xDF\xDF\xFF", 7, ZUMIME_T_TEXT_HTML, -1, ZUMIME_SIG_WS | ZUMIME_SIG_TT, ZUMIME_GROUP_SCRIPTABLE},
  /* "<B" and a tag-terminating byte */
  {0, "\x3C\x42\x20", "\xFF\xDF\xFF", 3, ZUMIME_T_TEXT_HTML, -1, ZUMIME_SIG_WS | ZUMIME_SIG_TT, ZUMIME_GROUP_SCRIPTABLE},
  /* "<BODY" and a tag-terminating byte */
  {0, "\x3C\x42\x4F\x44\x59\x20", "\xFF\xDF\xDF\xDF\xDF\xFF", 6, ZUMIME_T_TEXT_HTML, -1, ZUMIME_SIG_WS | ZUMIME_SIG_TT, ZUMIME_GROUP_SCRIPTABLE},
  /* "<BR" and a tag-terminating byte */
  {0, "\x3C\x42\x52\x20", "\xFF\xDF\xDF\xFF", 4, ZUMIME_T_TEXT_HTML, -1, ZUMIME_SIG_WS | ZUMIME_SIG_TT, ZUMIME_GROUP_SCRIPTABLE},
  /* "<P" and a tag-terminating byte */
  {0, "\x3C\x50\x20", "\xFF\xDF\xFF", 3, ZUMIME_T_TEXT_HTML, -1, ZUMIME_SIG_WS | ZUMIME_SIG_TT, ZUMIME_GROUP_SCRIPTABLE},
  /* "<!--" and a tag-terminating byte */
  {0, "\x3C\x21\x2D\x2D\x20", NULL, 5, ZUMIME_T_TEXT_HTML, -1, ZUMIME_SIG_WS | ZUMIME_SIG_TT, ZUMIME_GROUP_SCRIPTABLE},
  /* "<?xml" */
  {0, "\x3C\x3F\x78\x6D\x6C", NULL, 5, ZUMIME_T_APPLICATION_XML, -1, ZUMIME_SIG_WS, ZUMIME_GROUP_SCRIPTABLE},
  /* "%PDF-" */
  {0, "\x25\x50\x44\x46\x2D", NULL, 5, ZUMIME_T_APPLICATION_PDF, -1, 0, ZUMIME_GROUP_SCRIPTABLE},

  /* --- NONSCRIPTABLE --- */
  /* "%!PS-Adobe-" */
  {0, "\x25\x21\x50\x53\x2D\x41\x64\x6F\x62\x65\x2D", NULL, 11, ZUMIME_T_APPLICATION_POSTSCRIPT, -1, 0, ZUMIME_GROUP_NONSCRIPTABLE},
  /* UTF-16BE BOM */
  {0, "\xFE\xFF\x00\x00", "\xFF\xFF\x00\x00", 4, ZUMIME_T_TEXT_PLAIN, -1, 0, ZUMIME_GROUP_NONSCRIPTABLE},
  /* UTF-16LE BOM */
  {0, "\xFF\xFE\x00\x00", "\xFF\xFF\x00\x00", 4, ZUMIME_T_TEXT_PLAIN, -1, 0, ZUMIME_GROUP_NONSCRIPTABLE},
  /* UTF-8 BOM */
  {0, "\xEF\xBB\xBF\x00", "\xFF\xFF\xFF\x00", 4, ZUMIME_T_TEXT_PLAIN, -1, 0, ZUMIME_GROUP_NONSCRIPTABLE},

  /* --- IMAGE --- */
  /* Windows icon */
  {0, "\x00\x00\x01\x00", NULL, 4, ZUMIME_T_IMAGE_VND_MICROSOFT_ICON, -1, 0, ZUMIME_GROUP_IMAGE},
  /* Windows cursor */
  {0, "\x00\x00\x02\x00", NULL, 4, ZUMIME_T_IMAGE_VND_MICROSOFT_ICON, -1, 0, ZUMIME_GROUP_IMAGE},
  /* "BM" */
  {0, "\x42\x4D", NULL, 2, ZUMIME_T_IMAGE_BMP, -1, 0, ZUMIME_GROUP_IMAGE},
  /* "GIF87a" */
  {0, "\x47\x49\x46\x38\x37\x61", NULL, 6, ZUMIME_T_IMAGE_GIF, -1, 0, ZUMIME_GROUP_IMAGE},
  /* "GIF89a" */
  {0, "\x47\x49\x46\x38\x39\x61", NULL, 6, ZUMIME_T_IMAGE_GIF, -1, 0, ZUMIME_GROUP_IMAGE},
  /* "RIFF", 4 bytes, "WEBPVP" */
  {0, "\x52\x49\x46\x46\x00\x00\x00\x00\x57\x45\x42\x50\x56\x50", "\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF", 14, ZUMIME_T_IMAGE_WEBP, -1, 0, ZUMIME_GROUP_IMAGE},
  /* PNG signature */
  {0, "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A", NULL, 8, ZUMIME_T_IMAGE_PNG, -1, 0, ZUMIME_GROUP_IMAGE},
  /* JPEG SOI and a marker */
  {0, "\xFF\xD8\xFF", NULL, 3, ZUMIME_T_IMAGE_JPEG, -1, 0, ZUMIME_GROUP_IMAGE},

  /* --- AUDIO_VIDEO --- */
  /* "FORM", 4 bytes, "AIFF" */
  {0, "\x46\x4F\x52\x4D\x00\x00\x00\x00\x41\x49\x46\x46", "\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF", 12, ZUMIME_T_AUDIO_AIFF, -1, 0, ZUMIME_GROUP_AUDIO_VIDEO},
  /* "ID3" */
  {0, "\x49\x44\x33", NULL, 3, ZUMIME_T_AUDIO_MPEG, -1, 0, ZUMIME_GROUP_AUDIO_VIDEO},
  /* "OggS" and NUL */
  {0, "\x4F\x67\x67\x53\x00", NULL, 5, ZUMIME_T_APPLICATION_OGG, -1, 0, ZUMIME_GROUP_AUDIO_VIDEO},
  /* "MThd" and 6 */
  {0, "\x4D\x54\x68\x64\x00\x00\x00\x06", NULL, 8, ZUMIME_T_AUDIO_MIDI, -1, 0, ZUMIME_GROUP_AUDIO_VIDEO},
  /* "RIFF", 4 bytes, "AVI " */
  {0, "\x52\x49\x46\x46\x00\x00\x00\x00\x41\x56\x49\x20", "\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF", 12, ZUMIME_T_VIDEO_X_MSVIDEO, -1, 0, ZUMIME_GROUP_AUDIO_VIDEO},
  /* "RIFF", 4 bytes, "WAVE" */
  {0, "\x52\x49\x46\x46\x00\x00\x00\x00\x57\x41\x56\x45", "\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF", 12, ZUMIME_T_AUDIO_WAV, -1, 0, ZUMIME_GROUP_AUDIO_VIDEO},

  /* --- FONT --- */
  /* 34 bytes and "LP" */
  {0, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x4C\x50", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF", 36, ZUMIME_T_APPLICATION_VND_MS_FONTOBJECT, -1, 0, ZUMIME_GROUP_FONT},
  /* TrueType 1.0 */
  {0, "\x00\x01\x00\x00", NULL, 4, ZUMIME_T_FONT_TTF, -1, 0, ZUMIME_GROUP_FONT},
  /* "OTTO" */
  {0, "\x4F\x54\x54\x4F", NULL, 4, ZUMIME_T_FONT_OTF, -1, 0, ZUMIME_GROUP_FONT},
  /* "ttcf" */
  {0, "\x74\x74\x63\x66", NULL, 4, ZUMIME_T_FONT_COLLECTION, -1, 0, ZUMIME_GROUP_FONT},
  /* "wOFF" */
  {0, "\x77\x4F\x46\x46", NULL, 4, ZUMIME_T_FONT_WOFF, -1, 0, ZUMIME_GROUP_FONT},
  /* "wOF2" */
  {0, "\x77\x4F\x46\x32", NULL, 4, ZUMIME_T_FONT_WOFF2, -1, 0, ZUMIME_GROUP_FONT},

  /* --- ARCHIVE --- */
  /* gzip */
  {0, "\x1F\x8B\x08", NULL, 3, ZUMIME_T_APPLICATION_GZIP, -1, 0, ZUMIME_GROUP_ARCHIVE},
  /* "PK" ETX EOT */
  {0, "\x50\x4B\x03\x04", NULL, 4, ZUMIME_T_APPLICATION_ZIP, -1, 0, ZUMIME_GROUP_ARCHIVE},
  /* RAR 4.x */
  {0, "\x52\x61\x72\x21\x1A\x07\x00", NULL, 7, ZUMIME_T_APPLICATION_VND_RAR, -1, 0, ZUMIME_GROUP_ARCHIVE},

  /* --- EXTRA --- */
  /* RAR 5 */
  {0, "\x52\x61\x72\x21\x1A\x07\x01\x00", NULL, 8, ZUMIME_T_APPLICATION_VND_RAR, -1, 0, ZUMIME_GROUP_EXTRA},
  /* 7z */
  {0, "\x37\x7A\xBC\xAF\x27\x1C", NULL, 6, ZUMIME_T_APPLICATION_X_7Z_COMPRESSED, -1, 0, ZUMIME_GROUP_EXTRA},
  /* bzip2 */
  {0, "\x42\x5A\x68", NULL, 3, ZUMIME_T_APPLICATION_X_BZIP2, -1, 0, ZUMIME_GROUP_EXTRA},
  /* xz */
  {0, "\xFD\x37\x7A\x58\x5A\x00", NULL, 6, ZUMIME_T_APPLICATION_X_XZ, -1, 0, ZUMIME_GROUP_EXTRA},
  /* Zstandard frame */
  {0, "\x28\xB5\x2F\xFD", NULL, 4, ZUMIME_T_APPLICATION_ZSTD, -1, 0, ZUMIME_GROUP_EXTRA},
  /* TrueType 1.0 */
  {0, "\x00\x01\x00\x00", NULL, 4, ZUMIME_T_FONT_TTF, -1, 0, ZUMIME_GROUP_EXTRA},
  /* "OTTO" */
  {0, "\x4F\x54\x54\x4F", NULL, 4, ZUMIME_T_FONT_OTF, -1, 0, ZUMIME_GROUP_EXTRA},
  /* "ttcf" */
  {0, "\x74\x74\x63\x66", NULL, 4, ZUMIME_T_FONT_COLLECTION, -1, 0, ZUMIME_GROUP_EXTRA},
  /* "wOFF" */
  {0, "\x77\x4F\x46\x46", NULL, 4, ZUMIME_T_FONT_WOFF, -1, 0, ZUMIME_GROUP_EXTRA},
  /* "wOF2" */
  {0, "\x77\x4F\x46\x32", NULL, 4, ZUMIME_T_FONT_WOFF2, -1, 0, ZUMIME_GROUP_EXTRA},
  /* WebAssembly binary */
  {0, "\x00\x61\x73\x6D", NULL, 4, ZUMIME_T_APPLICATION_WASM, -1, 0, ZUMIME_GROUP_EXTRA},
  /* "ustar" at 257, checksum verified */
  {257, "\x75\x73\x74\x61\x72", NULL, 5, ZUMIME_T_APPLICATION_X_TAR, -1, ZUMIME_SIG_TAR, ZUMIME_GROUP_EXTRA},
  /* ISO 9660 "CD001" at 32769 */
  {32769, "\x43\x44\x30\x30\x31", NULL, 5, ZUMIME_T_APPLICATION_X_ISO9660_IMAGE, -1, 0, ZUMIME_GROUP_EXTRA},

  /* --- EXTRA (Stage 3): containers, executables, R and analytic data --- */
  /* OLE2 compound file */
  {0, "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", NULL, 8, ZUMIME_T_APPLICATION_X_OLE_STORAGE, -1, 0, ZUMIME_GROUP_EXTRA},
  /* EBML header */
  {0, "\x1A\x45\xDF\xA3", NULL, 4, ZUMIME_T_VIDEO_X_MATROSKA, -1, 0, ZUMIME_GROUP_EXTRA},
  /* ELF */
  {0, "\x7F\x45\x4C\x46", NULL, 4, ZUMIME_T_APPLICATION_X_ELF, -1, 0, ZUMIME_GROUP_EXTRA},
  /* Mach-O 32-bit BE */
  {0, "\xFE\xED\xFA\xCE", NULL, 4, ZUMIME_T_APPLICATION_X_MACH_BINARY, -1, 0, ZUMIME_GROUP_EXTRA},
  /* Mach-O 64-bit BE */
  {0, "\xFE\xED\xFA\xCF", NULL, 4, ZUMIME_T_APPLICATION_X_MACH_BINARY, -1, 0, ZUMIME_GROUP_EXTRA},
  /* Mach-O 32-bit LE */
  {0, "\xCE\xFA\xED\xFE", NULL, 4, ZUMIME_T_APPLICATION_X_MACH_BINARY, -1, 0, ZUMIME_GROUP_EXTRA},
  /* Mach-O 64-bit LE */
  {0, "\xCF\xFA\xED\xFE", NULL, 4, ZUMIME_T_APPLICATION_X_MACH_BINARY, -1, 0, ZUMIME_GROUP_EXTRA},
  /* Mach-O universal: fewer than 32 architectures */
  {0, "\xCA\xFE\xBA\xBE\x00\x00\x00\x00", "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xE0", 8, ZUMIME_T_APPLICATION_X_MACH_BINARY, -1, 0, ZUMIME_GROUP_EXTRA},
  /* Java class file */
  {0, "\xCA\xFE\xBA\xBE", NULL, 4, ZUMIME_T_APPLICATION_JAVA_VM, -1, 0, ZUMIME_GROUP_EXTRA},
  /* DOS/Windows executable */
  {0, "\x4D\x5A", NULL, 2, ZUMIME_T_APPLICATION_X_MSDOWNLOAD, -1, 0, ZUMIME_GROUP_EXTRA},
  /* TIFF, little-endian */
  {0, "\x49\x49\x2A\x00", NULL, 4, ZUMIME_T_IMAGE_TIFF, -1, 0, ZUMIME_GROUP_EXTRA},
  /* TIFF, big-endian */
  {0, "\x4D\x4D\x00\x2A", NULL, 4, ZUMIME_T_IMAGE_TIFF, -1, 0, ZUMIME_GROUP_EXTRA},
  /* Photoshop */
  {0, "\x38\x42\x50\x53", NULL, 4, ZUMIME_T_IMAGE_VND_ADOBE_PHOTOSHOP, -1, 0, ZUMIME_GROUP_EXTRA},
  /* FLAC */
  {0, "\x66\x4C\x61\x43", NULL, 4, ZUMIME_T_AUDIO_FLAC, -1, 0, ZUMIME_GROUP_EXTRA},
  /* AAC ADTS frame (layer 0) */
  {0, "\xFF\xF0", "\xFF\xF6", 2, ZUMIME_T_AUDIO_AAC, -1, 0, ZUMIME_GROUP_EXTRA},
  /* AMR */
  {0, "\x23\x21\x41\x4D\x52", NULL, 5, ZUMIME_T_AUDIO_AMR, -1, 0, ZUMIME_GROUP_EXTRA},
  /* SWF */
  {0, "\x46\x57\x53", NULL, 3, ZUMIME_T_APPLICATION_X_SHOCKWAVE_FLASH, -1, 0, ZUMIME_GROUP_EXTRA},
  /* SWF */
  {0, "\x43\x57\x53", NULL, 3, ZUMIME_T_APPLICATION_X_SHOCKWAVE_FLASH, -1, 0, ZUMIME_GROUP_EXTRA},
  /* SWF */
  {0, "\x5A\x57\x53", NULL, 3, ZUMIME_T_APPLICATION_X_SHOCKWAVE_FLASH, -1, 0, ZUMIME_GROUP_EXTRA},
  /* Flash video */
  {0, "\x46\x4C\x56\x01", NULL, 4, ZUMIME_T_VIDEO_X_FLV, -1, 0, ZUMIME_GROUP_EXTRA},
  /* Microsoft cabinet */
  {0, "\x4D\x53\x43\x46\x00\x00\x00\x00", NULL, 8, ZUMIME_T_APPLICATION_VND_MS_CAB_COMPRESSED, -1, 0, ZUMIME_GROUP_EXTRA},
  /* RPM package */
  {0, "\xED\xAB\xEE\xDB", NULL, 4, ZUMIME_T_APPLICATION_X_RPM, -1, 0, ZUMIME_GROUP_EXTRA},
  /* Debian package */
  {0, "\x21\x3C\x61\x72\x63\x68\x3E\x0A\x64\x65\x62\x69\x61\x6E\x2D\x62\x69\x6E\x61\x72\x79", NULL, 21, ZUMIME_T_APPLICATION_X_DEB, -1, 0, ZUMIME_GROUP_EXTRA},
  /* ar archive */
  {0, "\x21\x3C\x61\x72\x63\x68\x3E\x0A", NULL, 8, ZUMIME_T_APPLICATION_X_UNIX_ARCHIVE, -1, 0, ZUMIME_GROUP_EXTRA},
  /* LZ4 frame */
  {0, "\x04\x22\x4D\x18", NULL, 4, ZUMIME_T_APPLICATION_X_LZ4, -1, 0, ZUMIME_GROUP_EXTRA},
  /* lzip */
  {0, "\x4C\x5A\x49\x50", NULL, 4, ZUMIME_T_APPLICATION_LZIP, -1, 0, ZUMIME_GROUP_EXTRA},
  /* Unix compress (.Z) */
  {0, "\x1F\x9D", NULL, 2, ZUMIME_T_APPLICATION_X_COMPRESS, -1, 0, ZUMIME_GROUP_EXTRA},
  /* pcap */
  {0, "\xD4\xC3\xB2\xA1", NULL, 4, ZUMIME_T_APPLICATION_VND_TCPDUMP_PCAP, -1, 0, ZUMIME_GROUP_EXTRA},
  /* pcap */
  {0, "\xA1\xB2\xC3\xD4", NULL, 4, ZUMIME_T_APPLICATION_VND_TCPDUMP_PCAP, -1, 0, ZUMIME_GROUP_EXTRA},
  /* pcap */
  {0, "\x4D\x3C\xB2\xA1", NULL, 4, ZUMIME_T_APPLICATION_VND_TCPDUMP_PCAP, -1, 0, ZUMIME_GROUP_EXTRA},
  /* pcap */
  {0, "\xA1\xB2\x3C\x4D", NULL, 4, ZUMIME_T_APPLICATION_VND_TCPDUMP_PCAP, -1, 0, ZUMIME_GROUP_EXTRA},
  /* Avro object container */
  {0, "\x4F\x62\x6A\x01", NULL, 4, ZUMIME_T_APPLICATION_AVRO, -1, 0, ZUMIME_GROUP_EXTRA},
  /* DICOM "DICM" at 128 */
  {128, "\x44\x49\x43\x4D", NULL, 4, ZUMIME_T_APPLICATION_DICOM, -1, 0, ZUMIME_GROUP_EXTRA},
  /* JPEG XL codestream */
  {0, "\xFF\x0A", NULL, 2, ZUMIME_T_IMAGE_JXL, -1, 0, ZUMIME_GROUP_EXTRA},
  /* JPEG XL container */
  {0, "\x00\x00\x00\x0C\x4A\x58\x4C\x20\x0D\x0A\x87\x0A", NULL, 12, ZUMIME_T_IMAGE_JXL, -1, 0, ZUMIME_GROUP_EXTRA},
  /* Blender */
  {0, "\x42\x4C\x45\x4E\x44\x45\x52", NULL, 7, ZUMIME_T_APPLICATION_X_BLENDER, -1, 0, ZUMIME_GROUP_EXTRA},
  /* Apple icon */
  {0, "\x69\x63\x6E\x73", NULL, 4, ZUMIME_T_IMAGE_ICNS, -1, 0, ZUMIME_GROUP_EXTRA},
  /* WARC record */
  {0, "\x57\x41\x52\x43\x2F\x31\x2E", NULL, 7, ZUMIME_T_APPLICATION_WARC, -1, 0, ZUMIME_GROUP_EXTRA},
  /* RDS, XDR, format 3 */
  {0, "\x58\x0A\x00\x00\x00\x03", NULL, 6, ZUMIME_T_APPLICATION_X_RDS, -1, 0, ZUMIME_GROUP_EXTRA},
  /* RDS, XDR, format 2 */
  {0, "\x58\x0A\x00\x00\x00\x02", NULL, 6, ZUMIME_T_APPLICATION_X_RDS, -1, 0, ZUMIME_GROUP_EXTRA},
  /* RData */
  {0, "\x52\x44\x58\x33\x0A", NULL, 5, ZUMIME_T_APPLICATION_X_RDATA, -1, 0, ZUMIME_GROUP_EXTRA},
  /* RData */
  {0, "\x52\x44\x58\x32\x0A", NULL, 5, ZUMIME_T_APPLICATION_X_RDATA, -1, 0, ZUMIME_GROUP_EXTRA},
  /* RData */
  {0, "\x52\x44\x42\x33\x0A", NULL, 5, ZUMIME_T_APPLICATION_X_RDATA, -1, 0, ZUMIME_GROUP_EXTRA},
  /* RData */
  {0, "\x52\x44\x42\x32\x0A", NULL, 5, ZUMIME_T_APPLICATION_X_RDATA, -1, 0, ZUMIME_GROUP_EXTRA},
  /* SQLite 3 */
  {0, "\x53\x51\x4C\x69\x74\x65\x20\x66\x6F\x72\x6D\x61\x74\x20\x33\x00", NULL, 16, ZUMIME_T_APPLICATION_VND_SQLITE3, -1, 0, ZUMIME_GROUP_EXTRA},
  /* DuckDB "DUCK" at 8 */
  {8, "\x44\x55\x43\x4B", NULL, 4, ZUMIME_T_APPLICATION_X_DUCKDB, -1, 0, ZUMIME_GROUP_EXTRA},
  /* Parquet */
  {0, "\x50\x41\x52\x31", NULL, 4, ZUMIME_T_APPLICATION_VND_APACHE_PARQUET, -1, 0, ZUMIME_GROUP_EXTRA},
  /* Arrow IPC file */
  {0, "\x41\x52\x52\x4F\x57\x31\x00\x00", NULL, 8, ZUMIME_T_APPLICATION_VND_APACHE_ARROW_FILE, -1, 0, ZUMIME_GROUP_EXTRA},
  /* Feather v1 */
  {0, "\x46\x45\x41\x31", NULL, 4, ZUMIME_T_APPLICATION_VND_APACHE_ARROW_FILE, -1, 0, ZUMIME_GROUP_EXTRA},
  /* fst "PAAP" at 44 */
  {44, "\x50\x41\x41\x50", NULL, 4, ZUMIME_T_APPLICATION_X_FST, -1, 0, ZUMIME_GROUP_EXTRA},
  /* qs2 */
  {0, "\x0B\x0E\x0A", NULL, 3, ZUMIME_T_APPLICATION_X_QS2, -1, 0, ZUMIME_GROUP_EXTRA},
  /* HDF5 superblock at 0 */
  {0, "\x89\x48\x44\x46\x0D\x0A\x1A\x0A", NULL, 8, ZUMIME_T_APPLICATION_X_HDF5, -1, 0, ZUMIME_GROUP_EXTRA},
  /* HDF5 superblock at 512 */
  {512, "\x89\x48\x44\x46\x0D\x0A\x1A\x0A", NULL, 8, ZUMIME_T_APPLICATION_X_HDF5, -1, 0, ZUMIME_GROUP_EXTRA},
  /* HDF5 superblock at 1024 */
  {1024, "\x89\x48\x44\x46\x0D\x0A\x1A\x0A", NULL, 8, ZUMIME_T_APPLICATION_X_HDF5, -1, 0, ZUMIME_GROUP_EXTRA},
  /* HDF5 superblock at 2048 */
  {2048, "\x89\x48\x44\x46\x0D\x0A\x1A\x0A", NULL, 8, ZUMIME_T_APPLICATION_X_HDF5, -1, 0, ZUMIME_GROUP_EXTRA},
  /* NetCDF classic */
  {0, "\x43\x44\x46\x01", NULL, 4, ZUMIME_T_APPLICATION_X_NETCDF, -1, 0, ZUMIME_GROUP_EXTRA},
  /* NetCDF classic */
  {0, "\x43\x44\x46\x02", NULL, 4, ZUMIME_T_APPLICATION_X_NETCDF, -1, 0, ZUMIME_GROUP_EXTRA},
  /* NetCDF classic */
  {0, "\x43\x44\x46\x05", NULL, 4, ZUMIME_T_APPLICATION_X_NETCDF, -1, 0, ZUMIME_GROUP_EXTRA},
  /* Stata 13+ */
  {0, "\x3C\x73\x74\x61\x74\x61\x5F\x64\x74\x61\x3E", NULL, 11, ZUMIME_T_APPLICATION_X_STATA_DTA, -1, 0, ZUMIME_GROUP_EXTRA},
  /* Stata 110 */
  {0, "\x6E\x01\x01\x00", NULL, 4, ZUMIME_T_APPLICATION_X_STATA_DTA, -1, 0, ZUMIME_GROUP_EXTRA},
  /* Stata 110 */
  {0, "\x6E\x02\x01\x00", NULL, 4, ZUMIME_T_APPLICATION_X_STATA_DTA, -1, 0, ZUMIME_GROUP_EXTRA},
  /* Stata 111 */
  {0, "\x6F\x01\x01\x00", NULL, 4, ZUMIME_T_APPLICATION_X_STATA_DTA, -1, 0, ZUMIME_GROUP_EXTRA},
  /* Stata 111 */
  {0, "\x6F\x02\x01\x00", NULL, 4, ZUMIME_T_APPLICATION_X_STATA_DTA, -1, 0, ZUMIME_GROUP_EXTRA},
  /* Stata 112 */
  {0, "\x70\x01\x01\x00", NULL, 4, ZUMIME_T_APPLICATION_X_STATA_DTA, -1, 0, ZUMIME_GROUP_EXTRA},
  /* Stata 112 */
  {0, "\x70\x02\x01\x00", NULL, 4, ZUMIME_T_APPLICATION_X_STATA_DTA, -1, 0, ZUMIME_GROUP_EXTRA},
  /* Stata 113 */
  {0, "\x71\x01\x01\x00", NULL, 4, ZUMIME_T_APPLICATION_X_STATA_DTA, -1, 0, ZUMIME_GROUP_EXTRA},
  /* Stata 113 */
  {0, "\x71\x02\x01\x00", NULL, 4, ZUMIME_T_APPLICATION_X_STATA_DTA, -1, 0, ZUMIME_GROUP_EXTRA},
  /* Stata 114 */
  {0, "\x72\x01\x01\x00", NULL, 4, ZUMIME_T_APPLICATION_X_STATA_DTA, -1, 0, ZUMIME_GROUP_EXTRA},
  /* Stata 114 */
  {0, "\x72\x02\x01\x00", NULL, 4, ZUMIME_T_APPLICATION_X_STATA_DTA, -1, 0, ZUMIME_GROUP_EXTRA},
  /* Stata 115 */
  {0, "\x73\x01\x01\x00", NULL, 4, ZUMIME_T_APPLICATION_X_STATA_DTA, -1, 0, ZUMIME_GROUP_EXTRA},
  /* Stata 115 */
  {0, "\x73\x02\x01\x00", NULL, 4, ZUMIME_T_APPLICATION_X_STATA_DTA, -1, 0, ZUMIME_GROUP_EXTRA},
  /* SPSS system file */
  {0, "\x24\x46\x4C\x32", NULL, 4, ZUMIME_T_APPLICATION_X_SPSS_SAV, -1, 0, ZUMIME_GROUP_EXTRA},
  /* SPSS compressed system file */
  {0, "\x24\x46\x4C\x33", NULL, 4, ZUMIME_T_APPLICATION_X_SPSS_SAV, -1, 0, ZUMIME_GROUP_EXTRA},
  /* SAS7BDAT */
  {0, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xC2\xEA\x81\x60\xB3\x14\x11\xCF\xBD\x92\x08\x00\x09\xC7\x31\x8C\x18\x1F\x10\x11", NULL, 32, ZUMIME_T_APPLICATION_X_SAS_DATA, -1, 0, ZUMIME_GROUP_EXTRA},
  /* SAS transport */
  {0, "\x48\x45\x41\x44\x45\x52\x20\x52\x45\x43\x4F\x52\x44\x2A\x2A\x2A\x2A\x2A\x2A\x2A\x4C\x49\x42\x52\x41\x52\x59\x20\x48\x45\x41\x44\x45\x52\x20\x52\x45\x43\x4F\x52\x44\x21\x21\x21\x21\x21\x21\x21", NULL, 48, ZUMIME_T_APPLICATION_X_SAS_XPORT, -1, 0, ZUMIME_GROUP_EXTRA},

  /* --- EXTRA (Stage 3, oracle pass) --- */
  /* AIFF-C */
  {0, "\x46\x4F\x52\x4D\x00\x00\x00\x00\x41\x49\x46\x43", "\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF", 12, ZUMIME_T_AUDIO_AIFF, -1, 0, ZUMIME_GROUP_EXTRA},
  /* Embedded OpenType 1.0 */
  {0, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x4C\x50", "\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF", 36, ZUMIME_T_APPLICATION_VND_MS_FONTOBJECT, -1, 0, ZUMIME_GROUP_EXTRA},
  /* Embedded OpenType 2.1 */
  {0, "\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x4C\x50", "\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF", 36, ZUMIME_T_APPLICATION_VND_MS_FONTOBJECT, -1, 0, ZUMIME_GROUP_EXTRA},
  /* Embedded OpenType 2.2 */
  {0, "\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x4C\x50", "\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF", 36, ZUMIME_T_APPLICATION_VND_MS_FONTOBJECT, -1, 0, ZUMIME_GROUP_EXTRA},
  /* DOS EPS binary header */
  {0, "\xC5\xD0\xD3\xC6", NULL, 4, ZUMIME_T_APPLICATION_POSTSCRIPT, -1, 0, ZUMIME_GROUP_EXTRA},
  /* glTF binary */
  {0, "\x67\x6C\x54\x46", NULL, 4, ZUMIME_T_MODEL_GLTF_BINARY, -1, 0, ZUMIME_GROUP_EXTRA},
  /* Outlook PST */
  {0, "\x21\x42\x44\x4E", NULL, 4, ZUMIME_T_APPLICATION_VND_MS_OUTLOOK, -1, 0, ZUMIME_GROUP_EXTRA},
  /* tar without the ustar magic: the header checksum alone */
  {0, "", NULL, 0, ZUMIME_T_APPLICATION_X_TAR, -1, ZUMIME_SIG_TAR, ZUMIME_GROUP_EXTRA},
};

const int zumime_n_sigs = (int) (sizeof(zumime_sigs) / sizeof(zumime_sigs[0]));
