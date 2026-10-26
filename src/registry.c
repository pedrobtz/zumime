/* The one translation unit that defines the generated type tables. */
#define ZUMIME_TYPES_IMPLEMENTATION
#include "zumime_types.h"

/* Types registered for the session (design section 6.9). They take ids
 * after the generated ones, ZUMIME_N_TYPES + slot, in a fixed table: no
 * allocation, and a freed slot is reused. */

#include <string.h>

#include "zumime_sniff.h"

zumime_registered zumime_reg[ZUMIME_MAX_REGISTERED];

int zumime_reg_add(const char *name, int parent, int has_rule, uint32_t offset,
                   const unsigned char *bytes, const unsigned char *mask,
                   size_t len) {
  /* Not reachable from the tests: mime_register() refuses a name over 127
   * bytes and a rule over 64 bytes before it calls here. */
  if (strlen(name) >= sizeof(zumime_reg[0].name) || len > ZUMIME_RULE_MAX)
    return -1;
  for (int k = 0; k < ZUMIME_MAX_REGISTERED; k++) {
    zumime_registered *r = &zumime_reg[k];
    if (r->active) continue;
    memset(r, 0, sizeof(*r));
    memcpy(r->name, name, strlen(name) + 1); /* length checked above */
    r->parent = parent;
    r->has_rule = has_rule;
    r->offset = offset;
    r->len = (uint8_t) len;
    if (len) {
      memcpy(r->bytes, bytes, len);
      if (mask)
        memcpy(r->mask, mask, len);
      else
        memset(r->mask, 0xFF, len);
      for (size_t i = 0; i < len; i++) r->bytes[i] &= r->mask[i];
    }
    r->active = 1;
    return ZUMIME_N_TYPES + k;
  }
  return -1;
}

void zumime_reg_remove(int id) {
  int k = id - ZUMIME_N_TYPES;
  if (k >= 0 && k < ZUMIME_MAX_REGISTERED) memset(&zumime_reg[k], 0, sizeof(zumime_reg[k]));
}

int zumime_type_parent(int id) {
  if (id >= 0 && id < ZUMIME_N_TYPES) return zumime_type_parents[id];
  int k = id - ZUMIME_N_TYPES;
  if (k >= 0 && k < ZUMIME_MAX_REGISTERED && zumime_reg[k].active)
    return zumime_reg[k].parent;
  /* Not reachable from the tests: every id comes from the generated table
   * or a lookup of an active slot, and mime_unregister() refuses a type
   * that is the parent of another registered type. */
  return -1;
}

const char *zumime_type_name(int id) {
  if (id >= 0 && id < ZUMIME_N_TYPES) return zumime_type_names[id];
  int k = id - ZUMIME_N_TYPES;
  if (k >= 0 && k < ZUMIME_MAX_REGISTERED && zumime_reg[k].active)
    return zumime_reg[k].name;
  return NULL;
}

/* Data rules whose parent is the current type, repeated so a rule can sit
 * under a registered type. */
void zumime_apply_registered(const unsigned char *buf, size_t len,
                             zumime_result *out) {
  for (int depth = 0; depth < 8; depth++) {
    int changed = 0;
    for (int k = 0; k < ZUMIME_MAX_REGISTERED && !changed; k++) {
      const zumime_registered *r = &zumime_reg[k];
      if (!r->active || !r->has_rule || r->parent != out->type) continue;
      if (len < r->offset || len - r->offset < r->len) continue;
      int ok = 1;
      for (size_t i = 0; i < r->len && ok; i++)
        ok = (buf[r->offset + i] & r->mask[i]) == r->bytes[i];
      if (ok) {
        out->type = ZUMIME_N_TYPES + k;
        out->confidence = ZUMIME_CONF_DEFINITE;
        changed = 1;
      }
    }
    if (!changed) return;
  }
}
