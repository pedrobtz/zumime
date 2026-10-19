/* A driver for tools/fuzz/harness.c where libFuzzer is not available
 * (Apple's clang ships without it): each seed as is, then random bytes and
 * random mutations of the seeds for a number of seconds. Built with ASan
 * and UBSan by tools/fuzz/run-local. Not coverage-guided: the CI job with
 * libFuzzer is the campaign; this is the quick local check. */

#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define MAXSEEDS 512
#define MAXLEN 8192

static uint8_t *seeds[MAXSEEDS];
static size_t seed_len[MAXSEEDS];
static int nseeds = 0;

static void load(const char *dir) {
  DIR *d = opendir(dir);
  if (!d) return;
  struct dirent *e;
  while ((e = readdir(d)) && nseeds < MAXSEEDS) {
    if (e->d_name[0] == '.') continue;
    char path[4096];
    snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
    FILE *f = fopen(path, "rb");
    if (!f) continue;
    uint8_t *buf = malloc(MAXLEN);
    size_t n = fread(buf, 1, MAXLEN, f);
    fclose(f);
    seeds[nseeds] = buf;
    seed_len[nseeds++] = n;
  }
  closedir(d);
}

int main(int argc, char **argv) {
  int seconds = argc > 1 ? atoi(argv[1]) : 30;
  for (int i = 2; i < argc; i++) load(argv[i]);
  for (int i = 0; i < nseeds; i++) LLVMFuzzerTestOneInput(seeds[i], seed_len[i]);
  srand(12345);
  uint8_t buf[MAXLEN];
  time_t end = time(NULL) + seconds;
  unsigned long runs = 0;
  while (time(NULL) < end) {
    size_t n;
    if (nseeds && rand() % 4) {
      int s = rand() % nseeds;
      n = seed_len[s];
      memcpy(buf, seeds[s], n);
      int edits = 1 + rand() % 8;
      for (int k = 0; k < edits && n; k++) {
        switch (rand() % 4) {
        case 0: buf[rand() % n] = (uint8_t) rand(); break;
        case 1: n = (size_t) rand() % (n + 1); break;
        case 2: buf[rand() % n] ^= (uint8_t) (1u << (rand() % 8)); break;
        default: {
          size_t a = (size_t) rand() % n, b = (size_t) rand() % n;
          uint8_t t = buf[a];
          buf[a] = buf[b];
          buf[b] = t;
        }
        }
      }
    } else {
      n = (size_t) rand() % 2048;
      for (size_t i = 0; i < n; i++) buf[i] = (uint8_t) rand();
    }
    LLVMFuzzerTestOneInput(buf, n);
    runs++;
  }
  printf("%lu inputs, %d seeds, clean\n", runs, nseeds);
  return 0;
}
