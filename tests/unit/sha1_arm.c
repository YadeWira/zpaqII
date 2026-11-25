/* zpaqII - SHA-1: the ARMv8 crypto path against the portable one.
 *
 * The ARMv8 SHA-1 instructions are only used when the CPU reports them, so on
 * x86 this test has nothing to compare and says so.  `make test-sha1hw` runs
 * it here and, for ARM, it runs natively in CI (ubuntu-24.04-arm) and under
 * qemu with `make test-arm`.
 *
 * The portable path is the reference: every length boundary where the padding
 * changes (55, 56, 63, 64, 65, 119, 120, 127, 128) plus longer buffers that
 * go through several blocks.
 */
#include <stdio.h>
#include <string.h>

#include "zq.h"

/* internal hook, src/core/sha1.c */
void zq_sha1_force_portable(int on);
unsigned zq_cpu_features(void);
#define ZQ_CPU_SHA1 1u

static unsigned rnd = 12345u;
static int nextbyte(void) {
  rnd = rnd * 1103515245u + 12345u;
  return (int)((rnd >> 16) & 255u);
}

static void digest(const unsigned char *b, long n, char out[20], int portable) {
  zq_sha1 *s = zq_sha1_new();
  zq_sha1_force_portable(portable);
  zq_sha1_init(s);
  zq_sha1_write(s, (const char *)b, n);
  memcpy(out, zq_sha1_result(s), 20);
  zq_sha1_force_portable(0);
  zq_sha1_free(s);
}

int main(void) {
  static unsigned char buf[1 << 17];
  char a[20], b[20];
  static const long lens[] = {0,   1,   3,   55,  56,  63,  64,
                              65,  119, 120, 127, 128, 1000, 65536,
                              131072};
  int i, cases = 0, fails = 0;

  if ((zq_cpu_features() & ZQ_CPU_SHA1) == 0) {
    printf("sha1 arm hw: not available on this CPU (skipped)\n");
    return 0;
  }
  for (i = 0; i < (int)sizeof(buf); ++i) buf[i] = (unsigned char)nextbyte();

  for (i = 0; i < (int)(sizeof(lens) / sizeof(lens[0])); ++i) {
    digest(buf, lens[i], a, 0);
    digest(buf, lens[i], b, 1);
    ++cases;
    if (memcmp(a, b, 20)) {
      printf("MISMATCH len=%ld\n", lens[i]);
      ++fails;
    }
  }

  /* Many separate writes, so the buffer is hashed across call boundaries. */
  {
    zq_sha1 *p = zq_sha1_new(), *h = zq_sha1_new();
    long off;
    zq_sha1_force_portable(0);
    zq_sha1_init(h);
    zq_sha1_force_portable(1);
    zq_sha1_init(p);
    zq_sha1_force_portable(0);
    for (off = 0; off + 100 <= (long)sizeof(buf); off += 100) {
      zq_sha1_write(h, (const char *)buf + off, 100);
      zq_sha1_force_portable(1);
      zq_sha1_write(p, (const char *)buf + off, 100);
      zq_sha1_force_portable(0);
    }
    ++cases;
    if (memcmp(zq_sha1_result(h), zq_sha1_result(p), 20)) {
      printf("MISMATCH split writes\n");
      ++fails;
    }
    zq_sha1_free(p);
    zq_sha1_free(h);
  }

  printf("sha1 arm hw: %d cases, %d failures\n", cases, fails);
  return fails != 0;
}
