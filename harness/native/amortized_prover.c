/*
 * Amortized rapidsnark prover bench (V6 §C2): loads + parses the zkey ONCE
 * via groth16_prover_create_zkey_file, then times N groth16_prover_prove
 * calls on an in-memory witness buffer — pure proving, excluding per-call
 * process start, file I/O, and zkey parsing.
 *
 * usage: amortized_prover <zkey> <wtns> <N> <warmup> <samples_out> <proof_out> <public_out>
 * samples_out: one line per timed iteration, microseconds.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "prover.h"

static void *read_file(const char *path, unsigned long long *size_out) {
  FILE *f = fopen(path, "rb");
  if (!f) { fprintf(stderr, "cannot open %s\n", path); exit(1); }
  fseek(f, 0, SEEK_END);
  long size = ftell(f);
  fseek(f, 0, SEEK_SET);
  void *buf = malloc((size_t)size);
  if (!buf || fread(buf, 1, (size_t)size, f) != (size_t)size) {
    fprintf(stderr, "cannot read %s\n", path); exit(1);
  }
  fclose(f);
  *size_out = (unsigned long long)size;
  return buf;
}

static long long now_us(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (long long)ts.tv_sec * 1000000LL + ts.tv_nsec / 1000LL;
}

int main(int argc, char **argv) {
  if (argc != 8) {
    fprintf(stderr,
      "usage: %s <zkey> <wtns> <N> <warmup> <samples_out> <proof_out> <public_out>\n",
      argv[0]);
    return 1;
  }
  const char *zkey_path = argv[1];
  const char *wtns_path = argv[2];
  int n = atoi(argv[3]);
  int warmup = atoi(argv[4]);
  const char *samples_path = argv[5];
  const char *proof_path = argv[6];
  const char *public_path = argv[7];

  unsigned long long wtns_size = 0;
  void *wtns = read_file(wtns_path, &wtns_size);

  char error_msg[1024] = {0};
  void *prover = NULL;

  /* NOTE: rapidsnark v0.0.8's groth16_prover_create_zkey_file is unusable —
   * it hands the prover pointers into a stack-local FileLoader's mapping,
   * which is unmapped on return (use-after-free, segfault on first prove).
   * We own the zkey buffer ourselves and keep it alive for the prover's
   * lifetime via groth16_prover_create. */
  unsigned long long zkey_size = 0;
  long long t_load0 = now_us();
  void *zkey = read_file(zkey_path, &zkey_size);
  int rc = groth16_prover_create(&prover, zkey, zkey_size, error_msg, sizeof(error_msg));
  long long t_load1 = now_us();
  if (rc != PROVER_OK) { fprintf(stderr, "create failed (%d): %s\n", rc, error_msg); return 1; }
  fprintf(stderr, "zkey loaded+parsed once in %lld us\n", t_load1 - t_load0);

  unsigned long long proof_size_max = 0;
  groth16_proof_size(&proof_size_max);
  unsigned long long zkey_size_unused = 0;
  (void)zkey_size_unused;
  /* generous public buffer: 5 signals as decimal JSON fits well under 4 KiB */
  unsigned long long public_size_max = 16384;
  char *proof_buf = (char *)malloc(proof_size_max + 1);
  char *public_buf = (char *)malloc(public_size_max + 1);

  FILE *samples = fopen(samples_path, "w");
  if (!samples) { fprintf(stderr, "cannot open %s\n", samples_path); return 1; }

  for (int i = 0; i < warmup + n; i++) {
    unsigned long long proof_size = proof_size_max;
    unsigned long long public_size = public_size_max;
    long long t0 = now_us();
    rc = groth16_prover_prove(prover, wtns, wtns_size, proof_buf, &proof_size,
                              public_buf, &public_size, error_msg, sizeof(error_msg));
    long long t1 = now_us();
    if (rc != PROVER_OK) { fprintf(stderr, "prove failed (%d): %s\n", rc, error_msg); return 1; }
    if (i >= warmup) fprintf(samples, "%lld\n", t1 - t0);
  }
  fclose(samples);

  FILE *pf = fopen(proof_path, "w");
  fputs(proof_buf, pf);
  fclose(pf);
  FILE *pb = fopen(public_path, "w");
  fputs(public_buf, pb);
  fclose(pb);

  groth16_prover_destroy(prover);
  free(zkey);
  free(wtns);
  free(proof_buf);
  free(public_buf);
  return 0;
}
