/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <windows.h>

#include "../../mlkem/src/common.h"
#include "../../mlkem/src/randombytes.h"
#include "../../mlkem/mlkem_native.h"
#include "hal.h"

#ifndef MLK_BENCHMARK_NWARMUP
#define MLK_BENCHMARK_NWARMUP 50
#endif

#ifndef MLK_BENCHMARK_NITERATIONS
#define MLK_BENCHMARK_NITERATIONS 300
#endif

#ifndef MLK_BENCHMARK_NTESTS
#define MLK_BENCHMARK_NTESTS 500
#endif

#define CHECK(x)                                               \
  do                                                           \
  {                                                            \
    int rc_;                                                   \
    rc_ = (x);                                                 \
    if (!rc_)                                                  \
    {                                                          \
      fprintf(stderr, "ERROR (%s,%d)\n", __FILE__, __LINE__);  \
      return 1;                                                \
    }                                                          \
  } while (0)

static const int percentiles[] = {1, 10, 20, 30, 40, 50, 60, 70, 80, 90, 99};

static double get_time_ms(void)
{
  static LARGE_INTEGER freq;
  LARGE_INTEGER counter;

  if (freq.QuadPart == 0)
  {
    if (!QueryPerformanceFrequency(&freq) || freq.QuadPart <= 0)
    {
      return 0.0;
    }
  }

  if (!QueryPerformanceCounter(&counter))
  {
    return 0.0;
  }

  return 1000.0 * (double)counter.QuadPart / (double)freq.QuadPart;
}

static int cmp_double(const void *a, const void *b)
{
  const double da = *(const double *)a;
  const double db = *(const double *)b;

  if (da < db) return -1;
  if (da > db) return 1;
  return 0;
}

static void print_median(const char *txt, const double t_ms[MLK_BENCHMARK_NTESTS])
{
  printf("%s time = %.6f ms\n", txt, t_ms[MLK_BENCHMARK_NTESTS / 2]);
}

static void print_percentile_legend(void)
{
  unsigned i;
  printf("%21s", "percentile");
  for (i = 0; i < sizeof(percentiles) / sizeof(percentiles[0]); i++)
  {
    printf("%9d", percentiles[i]);
  }
  printf("\n");
}

static void print_percentiles(const char *txt,
                              const double t_ms[MLK_BENCHMARK_NTESTS])
{
  unsigned i;
  printf("%10s percentiles:", txt);

  for (i = 0; i < sizeof(percentiles) / sizeof(percentiles[0]); i++)
  {
    size_t idx = ((size_t)MLK_BENCHMARK_NTESTS * (size_t)percentiles[i]) / 100;
    if (idx >= MLK_BENCHMARK_NTESTS)
    {
      idx = MLK_BENCHMARK_NTESTS - 1;
    }
    printf("%9.6f", t_ms[idx]);
  }

  printf("\n");
}

static int bench(void)
{
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key_a[CRYPTO_BYTES];
  uint8_t key_b[CRYPTO_BYTES];
  unsigned char kg_rand[2 * CRYPTO_BYTES];
  unsigned char enc_rand[CRYPTO_BYTES];

  double times_kg[MLK_BENCHMARK_NTESTS];
  double times_enc[MLK_BENCHMARK_NTESTS];
  double times_dec[MLK_BENCHMARK_NTESTS];

  unsigned i, j;

  for (i = 0; i < MLK_BENCHMARK_NTESTS; i++)
  {
    int ret = 0;
    double t0, t1;

    CHECK(randombytes(kg_rand, sizeof(kg_rand)) == 0);
    CHECK(randombytes(enc_rand, sizeof(enc_rand)) == 0);

    for (j = 0; j < MLK_BENCHMARK_NWARMUP; j++)
    {
      ret |= crypto_kem_keypair_derand(pk, sk, kg_rand);
    }

    t0 = get_time_ms();
    for (j = 0; j < MLK_BENCHMARK_NITERATIONS; j++)
    {
      ret |= crypto_kem_keypair_derand(pk, sk, kg_rand);
    }
    t1 = get_time_ms();
    times_kg[i] = (t1 - t0) / (double)MLK_BENCHMARK_NITERATIONS;

    for (j = 0; j < MLK_BENCHMARK_NWARMUP; j++)
    {
      ret |= crypto_kem_enc_derand(ct, key_a, pk, enc_rand);
    }

    t0 = get_time_ms();
    for (j = 0; j < MLK_BENCHMARK_NITERATIONS; j++)
    {
      ret |= crypto_kem_enc_derand(ct, key_a, pk, enc_rand);
    }
    t1 = get_time_ms();
    times_enc[i] = (t1 - t0) / (double)MLK_BENCHMARK_NITERATIONS;

    for (j = 0; j < MLK_BENCHMARK_NWARMUP; j++)
    {
      ret |= crypto_kem_dec(key_b, ct, sk);
    }

    t0 = get_time_ms();
    for (j = 0; j < MLK_BENCHMARK_NITERATIONS; j++)
    {
      ret |= crypto_kem_dec(key_b, ct, sk);
    }
    t1 = get_time_ms();
    times_dec[i] = (t1 - t0) / (double)MLK_BENCHMARK_NITERATIONS;

    CHECK(ret == 0);
    CHECK(memcmp(key_a, key_b, CRYPTO_BYTES) == 0);
  }

  qsort(times_kg, MLK_BENCHMARK_NTESTS, sizeof(times_kg[0]), cmp_double);
  qsort(times_enc, MLK_BENCHMARK_NTESTS, sizeof(times_enc[0]), cmp_double);
  qsort(times_dec, MLK_BENCHMARK_NTESTS, sizeof(times_dec[0]), cmp_double);

  print_median("keypair", times_kg);
  print_median("encaps", times_enc);
  print_median("decaps", times_dec);

  printf("\n");

  print_percentile_legend();
  print_percentiles("keypair", times_kg);
  print_percentiles("encaps", times_enc);
  print_percentiles("decaps", times_dec);

  return 0;
}

int main(void)
{
  return bench();
}
