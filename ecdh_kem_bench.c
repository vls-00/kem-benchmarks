#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/hpke.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define ITERATIONS 100
#define EXPORT_LEN 32

static double diff_ms(const struct timespec *start, const struct timespec *end) {
    double sec = (double)(end->tv_sec - start->tv_sec) * 1000.0;
    double nsec = (double)(end->tv_nsec - start->tv_nsec) / 1000000.0;
    return sec + nsec;
}

static void print_errors_and_exit(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

typedef struct {
    const char *name;
    double keygen_ms;
    double encap_ms;
    double decap_ms;
} bench_result;

static void run_bench(const char *name, OSSL_HPKE_SUITE suite, bench_result *res) {
    const unsigned char info[] = "benchmark-info";
    unsigned char sender_secret[EXPORT_LEN];
    unsigned char receiver_secret[EXPORT_LEN];
    size_t enc_size = OSSL_HPKE_get_public_encap_size(suite);
    struct timespec t1, t2;
    double keygen_total = 0.0, encap_total = 0.0, decap_total = 0.0;

    if (enc_size == 0)
        print_errors_and_exit("OSSL_HPKE_get_public_encap_size failed");

    for (int i = 0; i < ITERATIONS; i++) {
        unsigned char pub[256];
        size_t publen = sizeof(pub);
        unsigned char *enc = malloc(enc_size);
        size_t enclen = enc_size;
        EVP_PKEY *priv = NULL;
        OSSL_HPKE_CTX *sctx = NULL, *rctx = NULL;

        if (enc == NULL)
            print_errors_and_exit("malloc failed");

        clock_gettime(CLOCK_MONOTONIC, &t1);
        if (OSSL_HPKE_keygen(suite, pub, &publen, &priv, NULL, 0, NULL, NULL) != 1) {
            free(enc);
            print_errors_and_exit("OSSL_HPKE_keygen failed");
        }
        clock_gettime(CLOCK_MONOTONIC, &t2);
        keygen_total += diff_ms(&t1, &t2);

        sctx = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, suite, OSSL_HPKE_ROLE_SENDER, NULL, NULL);
        if (sctx == NULL) {
            EVP_PKEY_free(priv);
            free(enc);
            print_errors_and_exit("OSSL_HPKE_CTX_new sender failed");
        }

        clock_gettime(CLOCK_MONOTONIC, &t1);
        if (OSSL_HPKE_encap(sctx, enc, &enclen, pub, publen, info, sizeof(info) - 1) != 1) {
            OSSL_HPKE_CTX_free(sctx);
            EVP_PKEY_free(priv);
            free(enc);
            print_errors_and_exit("OSSL_HPKE_encap failed");
        }
        clock_gettime(CLOCK_MONOTONIC, &t2);
        encap_total += diff_ms(&t1, &t2);

        if (OSSL_HPKE_export(sctx, sender_secret, sizeof(sender_secret), (const unsigned char *)"bench", 5) != 1) {
            OSSL_HPKE_CTX_free(sctx);
            EVP_PKEY_free(priv);
            free(enc);
            print_errors_and_exit("OSSL_HPKE_export sender failed");
        }

        rctx = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, suite, OSSL_HPKE_ROLE_RECEIVER, NULL, NULL);
        if (rctx == NULL) {
            OSSL_HPKE_CTX_free(sctx);
            EVP_PKEY_free(priv);
            free(enc);
            print_errors_and_exit("OSSL_HPKE_CTX_new receiver failed");
        }

        clock_gettime(CLOCK_MONOTONIC, &t1);
        if (OSSL_HPKE_decap(rctx, enc, enclen, priv, info, sizeof(info) - 1) != 1) {
            OSSL_HPKE_CTX_free(rctx);
            OSSL_HPKE_CTX_free(sctx);
            EVP_PKEY_free(priv);
            free(enc);
            print_errors_and_exit("OSSL_HPKE_decap failed");
        }
        clock_gettime(CLOCK_MONOTONIC, &t2);
        decap_total += diff_ms(&t1, &t2);

        if (OSSL_HPKE_export(rctx, receiver_secret, sizeof(receiver_secret), (const unsigned char *)"bench", 5) != 1) {
            OSSL_HPKE_CTX_free(rctx);
            OSSL_HPKE_CTX_free(sctx);
            EVP_PKEY_free(priv);
            free(enc);
            print_errors_and_exit("OSSL_HPKE_export receiver failed");
        }

        if (memcmp(sender_secret, receiver_secret, sizeof(sender_secret)) != 0) {
            OSSL_HPKE_CTX_free(rctx);
            OSSL_HPKE_CTX_free(sctx);
            EVP_PKEY_free(priv);
            free(enc);
            fprintf(stderr, "Shared secret mismatch on iteration %d\n", i + 1);
            exit(EXIT_FAILURE);
        }

        OSSL_HPKE_CTX_free(rctx);
        OSSL_HPKE_CTX_free(sctx);
        EVP_PKEY_free(priv);
        free(enc);
    }

    res->name = name;
    res->keygen_ms = keygen_total / ITERATIONS;
    res->encap_ms = encap_total / ITERATIONS;
    res->decap_ms = decap_total / ITERATIONS;
}

int main(void) {
    bench_result results[2];
    OSSL_HPKE_SUITE x25519 = {
        .kem_id = OSSL_HPKE_KEM_ID_X25519,
        .kdf_id = OSSL_HPKE_KDF_ID_HKDF_SHA256,
        .aead_id = OSSL_HPKE_AEAD_ID_EXPORTONLY
    };
    OSSL_HPKE_SUITE p256 = {
        .kem_id = OSSL_HPKE_KEM_ID_P256,
        .kdf_id = OSSL_HPKE_KDF_ID_HKDF_SHA256,
        .aead_id = OSSL_HPKE_AEAD_ID_EXPORTONLY
    };

    ERR_load_crypto_strings();
    OPENSSL_init_crypto(0, NULL);

    if (OSSL_HPKE_suite_check(x25519) != 1)
        print_errors_and_exit("X25519 HPKE suite is not supported by this OpenSSL build");
    if (OSSL_HPKE_suite_check(p256) != 1)
        print_errors_and_exit("P-256 HPKE suite is not supported by this OpenSSL build");

    run_bench("X25519", x25519, &results[0]);
    run_bench("P-256", p256, &results[1]);

    printf("Iterations: %d\n\n", ITERATIONS);
    printf("%-10s | %12s | %12s | %12s\n", "KEM", "KeyGen (ms)", "Encap (ms)", "Decap (ms)");
    printf("%-10s-+-%12s-+-%12s-+-%12s\n", "----------", "------------", "------------", "------------");
    for (size_t i = 0; i < 2; i++) {
        printf("%-10s | %12.6f | %12.6f | %12.6f\n",
               results[i].name,
               results[i].keygen_ms,
               results[i].encap_ms,
               results[i].decap_ms);
    }

    return 0;
}