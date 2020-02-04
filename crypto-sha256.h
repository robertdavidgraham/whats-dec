/*
 * SHA-256 hash function for prototyping
 *
 * This is a REPLACEMENT for the SHA256 hash functions found in OpenSSL
 * and clones, so that you can get things to work without messing with
 * dependencies.
 *
 * This is a SLOW implementation that conforms religiously to the
 * FIPS 180-4 specification.
 */
#ifndef CRYPTO_SHA256_H
#define CRYPTO_SHA256_H
#include <stddef.h>

typedef struct SHA256state_st {
    unsigned h[8];
    unsigned bitcount_low;
    unsigned bitcount_high;
    struct {
        unsigned char buf[64];
        unsigned count;
    } partial;
    unsigned md_len;
} SHA256_CTX;

int SHA256_Init(SHA256_CTX *ctx);
int SHA256_Update(SHA256_CTX *ctx, const void *data, size_t length);
int SHA256_Final(unsigned char *digest, SHA256_CTX *ctx);
unsigned char *SHA256(const unsigned char *message, size_t length,
                      unsigned char *digest);
void SHA256_Transform(SHA256_CTX *ctx, const unsigned char *data);

#endif
