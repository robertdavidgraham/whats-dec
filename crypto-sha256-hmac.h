/*
    simple HMAC for prototyping

    This is a simple HMAC-SHA256 module for prototyping, so that you
    don't have to pull in a bunch of dependencies.

    Dependencies:
        SHA-256 functions, such as from crypto_sha256.c
*/
#ifndef CRYPTO_SHA256_HMAC
#define CRYPTO_SHA256_HMAC
#include "crypto-sha256.h"
#include <stddef.h>

typedef struct {
    SHA256_CTX hashctx;
    unsigned char key0[64];
    size_t key0_length;
} HMAC_CTX;

void hmac_sha256_init(HMAC_CTX *ctx, const void *v_key, size_t key_length);
void hmac_sha256_update(HMAC_CTX *ctx, const void *message,
                        size_t message_length);
void hmac_sha256_final(HMAC_CTX *ctx, unsigned char *digest,
                       size_t digest_length);

/**
 * @param message
 *      The message/file/data to hash.
 * @param message_length
 *      The size of the message, in bytes.
 * @param key
 *      The key to use for this keyed-hash.
 * @param key_length
 *      The size of the key, in bytes.
 * @param digest
 *      A pointer to buffer of at least 32-bytes that will
 *      hold the hash value.
 * @param disgest_length
 *      The length of the buffer.
 */
void crypto_hmac_sha256(const void *key, size_t key_length, const void *message,
                        size_t message_length, unsigned char *digest,
                        size_t digest_length);

#endif
