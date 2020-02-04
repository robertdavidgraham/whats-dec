/*
    simple HKDF for prototyping

    This is a simple HKDF-SHA256 module for prototyping, so that you
    don't have to pull in a bunch of dependencies.

    Dependencies:
        SHA-256 functions, such as from crypto_sha256.c
        HMAC functions, such as from crypto_sha256_hmac.c
*/
#ifndef CRYPTO_SHA256_HKDF_H
#define CRYPTO_SHA256_HKDF_H

int crypto_hkdf(const void *salt, size_t salt_length, const void *ikm,
                size_t ikm_length, const void *info, size_t info_len,
                unsigned char *okm, size_t okm_len);

int crypto_hkdf_selftest(void);

#endif
