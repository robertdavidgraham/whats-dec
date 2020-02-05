/*
    simple BASE64 module for prototyping

    This is a simple BASE64 encoder/decoder for prototyping, so that
    it can easily be included in a project without importing
    additional dependencies.
*/
#ifndef CRYPTO_BASE64_H
#define CRYPTO_BASE64_H
#include <stddef.h>

void base64_print(const char *prefix, const void *src, size_t length);

/**
 * Decodes a string.
 * @return
 *  the number of bytes written to 'dst', or ~0 on error. Common
 *  errors are when the destination buffer isn't big enough.
 */
size_t base64_decode(void *dst, size_t sizeof_dst, const void *src,
                     size_t sizeof_src);

/**
 * Encodes a string.
 * @return
 *  the number of bytes written to 'dst', or ~0 on error. Common
 *  errors are when the destination buffer isn't big enough.
 */
size_t base64_encode(void *dst, size_t sizeof_dst, const void *src,
                     size_t sizeof_src);

/**
 * Do a simple selftest to verify that this module is working correctly.
 * @return
 *  0 on success, 1 on failure
 */
int base64_selftest(void);

#endif
