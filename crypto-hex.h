/*
    simple hex decoder for prototyping

    This is a simple module with no additional dependencies
    to easily prototype code without pulling in a ton of
    additional dependencies.
*/
#ifndef CRYPTO_HEX_H
#define CRYPTO_HEX_H
#include <stddef.h>

/**
 * Parse the nul-teriminated string containing hex characters,
 * converting to binary bytes.
 * @param src
 *      A nul-termianted string containd ASCII characters in the
 *      ranges ['0'..'9'], ['a'..'f'], and ['A'..'F']. Any other
 *      character, including spaces, is an error. There must
 *      be an even number of characters, an odd number produces
 *      an error.
 * @param dst
 *      The destination buffer where the decoded binary bytes will
 *      be written. Must be at least half the size of the input
 *      string.
 * @param dst_max
 *      The maximum size of the buffer where data will be written.
 *      Maybe larger than necessary, but if smaller than needed,
 *      an error will be returned.
 * @return
 *      the number of bytes converted, or (~0) if an error occurred.
 */
size_t hex_decode(const char *src, unsigned char *dst, size_t dst_max);

/**
 * Prints a binary string to stdout encoded as hex.
 * @param prefix
 *      A prefix to print in front of the hex string.
 * @param buf
 *      A buffer containing binary characters that will be printed
 *      in hex.
 * @param length
 *      The number of bytes to print in the source string
 *      (meaning twice as many text characters will be printed)
 */
void hex_print(const char *prefix, const void *buf, size_t length);

#endif
