#include "crypto-hex.h"
#include <stdio.h>

/**
 * Standard char->hex function for parsing hex into binary
 */
static unsigned hexval(const char c) {
    if ('0' <= c && c <= '9')
        return c - '0';
    else if ('a' <= c && c <= 'f')
        return c - 'a' + 10;
    else if ('A' <= c && c <= 'F')
        return c - 'A' + 10;
    else
        return ~0;
}

/**
 * Read string of hex characters into binary.
 * @param src
 *  A nul-terminate string containing the numbers '0' through '9'
 *  or the letters 'a' - 'f', upper or lower case.
 * @param dst
 *  Where the parsed binary data is stored.
 * @param dst_max
 *  The maximum buffer size to hold the data.
 * @return the length of the string if valid, or ~0 if there's an
 *  an error, such as invalid hex characters, an odd number of
 *  characters, or the output would overflow the destination buffer.
 */
size_t hex_decode(const char *src, unsigned char *dst, size_t dst_max) {
    size_t i;
    size_t dst_offset = 0;

    /* Strings may optionally be prefixed by "0x" */
    if (src && src[0] == '0' && src[1] == 'x')
        src += 2;

    /* Read all 2-byte values */
    for (i = 0; src[i] && src[i + 1]; i += 2) {
        unsigned num = hexval(src[i]) << 4 | hexval(src[i + 1]);
        if (num == (unsigned)~0)
            return ~0; /* not a hex character */
        if (dst_offset >= dst_max)
            return ~0; /* would overflow buffer */
        dst[dst_offset++] = (unsigned char)num;
    }

    /* Most be an even number of characters. If there is an odd number,
     * then there is an error */
    if (src[i] != '\0')
        return ~0;

    return dst_offset;
}

/** Print the buffer in hex */
void hex_print(const char *prefix, const void *v_buf, size_t length) {
    size_t i;
    const unsigned char *buf = (const unsigned char *)v_buf;
    printf("%s", prefix);
    for (i = 0; i < length; i++)
        printf("%02x%s", buf[i], ((i % 16) == 15) ? " " : "");
    printf("\n");
}
