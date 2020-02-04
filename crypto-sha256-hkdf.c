/*
    simple HKDF for prototyping

    This is a simple HKDF-SHA256 module for prototyping, so that you
    don't have to pull in a bunch of dependencies.

    Dependencies:
        SHA-256 functions, such as from crypto_sha256.c
        HMAC functions, such as from crypto_sha256_hmac.c

    References:
        RFC 5869
        https://tools.ietf.org/html/rfc5869
*/
#include "crypto-sha256-hmac.h"
#include <string.h>

enum {
    DIGEST_SIZE = 32,
    BLOCK_SIZE = 64,
};

enum {
    shaBadParam = 13,
    SUCCESS = 0,
    FAILURE = 1,
};

/*
 * ikm = initial keying material
 * prk = pseudo-random key (that will be used in the next step)
 */
int hkdf_extract(const unsigned char *salt, size_t salt_length,
                 const unsigned char *ikm, size_t ikm_length,
                 unsigned char *prk, size_t prk_length) {
    static unsigned char null_salt[DIGEST_SIZE] = {0};

    /* RFC 5869 - 2.2
     * salt     optional salt value (a non-secret random value);
     *          if not provided, it is set to a string of HashLen zeros. */
    if (salt == NULL || salt_length == 0) {
        salt = null_salt;
        salt_length = DIGEST_SIZE;
    }

    /* RFC 5869 - 2.2
     * The output PRK is calculated as follows:
     * PRK = HMAC-Hash(salt, IKM) */
    crypto_hmac_sha256(salt, salt_length, /* key */
                       ikm, ikm_length,   /* msg */
                       prk, prk_length    /* digest */
    );
    return SUCCESS;
}
/*
 * @param okm_length
 *  This is the value of 'L', the desired number of bytes to
 *  expand to.
 */
int hkdf_expand(const unsigned char *prk, size_t prk_len,
                const unsigned char *info, size_t info_len, unsigned char *okm,
                size_t okm_len) {
    size_t n;
    size_t offset = 0;
    size_t N;
    size_t T_length;
    unsigned char T[DIGEST_SIZE];

    /* RFC 5869 - 2.3
     * PRK      a pseudorandom key of at least HashLen octets
     *          (usually, the output from the extract step)
     */
    if (prk_len < DIGEST_SIZE)
        return FAILURE;

    /* RFC 5869 - 2.3
     * info     optional ctx and application specific information
     *         (can be a zero-length string) */
    if (info == NULL || info_len == 0) {
        info = (const unsigned char *)"";
        info_len = 0;
    }

    /* RFC 5869 - 2.3
     *     L        length of output keying material in octets
     *          (<= 255*HashLen) */
    if (okm_len > 255 * DIGEST_SIZE)
        return FAILURE;

    /* N = ceil(L/HashLen) */
    N = okm_len / DIGEST_SIZE;
    if ((okm_len % DIGEST_SIZE) != 0)
        N++;

    /* T(0) = empty string (zero length) */
    T_length = 0;

    /*
     * T(n) = HMAC-Hash(PRK, T(n-1) | info | n)
     * (where the constant concatenated to the end of each T(n) is a
     * single octet.)
     */
    for (n = 1; n <= N; n++) {
        HMAC_CTX ctx;
        unsigned char c = n;
        size_t j;

        hmac_sha256_init(&ctx, prk, prk_len);
        hmac_sha256_update(&ctx, T, T_length);
        hmac_sha256_update(&ctx, info, info_len);
        hmac_sha256_update(&ctx, &c, 1);
        hmac_sha256_final(&ctx, T, DIGEST_SIZE);

        /* T = T(1) | T(2) | T(3) | ... | T(N)
         * OKM = first L octets of T */
        for (j = 0; j < DIGEST_SIZE && offset + j < okm_len; j++)
            okm[offset + j] = T[j];

        offset += DIGEST_SIZE;
        T_length = DIGEST_SIZE;
    }
    return SUCCESS;
}

int crypto_hkdf(const void *salt, size_t salt_length, const void *ikm,
                size_t ikm_length, const void *info, size_t info_len,
                unsigned char *okm, size_t okm_len) {
    int err;
    unsigned char prk[DIGEST_SIZE];

    err = hkdf_extract(salt, salt_length, ikm, ikm_length, prk, sizeof(prk));
    if (err != SUCCESS)
        return err;

    err = hkdf_expand(prk, DIGEST_SIZE, info, info_len, okm, okm_len);
    if (err != SUCCESS)
        return err;

    return SUCCESS;
}

int crypto_hkdf_selftest(void) {
    const char ikm[] = "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
                       "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
                       "\x0b\x0b\x0b\x0b\x0b\x0b";
    const char salt[] = "\x00\x01\x02\x03\x04\x05\x06\x07"
                        "\x08\x09\x0a\x0b\x0c";
    const char info[] = "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7"
                        "\xf8\xf9";
    const char expected_prk[] = "\x07\x77\x09\x36\x2c\x2e\x32\xdf"
                                "\x0d\xdc\x3f\x0d\xc4\x7b\xba\x63"
                                "\x90\xb6\xc7\x3b\xb5\x0f\x9c\x31"
                                "\x22\xec\x84\x4a\xd7\xc2\xb3\xe5";
    const char expected_okm[] = "\x3c\xb2\x5f\x25\xfa\xac\xd5\x7a"
                                "\x90\x43\x4f\x64\xd0\x36\x2f\x2a"
                                "\x2d\x2d\x0a\x90\xcf\x1a\x5a\x4c"
                                "\x5d\xb0\x2d\x56\xec\xc4\xc5\xbf"
                                "\x34\x00\x72\x08\xd5\xb8\x87\x18"
                                "\x58\x65";
    const char expected_okm2[] = "\xab\xba\xfb\x13\xf5\xc1\xbc\x48"
                                 "\x9d\x42\x03\x13\x58\x17\x95\x6d";
    unsigned char found[1024];
    int err;

    err = hkdf_extract((const unsigned char *)salt, 13,
                       (const unsigned char *)ikm, 22, found, DIGEST_SIZE);
    if (err != SUCCESS || memcmp(expected_prk, found, DIGEST_SIZE) != 0) {
        return 1;
    }

    /* Second, test that entire function works */
    err =
        crypto_hkdf((const unsigned char *)salt, 13, (const unsigned char *)ikm,
                    22, (const unsigned char *)info, 10, found, 42);
    if (err != SUCCESS || memcmp(expected_okm, found, 42) != 0) {
        return 1;
    }

    /* Third, test that null-salt works  */
    err = crypto_hkdf(0, 0, (const unsigned char *)ikm, 22,
                      (const unsigned char *)info, 10, found, 16);
    if (err != SUCCESS || memcmp(expected_okm2, found, 16) != 0) {
        return 1;
    }

    return 0;
}

/****************************************************************************/
/****************************************************************************/
/****************************************************************************/
#ifdef UNITTEST_SHKDF
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct {
    const char *ikm;
    const char *salt;
    const char *info;
    size_t length;
    const char *prk;
    const char *okm;
} tests[] = {
    {
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", /* key */
        "000102030405060708090a0b0c",                   /* salt */
        "f0f1f2f3f4f5f6f7f8f9",                         /* info */
        42,
        "077709362c2e32df0ddc3f0dc47bba63"
        "90b6c73bb50f9c3122ec844ad7c2b3e5", /* prk */
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865" /* okm */
    },
    {"0x000102030405060708090a0b0c0d0e0f"
     "101112131415161718191a1b1c1d1e1f"
     "202122232425262728292a2b2c2d2e2f"
     "303132333435363738393a3b3c3d3e3f"
     "404142434445464748494a4b4c4d4e4f",
     "0x606162636465666768696a6b6c6d6e6f"
     "707172737475767778797a7b7c7d7e7f"
     "808182838485868788898a8b8c8d8e8f"
     "909192939495969798999a9b9c9d9e9f"
     "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
     "0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
     "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
     "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
     "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
     "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
     82,
     "0x06a6b88c5853361a06104c9ceb35b45c"
     "ef760014904671014a193f40c15fc244",
     "0xb11e398dc80327a1c8e7f78c596a4934"
     "4f012eda2d4efad8a050cc4c19afa97c"
     "59045a99cac7827271cb41c65e590e09"
     "da3275600c2f09b8367793a9aca3db71"
     "cc30c58179ec3e87c14c01d5c1f3434f"
     "1d87"},
    {"0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "", "", 42,
     "0x19ef24a32c717b167f33a91d6f648bdf"
     "96596776afdb6377ac434c1c293ccb04",
     "0x8da4e775a563c18f715f802a063c5a31"
     "b8a11f5c5ee1879ec3454e5f3c738d2d"
     "9d201395faa4b61a96c8"},
    {"4ca80d66c68402fb53ccd1207c3a9de5401d9a704d51c26d37b9b130aba700fc", /* ikm
                                                                          */
     "", /* salt */
     "576861747341707020566964656f204b657973", 112,
     "533b19465d067d988c2a4c2b0bb4b218"
     "1ab415c8450bfe3997378ef5ba30f56f",
     "4367627b7897b3e4efaef9a38cb49611"
     "234b96b5349e39f221481eb91b25ef20"
     "a2a93b68b37eb5785b51aadda36150db"
     "a329f783e12eb633fce420a03d79cc83"
     "4804f5f9931b53e150b92a3c04564ec7"
     "e5839caa197ab45f4b17823bfebe58ea"
     "c8f1a84d854bc0a92c9038168ae3d115"},
    {0}};

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
    else {
        assert(!"c is no hex");
    }
}

/** Read strings of hex from RFCs into binary. This is because we
 * copy/pasted the test-cases from RFCs */
size_t read_hex(const char *src, unsigned char *dst, size_t dst_max) {
    size_t i;
    size_t dst_offset = 0;

    /* Strings may optionally be prefixed by "0x" */
    if (src && src[0] && memcmp(src, "0x", 2) == 0)
        src += 2;

    /* Read all 2-byte values */
    for (i = 0; src[i] && src[i + 1]; i += 2) {
        unsigned num = hexval(src[i]) << 4 | hexval(src[i + 1]);
        if (dst_offset >= dst_max) {
            printf("%u >= %u\n", (unsigned)dst_offset, (unsigned)dst_max);
        }
        assert(dst_offset < dst_max);
        dst[dst_offset++] = (unsigned char)num;
    }
    return dst_offset;
}

/** Print the buffer in hex */
static void printbuf(const char *prefix, const unsigned char *buf,
                     size_t length) {
    size_t i;
    printf("%s", prefix);
    for (i = 0; i < length; i++)
        printf("%02x%s", buf[i], ((i % 16) == 15) ? " " : "");
    printf("\n");
}

/* Only when the unittest #define */
int main(void) {
    size_t i;
    unsigned test_number = 0;
    int err;

    for (i = 0; tests[i].ikm; i++) {
        struct {
            unsigned char ikm[128];
            size_t ikm_length;
            unsigned char salt[128];
            size_t salt_length;
            unsigned char info[128];
            size_t info_length;
            unsigned char prk[64];
            size_t prk_length;
            unsigned char okm[1024];
            size_t okm_length;
        } x;
        unsigned char found[1024];

        test_number++;

        /* convert the strings in the test cases to binary */
        x.ikm_length = read_hex(tests[i].ikm, x.ikm, sizeof(x.ikm));
        x.salt_length = read_hex(tests[i].salt, x.salt, sizeof(x.salt));
        x.info_length = read_hex(tests[i].info, x.info, sizeof(x.info));
        x.prk_length = read_hex(tests[i].prk, x.prk, sizeof(x.prk));
        x.okm_length = read_hex(tests[i].okm, x.okm, sizeof(x.okm));

        printf("ikm=%u, salt=%u, info=%u\n", (unsigned)x.ikm_length,
               (unsigned)x.salt_length, (unsigned)x.info_length);

        /* First test that 'extract' worked */
        err = hkdf_extract(x.salt, x.salt_length, x.ikm, x.ikm_length, found,
                           DIGEST_SIZE);
        if (err != SUCCESS || memcmp(x.prk, found, x.prk_length) != 0) {
            printbuf("    expected= ", x.prk, x.prk_length);
            printbuf("    found   = ", found, x.prk_length);
            goto fail;
        }

        /* Second, test that entire function works */
        err = crypto_hkdf(x.salt, x.salt_length, x.ikm, x.ikm_length, x.info,
                          x.info_length, found, x.okm_length);
        if (err != SUCCESS || memcmp(x.okm, found, x.okm_length) != 0) {
            printbuf("    expected= ", x.okm, x.okm_length);
            printbuf("    found   = ", found, x.okm_length);
        }
    }

    /*
     * NULL salt test. This is special test of a NULL parameter
     */
    test_number++;
    {
        unsigned char found[DIGEST_SIZE];
        unsigned char expected[DIGEST_SIZE];
        size_t expected_length;
        int err;

        expected_length = read_hex("b613679a0814d9ec772f95d778c35fc5"
                                   "ff1697c493715653c6c712144292c5ad",
                                   expected, sizeof(expected));

        err = hkdf_extract(NULL, 0, (const unsigned char *)"", 0, found,
                           DIGEST_SIZE);
        if (err != SUCCESS || memcmp(found, expected, expected_length) != 0) {
            printf("     err=%d\n", err);
            printbuf("    expected=", expected, expected_length);
            printbuf("    found   =", found, DIGEST_SIZE);
            goto fail;
        }
    }
    printf("[+] sha256-hdkf: succcess (%d tests)\n", test_number);
    return 0;
fail:
    printf("[-] sha256-hkdf: failed, test-case=%u\n", test_number);
    return 1;
}
#endif
