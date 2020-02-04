/*
    simple HMAC for prototyping

    This is a simple HMAC-SHA256 module for prototyping, so that you
    don't have to pull in a bunch of dependencies.

    Dependencies:
        SHA-256 functions, such as from crypto_sha256.c

    FIPS PUB 198-1
        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf
        MAC(text) = HMAC(K, text) = H((K₀ ⊕ opad )|| H((K₀ ⊕ ipad) || text))
    RFCs
        HMAC: Keyed-Hashing for Message Authentication
        https://tools.ietf.org/html/rfc2104
        https://tools.ietf.org/html/rfc4231
    OID
        1.2.840.113549.2.9
        iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2)
   id-hmacWithSHA256(9) Scheme
        http://www.rsasecurity.com/rsalabs/pkcs/schemas/pkcs-5#hmac-sha-256

*/
#include "crypto-sha256-hmac.h"
#include "crypto-sha256.h"
#include <stdlib.h>

enum {
    /* This is the 256-bit output of the SHA-256 function */
    DIGEST_SIZE = 32,

    /* This is the 512-bit internal blocksize within the SHA-256 function */
    BLOCK_SIZE = 64,
};

void hmac_sha256_init(HMAC_CTX *ctx, const void *v_key, size_t key_length) {
    const unsigned char *key = (const unsigned char *)v_key;
    size_t i;
    unsigned char ipad[BLOCK_SIZE];

    /*
     * FIPS 198-1 - Step 2
     * If the length of K > B: hash K to obtain an L byte string,
     * then append (B-L) zeros to create a B-byte string K0
     */
    if (key_length > BLOCK_SIZE) {
        SHA256_CTX hashctx;
        SHA256_Init(&hashctx);
        SHA256_Update(&hashctx, key, key_length);
        SHA256_Final(ctx->key0, &hashctx);
        ctx->key0_length = DIGEST_SIZE;
    } else {
        for (i = 0; i < key_length; i++)
            ctx->key0[i] = key[i];
        ctx->key0_length = key_length;
    }

    /*
     * FIPS 198-1 - Step 3
     * If the length of K < B: append zeros to the end of K to create a
     * B-byte string K0 */
    for (i = ctx->key0_length; i < BLOCK_SIZE; i++)
        ctx->key0[i] = 0;

    /* FIPS 198-1 - Step 4
     * Exclusive-Or K0 with ipad to produce a B-byte string: K0 ⊕ ipad. */
    for (i = 0; i < BLOCK_SIZE; i++)
        ipad[i] = ctx->key0[i] ^ 0x36;

    /* FIPS 198-1 - Step 5a
     * "Append the stream of data 'text' to the string resulting from step 4:
     * (K0 ⊕ ipad) || text."
     *
     * This means we start doing the underlying hash with 'ipad', before
     * continuing later with 'text'. */
    SHA256_Init(&ctx->hashctx);
    SHA256_Update(&ctx->hashctx, ipad, BLOCK_SIZE);
}

void hmac_sha256_update(HMAC_CTX *ctx, const void *message,
                        size_t message_length) {
    /* FIPS 198-1 - Step 5b
     * "Append the stream of data 'text' to the string resulting from step 4:
     * (K0 ⊕ ipad) || text."
     *
     * We already started hashing 'ipad' in the _init() function, so we
     * just continue here hashing 'text' (aka. 'message'). */
    SHA256_Update(&ctx->hashctx, message, message_length);
}

void hmac_sha256_final(HMAC_CTX *ctx, unsigned char *digest,
                       size_t digest_length) {
    size_t i;
    unsigned char opad[BLOCK_SIZE];

    if (digest_length < DIGEST_SIZE)
        abort();

    /* FIPS 198-1 - Step 6
     * "Step 6 Apply H to the stream generated in step 5:
     * H((K0 ⊕ ipad) || text)."
     *
     * For this code, this step maps with finalizing the hash after doing
     * multiple updates.
     */
    SHA256_Final(digest, &ctx->hashctx);

    /* FIPS 198-1 - Step 7
     * "Exclusive-Or K0 with opad: K0 ⊕ opad."
     */
    for (i = 0; i < BLOCK_SIZE; i++)
        opad[i] = ctx->key0[i] ^ 0x5C;

    /* FIPS 198-1 - Step 8 and Step 9
     * Step 8 - Append the result from step 6 to step 7:
     *  (K0 ⊕ opad) || H((K0 ⊕ ipad) || text).
     * Step 9 - Apply H to the result from step 8:
     *  H((K0 ⊕ opad )|| H((K0 ⊕ ipad) || text)). */
    SHA256_Init(&ctx->hashctx);
    SHA256_Update(&ctx->hashctx, opad, BLOCK_SIZE);
    SHA256_Update(&ctx->hashctx, digest, DIGEST_SIZE);
    SHA256_Final(digest, &ctx->hashctx);
}

void crypto_hmac_sha256(const void *key, size_t key_length, const void *message,
                        size_t message_length, unsigned char *digest,
                        size_t digest_length) {
    HMAC_CTX ctx;

    hmac_sha256_init(&ctx, key, key_length);
    hmac_sha256_update(&ctx, message, message_length);
    hmac_sha256_final(&ctx, digest, digest_length);
}

#ifdef UNITTEST_SHA256_HMAC
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct {
    const char *key;
    const char *message;
    const char *digest;
} tests[] = {{"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
              "4869205468657265", /* "Hi There" */
              "b0344c61d8db38535ca8afceaf0bf12b"
              "881dc200c9833da726e9376c2e32cff7"},
             {"4a656665",                        /* "Jefe" */
              "7768617420646f2079612077616e7420" /* "what do ya want " */
              "666f72206e6f7468696e673f",        /* "for nothing?" */
              "5bdcc146bf60754e6a042426089575c7"
              "5a003f089d2739839dec58b964ec3843"},
             {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
              "aaaaaaaa",
              "dddddddddddddddddddddddddddddddd"
              "dddddddddddddddddddddddddddddddd"
              "dddddddddddddddddddddddddddddddd"
              "dddd",
              "773ea91e36800e46854db8ebd09181a7"
              "2959098b3ef8c122d9635514ced565fe"},
             {"0102030405060708090a0b0c0d0e0f10"
              "111213141516171819",
              "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
              "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
              "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
              "cdcd",
              "82558a389a443c0ea4cc819899f2083a"
              "85f0faa3e578f8077a2e3ff46729665b"},
             {"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"
              "0c0c0c0c",
              "546573742057697468205472756e6361"
              "74696f6e",
              "a3b6167473100ee06e0c796c2955552b"
              "fa6f7c0a6a8aef8b93f860aab0cd20c5"},
             {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
              "aaaaaa",
              "54657374205573696e67204c61726765"
              "72205468616e20426c6f636b2d53697a"
              "65204b6579202d2048617368204b6579"
              "204669727374",
              "60e431591ee0b67f0d8a26aacbf5b77f"
              "8e0bc6213728c5140546040f0ee37f54"},
             {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
              "aaaaaa",
              "54686973206973206120746573742075"
              "73696e672061206c6172676572207468"
              "616e20626c6f636b2d73697a65206b65"
              "7920616e642061206c61726765722074"
              "68616e20626c6f636b2d73697a652064"
              "6174612e20546865206b6579206e6565"
              "647320746f2062652068617368656420"
              "6265666f7265206265696e6720757365"
              "642062792074686520484d414320616c"
              "676f726974686d2e",
              "9b09ffa71b942fcb27635fbcd5b0e944"
              "bfdc63644f0713938a7f51535c3a35e2"},
             {"", "",
              "b613679a0814d9ec772f95d778c35fc5"
              "ff1697c493715653c6c712144292c5ad"},
             {0}};

unsigned hexval(const char c) {
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
size_t read_hex(const char *src, unsigned char *dst, size_t dst_max) {
    size_t i;
    size_t dst_offset = 0;
    for (i = 0; src[i]; i++) {
        unsigned num;

        num = hexval(src[i]);
        i++;
        assert(src[i]);
        num = hexval(src[i]) | (num << 4);

        assert(dst_offset < dst_max);
        dst[dst_offset++] = (unsigned char)num;
    }
    return dst_offset;
}

int main(void) {
    size_t i;
    unsigned test_number = 0;

    for (i = 0; tests[i].key; i++) {
        size_t j;
        unsigned char digest[DIGEST_SIZE];
        unsigned char key[1024];
        unsigned char message[1024];
        unsigned char expected[32];
        size_t key_length;
        size_t message_length;
        size_t expected_length;

        test_number++;

        /* convert the strings in the test cases to binary */
        key_length = read_hex(tests[i].key, key, sizeof(key));
        message_length = read_hex(tests[i].message, message, sizeof(message));
        expected_length = read_hex(tests[i].digest, expected, sizeof(expected));
        assert(expected_length == 32);

        crypto_hmac_sha256(key, key_length, message, message_length, digest,
                           sizeof(digest));

        if (memcmp(digest, expected, 32) != 0) {
            printf("[-] sha-256-hmac testcase=%u failed\n", test_number);
            printf("    expected= ");
            for (j = 0; j < sizeof(expected); j++)
                printf("%02x%s", expected[j], (j == 15) ? " " : "");
            printf("\n");
            printf("    found   = ");
            for (j = 0; j < sizeof(digest); j++)
                printf("%02x%s", digest[j], (j == 15) ? " " : "");
            printf("\n");
        }
    }
    printf("[+] sha256-hmac: succcess (%u test cases)\n", test_number);
    return 0;
}
#endif
