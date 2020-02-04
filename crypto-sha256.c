/*
 * SHA-256 hash function for prototyping
 *
 * This is a REPLACEMENT for the SHA256 hash functions found in OpenSSL
 * and clones, so that you can get things to work without messing with
 * dependencies.
 *
 * This is a SLOW implementation that conforms religiously to the
 * FIPS 180-4 specification.
 *
 * This is written in clean C without all those macros and type-unsafe
 * issues. It only imports <stddef.h> for the 'size_t' type.
 *
 * References
 *
 * FIPS 180-4
 *  https://csrc.nist.gov/csrc/media/publications/fips/180/4/final/documents/fips180-4-draft-aug2014.pdf
 * RFC 4634
 *  https://tools.ietf.org/html/rfc4634
 * RFC 6234
 *  https://tools.ietf.org/html/rfc6234
 * Wikipedia - SHA2
 *  https://en.wikipedia.org/wiki/SHA-2
 */
#include "crypto-sha256.h"

#ifdef _MSC_VER
#define inline __inline
#endif

/**
 * From FIPS 180-4 §3.1 - Bit Strings and Integers
 * Throughout this specification, the “big-endian” convention is used when
 * expressing both 32- and 64-bit words, so that within each word, the
 * most significant bit is stored in the left-most bit position.
 */
static unsigned read_word(const unsigned char *p, size_t offset) {
    return (((unsigned)((p)[offset + 0] & 0xFF)) << 24) |
           (((unsigned)((p)[offset + 1] & 0xFF)) << 16) |
           (((unsigned)((p)[offset + 2] & 0xFF)) << 8) |
           (((unsigned)((p)[offset + 3] & 0xFF)) << 0);
}

/**
 * See `read_word()` above
 */
static void write_word(unsigned char *p, unsigned x) {
    p[0] = (unsigned char)(((x) >> 24) & 0xFF);
    p[1] = (unsigned char)(((x) >> 16) & 0xFF);
    p[2] = (unsigned char)(((x) >> 8) & 0xFF);
    p[3] = (unsigned char)(((x) >> 0) & 0xFF);
}

/**
 * FIPS 180-4 §3.2.4 - Operations on Words, rotate right
 */
static inline unsigned ROTR(unsigned x, unsigned n) {
    return ((x >> n) | (x << (32 - n)));
}

/*
 * FIPS 180-4 § 4.1.2 SHA-224 and SHA-256 Functions
 * Ch(x, y,z) = (x ∧ y) ⊕ (¬x ∧ z)
 * Maj(x, y,z) = (x ∧ y) ⊕ (x ∧ z) ⊕ ( y ∧ z)
 * ∑₀(x) = ROTR²(x) ⊕ ROTR¹³(x) ⊕ ROTR²²(x)
 * ∑₁(x) = ROTR⁶(x) ⊕ ROTR¹¹(x) ⊕ ROTR²⁵(x)
 * σ₀(x) = ROTR⁷(x) ⊕ ROTR¹⁸(x) ⊕ SHR³(x)
 * σ₁(x) = ROTR¹⁷(x) ⊕ ROTR¹⁹(x) ⊕ SHR¹⁰(x)
 */
static inline unsigned Ch(unsigned x, unsigned y, unsigned z) {
    return (z ^ (x & (y ^ z)));
}
static inline unsigned Maj(unsigned x, unsigned y, unsigned z) {
    return (((x | y) & z) | (x & y));
}
static inline unsigned Sigma0(unsigned x) {
    return (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22));
}
static inline unsigned Sigma1(unsigned x) {
    return (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25));
}
static inline unsigned Gamma0(unsigned x) {
    return (ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3));
}
static inline unsigned Gamma1(unsigned x) {
    return (ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10));
}

/**
 * FIPS 180-4 §4.2.2 - SHA-224 and SHA-256 Constants
 * These constants represent the first thirty-two bits of the fractional
 * parts of the cube roots of the first sixty-four prime numbers.
 */
static const unsigned K[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2, 0xe5c8911e, 0xac9d7b7d};

/**
 * FIPS 180-4 §5.3.3 - SHA-256
 * For SHA-256, the initial hash value, H(0), shall consist of the following
 * eight 32-bit words, in hex.
 * These words were obtained by taking the first thirty-two bits of the
 * fractional parts of the square roots of the first eight prime numbers.
 */
int SHA256_Init(SHA256_CTX *ctx) {
    unsigned *H = ctx->h;

    H[0] = 0x6A09E667;
    H[1] = 0xBB67AE85;
    H[2] = 0x3C6EF372;
    H[3] = 0xA54FF53A;
    H[4] = 0x510E527F;
    H[5] = 0x9B05688C;
    H[6] = 0x1F83D9AB;
    H[7] = 0x5BE0CD19;

    ctx->bitcount_low = 0;
    ctx->bitcount_high = 0;
    ctx->partial.count = 0;
    ctx->md_len = 32; /* 256-bits for output length */

    return 1; /* success */
}

/**
 * FIPS 180-4 - 6.2.2 SHA-256 Hash Computation
 */
void SHA256_Transform(SHA256_CTX *ctx, const unsigned char *buf) {
    unsigned a, b, c, d, e, f, g, h;
    unsigned W[64];
    unsigned *H = ctx->h;
    int i;

    /* FIPS 180-4 §6.2.2.1
     * Prepare the message schedule */
    for (i = 0; i < 16; i++)
        W[i] = read_word(buf, i * 4);
    for (i = 16; i < 64; i++)
        W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];

    /* FIPS 180-4 §6.2.2.2
     * Initialize the eight working variables */
    a = H[0];
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];
    f = H[5];
    g = H[6];
    h = H[7];

    /* FIPS 180-4 §6.2.2.3
     * do 64 rounds on the current block */
    for (i = 0; i < 64; i++) {
        unsigned T1, T2;

        T1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];
        T2 = Sigma0(a) + Maj(a, b, c);

        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    /* FIPS 180-4 §6.2.2.4
     * Compute the ith intermediate hash value H(i) */
    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    H[5] += f;
    H[6] += g;
    H[7] += h;
}

int SHA256_Update(SHA256_CTX *ctx, const void *vsrc, size_t length) {
    const unsigned char *src = (const unsigned char *)vsrc;
    size_t offset = 0;
    unsigned long long x;

    /* Update the length. Externally, this is represented as two
     * 32-bit integers, but we'll just do the calculation with
     * 64-bits internally. */
    x = ((unsigned long long)ctx->bitcount_high << 32ULL) +
        (unsigned long long)ctx->bitcount_low;
    x += length * 8ULL; /* counts bits */
    ctx->bitcount_high = x >> 32ULL;
    ctx->bitcount_low = x & 0xffffffffULL;

    /* If there's a partial chunk left over from a previous call,
     * then process that first */
    if (ctx->partial.count) {
        /* Append to the previous partial block */
        while (offset < length && ctx->partial.count < 64)
            ctx->partial.buf[ctx->partial.count++] = src[offset++];

        /* If we have a full block, then do the transform */
        if (ctx->partial.count == 64) {
            ctx->partial.count = 0;
            SHA256_Transform(ctx, ctx->partial.buf);
        } else {
            return 1; /* success */
        }
    }

    /* Process all the complete blocks in the input */
    while (length - offset > 64) {
        SHA256_Transform(ctx, src + offset);
        offset += 64;
    }

    /* Store any remaining bytes for later calls */
    while (offset < length)
        ctx->partial.buf[ctx->partial.count++] = src[offset++];

    return 1; /* success */
}

int SHA256_Final(unsigned char *digest, SHA256_CTX *ctx) {
    unsigned int i;
    unsigned char finalcount[8];

    /* Write the final length to a buffer that we'll append to the
     * end of the input. We need to save first before doing the rest
     * of the logic below that will continue to update the length
     * incorrectly */
    write_word(&finalcount[0], ctx->bitcount_high);
    write_word(&finalcount[4], ctx->bitcount_low);

    /* FIPS 180-4 §5.1.1 SHA-1, SHA-224 and SHA-256
     * Append the bit “1” to the end of the message */
    SHA256_Update(ctx, "\x80", 1);

    /* If there aren't enough bytes to hold the 64-bit length field
     * in this block, then pad this block with zeroes to put the length
     * field in the next block */
    while (ctx->partial.count > 56)
        SHA256_Update(ctx, "\0", 1);

    /* Put the 64-bit bit length field at the end of this block, padding
     * with zeroes between the end of data and start of length field. */
    while (ctx->partial.count < 56)
        SHA256_Update(ctx, "\0", 1);

    /* Do the length. This ends the final block, so will call the Transform
     * function */
    SHA256_Update(ctx, finalcount, sizeof(finalcount));

    /*
     * The final state is an array of unsigned integers's; place them as a
     * series of bigendian 4-byte words onto the output
     */
    for (i = 0; i < 8; i++)
        write_word(digest + 4 * i, ctx->h[i]);

    /*
     * Clear memory, so that artifacts of a hash aren't left around to
     * be hacked somewhere else.
     */
    for (i = 0; i < 8; i++)
        ctx->h[i] = 0xa3;
    ctx->bitcount_low = 0xa3a3a3a3;
    ctx->bitcount_high = 0xa3a3a3a3;
    for (i = 0; i < sizeof(ctx->partial.buf); i++)
        ctx->partial.buf[i] = 0xA3;
    ctx->partial.count = 0xa3a3a3a3;
    ctx->md_len = 0xa3a3a3a3;

    return 1; /* success */
}

unsigned char *SHA256(const unsigned char *message, size_t length,
                      unsigned char *digest) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, message, length);
    SHA256_Final(digest, &ctx);
    return digest;
}

#ifdef UNITTEST_SHA256
#include <stdio.h>

/**
 * Run a single test vector, consisting of a buffer repeated a number of times.
 * Instead of testing the entire 32-byte output, only the first and last
 * 4-bytes are tested, to make the code easier.
 */
static int test(unsigned test_number, const void *buf, size_t length,
                size_t repeat_count, unsigned expected_first,
                unsigned expected_last) {
    unsigned char digest[32];
    size_t i;
    unsigned found_first;
    unsigned found_last;

    /*
     * Do the hash calculation
     */
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    for (i = 0; i < repeat_count; i++)
        SHA256_Update(&ctx, buf, length);
    SHA256_Final(digest, &ctx);

    /*
     * Test the result against expected result
     */
    found_first = read_word(digest, 0);
    found_last = read_word(digest, 32 - 4);
    if (found_first != expected_first) {
        fprintf(stderr, "%u: expected_first=0x%08x, found=0x%08x\n",
                test_number, expected_first, found_first);
        return 1; /* fail */
    }
    if (found_last != expected_last) {
        fprintf(stderr, "%u: expected_last=0x%08x, found=0x%08x\n", test_number,
                expected_last, found_last);
        return 1; /* fail */
    }

    return 0; /*success (fail_count==0) */
}

/**
 * Generates predictably random stream of bytes to fill a buffer
 * against which we can do a predictable test.
 */
static void rc4_keystream(unsigned char *dst, size_t length) {
    size_t i;
    unsigned char x = 0;
    unsigned char y = 0;
    unsigned char m[256];
    unsigned char j = 0;

    /* Initialize the state */
    for (i = 0; i < 256; i++)
        m[i] = i;
    for (i = 0; i < 256; i++) {
        unsigned char a = m[i];
        j = (unsigned char)(j + a);
        m[i] = m[j];
        m[j] = a;
    }

    /* Generate the bytes */
    for (i = 0; i < length; i++) {
        unsigned char a;
        unsigned char b;

        a = m[++x];
        y += a;
        b = m[y & 0xFF];

        m[x] = b;
        m[y] = a;

        dst[i] = m[(a + b) & 0xFF];
    }
}

/**
 * This tests messages of increasing length. The idea here isn't to
 * test that the math is correct, but to test that the padding at the
 * end is correct, regardless of the length of the message. Thus,
 * we test all lengths, from [0..130], up to a couple bytes past
 * two blocks of input. The resulting test vectors can get huge in the
 * code, so instead of having all 256-bits per vector, we just have the
 * truncated first 32-bits of each result.
 */
int test_padding(void) {
    static const unsigned testvector[130] = {
        0xe3b0c442, 0x7941cb07, 0x5d9a905b, 0xb0cd6528, 0x841267bd, 0xee5196f7,
        0x4ed4d0ef, 0x413cd83a, 0xe1d4b3a5, 0xd5862637, 0xf2736be7, 0x7498e997,
        0x36394e4b, 0xcded9136, 0x70bdeda7, 0x0378beea, 0x067c5312, 0xfcd84b9d,
        0x45d75c4c, 0xd8157a4f, 0xb7d2e3cf, 0x9cc81979, 0xccc089e8, 0xc5fe96ec,
        0x5d75b680, 0xff870d50, 0x657bb0d0, 0xf94b9977, 0xb43d4352, 0x755da38c,
        0x1553e1c0, 0xed52a4f7, 0x119a7e25, 0x8b607dab, 0x8ac0fac5, 0x2fe4b847,
        0x8a32752b, 0x805b5dc7, 0xb888af40, 0x6c48b24d, 0x4b2077fa, 0xebae1110,
        0x81a98a8b, 0xe451e8e4, 0x05d7d6d7, 0xf9714b24, 0x4c30effb, 0x4e405acc,
        0xfbd466ef, 0xef5f941a, 0x1cb7ca59, 0xb158f503, 0xe666933f, 0xaf169f8d,
        0x0617bb24, 0x038051e9, 0x42a40de4, 0x5e54c21b, 0xa7c9e51f, 0x8d56833f,
        0xcbf8732b, 0x87873a7c, 0xeaed995a, 0x559f74bd, 0x3d29e895, 0x2810a8c2,
        0x34f85d38, 0xde1d6ef3, 0x09cadbd9, 0x763ce6f0, 0xd65be05b, 0x19a4c1f8,
        0xdbd4d2fe, 0x4c63821d, 0x1c5938e9, 0x73e0816d, 0x71dc3730, 0xe0e4afca,
        0x72b9413b, 0x4336d43d, 0xaac48d6a, 0x7da5f0f1, 0x6643a5bc, 0x2642b44e,
        0x8822397b, 0xddaea137, 0x64ee0587, 0x5e7fef9b, 0x5dd96249, 0x91e1dab6,
        0x23356561, 0x36639b50, 0x7c8b37b6, 0x453c691e, 0x9002e78b, 0xf161a8e7,
        0x75f550bd, 0xc602049f, 0xd62b3bc4, 0xb9d3bc9f, 0xa3098306, 0x9acdde4a,
        0x6e32cd17, 0x58718964, 0x2518cf6a, 0x398dc3a6, 0x8167144e, 0x98ae74a0,
        0x3eef78bd, 0xf8120ea3, 0x7fb20790, 0x75b204af, 0x83105b9b, 0x4610744b,
        0x72905925, 0x5205d196, 0x34151c46, 0xed423264, 0x27d702a6, 0xba72fa89,
        0x9e7d20b7, 0x874a07d3, 0xaa215611, 0xfb037338, 0xfdf46fb5, 0x29b42273,
        0xc8f83098, 0x6c9357fb, 0x48849546, 0xd3086678};
    size_t i;
    unsigned char buf[256];
    unsigned char digest[32];

    rc4_keystream(buf, 256);

    for (i = 0; i < 130; i++) {
        unsigned x;
        SHA256(buf, i, digest);
        x = read_word(digest, 0);
        if (x != testvector[i]) {
            printf("[-] rc4[i] failed, expected=0x%08x, found=0x%08x\n",
                   testvector[i], x);
            return 1;
        }
    }
    return 0;
}

int main(void) {
    int fail_count = 0;
    unsigned test_number = 0;

    fail_count += test_padding();
    test_number++;

    fail_count += test(test_number++, "", 0, 1, 0xe3b0c442, 0x7852b855);
    fail_count += test(test_number++, "abc", 3, 1, 0xba7816bf, 0xf20015ad);
    fail_count +=
        test(2, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
             1, 0x248d6a61, 0x19db06c1);
    fail_count +=
        test(test_number++,
             "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnh"
             "ijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
             112, 1, 0xcf5b16a7, 0x7afee9d1);
    fail_count += test(test_number++, "a", 1, 1000000, 0xcdc76e5c, 0xc7112cd0);

    /*fail_count += test(3,
       "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno", 64,
       16777216, 0x50e72a0e, 0x6fcd055e);*/

    if (fail_count == 0) {
        fprintf(stderr, "[+] sha256: success (%u test cases)\n", test_number);
        return 0;
    } else {
        fprintf(stderr, "[-] sha256: fail\n");
        return 1;
    }
}
#endif
