/*

  whats-dec -- WhatsApp media decryption

  This program decrypts media files that were encrypted via WhatsApp's
  end-to-end encryption. Because the keys are located on the ends (devices),
  we can decrypt these files by first pulling the keys from the device
  (or from a backup of the device).

  Ciphersuite:
    - key-exchange: none
    - bulk-encryption: AES-256-CBC
    - message-authentication (MAC): HMAC-SHA256
    - pseudo-random-function (PRF): HKDF-SHA256
*/
#define _CRT_SECURE_NO_WARNINGS
#include "crypto-aes256.h"
#include "crypto-base64.h"
#include "crypto-hex.h"
#include "crypto-sha256-hkdf.h"
#include "crypto-sha256-hmac.h"
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(WIN32) || defined(_WIN32)
#define snprintf _snprintf
#endif

enum MediaType {
    MediaType_Unknown,
    MediaType_Image,
    MediaType_Video,
    MediaType_Audio,
    MediaType_Text,
};

/**
 * This holds the configuration parsed from the command-line.
 */
struct configuration {
    size_t mediakey_length;
    unsigned char mediakey[32];
    char infilename[512];
    char outfilename[512];
    size_t mediatype;
};

/**
 * Determine the type of media (video, image, audio, doc) from either
 * the extension of the file (.mp4, .jpeg, .txt) or by a specific
 * name for the media type */
static enum MediaType get_media_type(const char *filename) {
    static const char *types[6][32] = {
        {0},
        {"image", ".gif", ".jpg", ".jpeg", ".png", ".tiff", ".raw", ".svg", 0},
        {"video",      ".mp4", ".mpeg", ".mpg", ".mpeg4", ".mpv", ".qt",
         ".quicktime", ".vc1", ".flv",  ".vob", ".ogg",   ".ogv", ".avi",
         ".mov",       ".wmv", ".m4p",  ".m4v", ".3gp",   ".3g2", 0},
        {"audio", ".mp3", ".aiff", ".aac", ".flac", ".wav", ".webm", 0},
        {"text", ".doc", ".pdf", ".txt", 0},
        {0}};
    size_t i;

    /* For all rows, search all columns */
    for (i = 0; i < 5; i++) {
        size_t j;
        for (j = 0; types[i][j]; j++) {
            const char *ext = types[i][j];
            if (strcmp(ext, filename + strlen(filename) - strlen(ext)) == 0)
                return i;
        }
    }
    return 0;
}

/**
 * For selftests, prints a message when the test fails/succeeds
 */
static int STATUS(int test_result, const char *name) {
    if (test_result)
        fprintf(stderr, "[-] %s: failed\n", name);
    else
        fprintf(stderr, "[+] %s: succeeded\n", name);
    return test_result;
}

/**
 * Call all the quick selftest functions for the crypto modules, to make
 * sure all the routines are running well. It's not a comprehensive test,
 * though. */
static void selftest(void) {
    int failure_count = 0;

    failure_count += STATUS(AES256_selftest(0), "AES-256");
    failure_count += STATUS(base64_selftest(), "BASE64");
    failure_count += STATUS(crypto_hkdf_selftest(), "HKDF-SHA256");
    exit(STATUS(failure_count, "selftest") != 0);
}

/**
 * Prints a quick message telling people how to use this module.
 */
static void print_help(void) {
    fprintf(
        stderr,
        "Usage:\n whats-dec --key <key> --in <filename> --out <filename>\n");
    exit(1);
}

/**
 * Parse a single command-line parameter
 */
static void parse_param(struct configuration *cfg, const char *name,
                        const char *value) {
    if (strcmp(name, "key") == 0 || strcmp(name, "mediakey") == 0) {
        /* --mediakey
         * This is the 256-bit/32-byte key in either HEX or BASE64 format.
         * We attempt to parse one, it as one, and if that doens't work,
         * try to parse it as the other. */

        /* Try to decode this as hex */
        cfg->mediakey_length =
            hex_decode(value, cfg->mediakey, sizeof(cfg->mediakey));
        if (cfg->mediakey_length == sizeof(cfg->mediakey))
            return;

        /* If that didn't work, try to decode as base64 */
        cfg->mediakey_length = base64_decode(
            cfg->mediakey, sizeof(cfg->mediakey), value, strlen(value));
        if (cfg->mediakey_length == sizeof(cfg->mediakey))
            return;

        /* If neither hex or base64 worked to give us 32-bytes, then
         * exit wih an error */
        fprintf(stderr,
                "[-] invalid key, need %u-bytes encoded as hex or base64\n",
                (unsigned)sizeof(cfg->mediakey));
        exit(1);
    } else if (strcmp(name, "in") == 0 || strcmp(name, "filename") == 0 ||
               strcmp(name, "infilename") == 0) {
        /* --in
         * This is the input filename, the one downloaded from the WhatsApp
         * website, likely ending in .enc */
        if (strlen(value) + 1 >= sizeof(cfg->infilename)) {
            fprintf(stderr, "[-] infilename too long\n");
            exit(1);
        }
        snprintf(cfg->infilename, sizeof(cfg->infilename), "%s", value);
    } else if (strcmp(name, "out") == 0 || strcmp(name, "outfilename") == 0) {
        /* --out
         * This is the output filename, where we store the video/image.
         * If the user hasn't configured the media type, then we need to guess
         * this from the file extension */
        if (strlen(value) + 1 >= sizeof(cfg->outfilename)) {
            fprintf(stderr, "[-] outfilename too long\n");
            exit(1);
        }
        snprintf(cfg->outfilename, sizeof(cfg->outfilename), "%s", value);
        if (cfg->mediatype == 0)
            cfg->mediatype = get_media_type(cfg->outfilename);
    } else if (strcmp(name, "type") == 0 || strcmp(name, "mediatype") == 0) {
        /* --type
         * This optional field specifies the media type of the file. This
         * is combined with the decryption key, so if we don't get it right,
         * the file won't decrypt. We usually will determine this from
         * the output file extension, but if that doesn't work, the user
         * will need to manually configure this */
        size_t t = get_media_type(value);
        if (t == 0) {
            fprintf(stderr,
                    "[-] unknown media type=%s. Valid parms: video, audio, "
                    "image, doc\n",
                    value);
            exit(1);
        }
        cfg->mediatype = t;
    } else {
        fprintf(stderr, "[-] unknown parameter: --%s (try --help)\n", name);
        exit(1);
    }
}

/**
 * Called by 'main()' to parse the command-line
 */
struct configuration parse_command_line(int argc, char *argv[]) {
    int i;
    struct configuration cfg = {0, {0}, {0}, {0}, 0};

    for (i = 1; i < argc; i++) {
        if (argv[i][0] != '-') {
            fprintf(stderr, "[-] unexpected param: %s\n", argv[i]);
            break;
        }
        switch (argv[i][1]) {
        case '-':
            /* -- double dash seen */
            if (strcmp(argv[i], "--help") == 0)
                print_help();
            if (strcmp(argv[i], "--test") == 0)
                selftest();
            if (i + 1 < argc) {
                /* Of the form '--foo bar' */
                parse_param(&cfg, argv[i] + 2, argv[i + 1]);
                i++;
            } else {
                fprintf(stderr, "[-] missing expected parameter after '%s'\n",
                        argv[i]);
                exit(1);
            }
            break;
        case 'h':
        case '?':
            print_help();
            break;
        default:
            fprintf(stderr, "[-] invalid parameter: -%c (try -h for help)\n",
                    argv[i][1]);
            exit(1);
            break;
        }
    }

    return cfg;
}


/**
 * This is the function that does all the decryption. The rest of this 
 * file is just getting all the configuration and inputs in order to
 * get to this point. You can probably copy/paste this into another
 * program without too much trouble -- the only dependencies are on
 * the underlying cryptographic functions.
 */
void decrypt_stream(FILE *fp_in, FILE *fp_out, const unsigned char *mediakey,
                    size_t mediakey_length, enum MediaType mediatype) {
    unsigned char prevblock[16];
    size_t bytes_read;
    size_t bytes_written;
    struct AES_ctx ctx;
    HMAC_CTX hmac;
    SHA256_CTX filesha_ctx, encsha_ctx;
    unsigned char okm[112] = {0};
    unsigned char iv[16] = {0};
    unsigned char aeskey[32] = {0};
    unsigned char mackey[32] = {0};
    unsigned padding_length;
    unsigned last_length;
    unsigned char tmp[32];
    unsigned char block[16];

    

    static const char *infostrings[6] = {
        /* first value is repeated when type is unknown */
        "WhatsApp Video Keys", "WhatsApp Image Keys",    "WhatsApp Video Keys",
        "WhatsApp Audio Keys", "WhatsApp Document Keys", 0};
    const char *info = infostrings[mediatype];

    /*
     * Key expansion
     * 
     * The 32-byte "mediakey" needs to be expanded with a PRF to at least
     * 80-bytes, from which we'll get a 16-byte initialization-vector/nonce,
     * a 32-byte AES key, and a 32-byte MAC key. This is a fairly typical
     * step in modern encryption.
     */
    crypto_hkdf(0, 0, mediakey, mediakey_length, info, strlen(info), okm,
                sizeof(okm));
    memcpy(iv, okm + 0, sizeof(iv));
    memcpy(aeskey, okm + 16, sizeof(aeskey));
    memcpy(mackey, okm + 48, sizeof(mackey));

    printf("[a] info string = %s\n", info);
    hex_print("[b] mediakey.iv = ", iv, sizeof(iv));
    hex_print("[c] mediakey.aeskey = ", aeskey, sizeof(aeskey));
    hex_print("[d] mediakey.mackey = ", mackey, sizeof(mackey));

    /*
     * Initialize the decryptions.
     * There are many things we calculate:
     *  - AES - this is where we decrypt the contents
     *  - HMAC - this verifies the contents haven't been intentionally
     *    corrupted, modified, or tampered with.
     *  - SHA(enc) - hash of the encrypted file (everything read)
     *  - SHA(file) - hash of the decrypted file (everything written)
     * The HMAC guards against corruption, while the hashes are used
     * to identify this file.
     */
    AES_init_ctx_iv(&ctx, aeskey, iv);
    hmac_sha256_init(&hmac, mackey, 32);
    hmac_sha256_update(&hmac, iv, 16);
    SHA256_Init(&filesha_ctx);
    SHA256_Init(&encsha_ctx);

    /*
     * Read in at least one full block. Since the last block
     * will be a partial block, we end up working always one
     * block behind.
     */
    bytes_read = fread(prevblock, 1, sizeof(prevblock), fp_in);
    SHA256_Update(&encsha_ctx, prevblock, bytes_read);
    if (bytes_read != sizeof(prevblock)) {
        printf("[-] file too short (%u bytes read, expected at least 16)\n",
               (unsigned)bytes_read);
        exit(1);
    }

    /*
     * Do all the crypto calculations on this block. These are the
     * same set we do after each read below.
     */
    hmac_sha256_update(&hmac, prevblock, bytes_read);
    AES_CBC_decrypt_buffer(&ctx, prevblock, bytes_read);
    
    /*
     * We print the (decrypted) contents of the first block. This will
     * give us a hint whether we've properly decryptd things, as it should
     * look like the prologue to a JPEG, MP4, or whatever.
     * We only do this for the first and last block, however, not every
     * block.
     */
    hex_print("[e] block[0] = ", prevblock, bytes_read);

    /*
     * Read in all blocks until the end of file, doing the same
     * crypto operations as above.
     */
    for (;;) {

        /* Read the next block */
        bytes_read = fread(block, 1, sizeof(block), fp_in);
        SHA256_Update(&encsha_ctx, block, bytes_read);

        /* Stop reading when we reach an incomplete block */
        if (bytes_read != sizeof(block))
            break;

        /* Flush the previous block */
        SHA256_Update(&filesha_ctx, prevblock, bytes_read);
        bytes_written = fwrite(prevblock, 1, bytes_read, fp_out);
        if (bytes_written != bytes_read) {
            printf("[-] error writing decrypted output\n");
            exit(1);
        }

        /* decrypt this block and store if for later */
        memcpy(prevblock, block, bytes_read);
        hmac_sha256_update(&hmac, prevblock, bytes_read);
        AES_CBC_decrypt_buffer(&ctx, prevblock, bytes_read);
    }

    /* We've reached the end of the file. The current read needs to
    * be 10-bytes long representing the 'MAC'. The previous block
    * may be padded */
    if (bytes_read != 10) {
        printf("[-] expected 10 remaining bytes at end of file, found %u\n",
            (unsigned)bytes_read);
        exit(1);
    }

    /* The number of bytes of padding are given by the last byte in the
     * the block, and should have a value from between [1..16]. If it's
     * over that number, then it means corruption happened, in which the
     * MAC (below) should also not check out */
    padding_length = prevblock[15];
    if (padding_length > 16) {
        printf("[-] invalid padding length: %u (must be 16 or less)\n",
                padding_length);
        padding_length = 16;
    }

    /* Here we print the last block, minus the padding. If the padding
     * length is 16 bytes, then the final block will be empty */
    last_length = sizeof(prevblock) - padding_length;
    hex_print("[f] block[n] = ", prevblock, last_length);

    /* Here we print the padding and MAC. These are additional [11..26]
     * bytes at the end of the file that the FTI researchers falsely
     * believed were an exploit or malware. */
    hex_print("[g]-padding = ", prevblock + last_length,
                padding_length);
    hex_print("[h]-mac = ", block, bytes_read);

    /* Write the last block */
    SHA256_Update(&filesha_ctx, prevblock, last_length);
    bytes_written = fwrite(prevblock, 1, last_length, fp_out);
    if (bytes_written != last_length) {
        printf("[-] error writing decrypted output\n");
        exit(1);
    }

    /* calculate the expected MAC and see if they match */
    hmac_sha256_final(&hmac, tmp, sizeof(tmp));
    hex_print("[i] MAC = ", tmp, sizeof(tmp));
    if (memcmp(block, tmp, 10) == 0) {
        printf("[j] matched! (verified unmodified)\n");
    } else {
        printf("[-] match failed (file corrupted)\n");
    }

    SHA256_Final(tmp, &filesha_ctx);
    hex_print("[k] SHA256(file).hex = ", tmp, 32);
    base64_print("[l] SHA256(file).b64 = ", tmp, 32);
    SHA256_Final(tmp, &encsha_ctx);
    hex_print("[m] SHA256(enc).hex = ", tmp, 32);
    base64_print("[n] SHA256(enc).b64 = ", tmp, 32);
    
}

int main(int argc, char *argv[]) {
    struct configuration cfg;
    FILE *fp_in;
    FILE *fp_out;
    static const char *medianames[6] = {"video", "image", "video",
                                        "audio", "text",  "unknown"};

    /* 
     * Read in the command-line configuration 
     */
    cfg = parse_command_line(argc, argv);

    /*
     * Verify we have all the necessary parameters
     */
    if (cfg.mediakey_length == 0) {
        fprintf(stderr, "[-] missing key, use '--key' parameter\n");
        return 1;
    }
    if (cfg.infilename[0] == '\0') {
        fprintf(stderr,
                "[-] missing input file, use '--in' parameter\n");
        return 1;
    }
    if (cfg.outfilename[0] == '\0') {
        fprintf(stderr,
                "[-] missing output file, use '--out' parameter\n");
        return 1;
    }
    if (cfg.mediatype == 0) {
        fprintf(stderr,
                "[-] unknown media type, use '--type' parameter"
                " with 'video', 'image', 'audio', or 'text'\n");
        return 1;
    }

    /* Print the configuration parameters to the command-line */
    printf("[+] ciphertext = %s\n", cfg.infilename);
    printf("[+] plaintext  = %s\n", cfg.outfilename);
    printf("[+] mediatype = %s\n", medianames[cfg.mediatype]);
    hex_print("[+] mediakey = ", cfg.mediakey, cfg.mediakey_length);

    /*
     * Open the files
     */
    fp_in = fopen(cfg.infilename, "rb");
    if (fp_in == NULL) {
        printf("[-] %s: %s\n", cfg.infilename, strerror(errno));
        exit(1);
    }
    fp_out = fopen(cfg.outfilename, "wb");
    if (fp_out == NULL) {
        printf("[-] %s: %s\n", cfg.outfilename, strerror(errno));
        exit(1);
    }

    /*
     * This is where all the magic happens
     */
    decrypt_stream(fp_in, fp_out, cfg.mediakey, cfg.mediakey_length,
                   cfg.mediatype);

    /*
     * Everything done so clean up and exit
     */
    fclose(fp_in);
    fclose(fp_out);

    return 0;
}
