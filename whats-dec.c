/*

  whats-dec -- WhatsApp media decryption

  This program decrypts media files that were encrypted via WhatsApp's
  end-to-end encryption. Because the keys are located on the ends, we
  can decrypt these files by first pulling the keys from the device
  (or from a backup of the device).

  Ciphersuite:
    - key-exchange: none
    - bulk-encryption: AES-256-CBC
    - message-authentication (MAC): HMAC-SHA256
    - pseudo-random-function (PRF): HKDF-SHA256
*/
#include "aes.h"
#include "crypto-base64.h"
#include "util-sha256-hkdf.h"
#include "util-sha256-hmac.h"
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int selftest(void) {
  uint8_t key[32];
  uint8_t out[64];
  uint8_t iv[16];
  uint8_t in[64];
  struct AES_ctx ctx;

  if (base64_selftest())
    return 1;

  parse_hex("234b96b5349e39f221481eb91b25ef20"
            "a2a93b68b37eb5785b51aadda36150db",
            key, sizeof(key));
  parse_hex("0242dca8280f7408d5f45f91540d0baa"
            "0ed8fbe1dc725b9e79945fe3aab39639"
            "78efe8d97089704c3e09ebff902023de"
            "44553177293733bacaff00f47545b180",
            out, sizeof(out));
  parse_hex("4367627b7897b3e4efaef9a38cb49611", iv, sizeof(iv));
  parse_hex("000000206674797069736f6d00000200"
            "69736f6d69736f32617663316d703431"
            "000000186265616d0100000001000000"
            "00000000070000000002193b6d6f6f76",
            in, sizeof(in));

  AES_init_ctx_iv(&ctx, key, iv);
  AES_CBC_encrypt_buffer(&ctx, in, 64);

  if (0 == memcmp((char *)out, (char *)in, 64)) {
    // printf("[+] selftest: AES success\n");
    return (0);
  } else {
    printf("[-] selftest: AES failure\n");
    return (1);
  }
}

struct configuration {
  size_t mediakey_length;
  unsigned char mediakey[32];
  char infilename[512];
  char outfilename[512];
};

static void print_help(void) {
  fprintf(stderr,
          "Usage:\n whats-dec --key <key> --in <filename> --out <filename>\n");
  exit(1);
}

static void parse_param(struct configuration *cfg, const char *name,
                        const char *value) {
  if (strcmp(name, "key") == 0 || strcmp(name, "mediakey") == 0) {
    cfg->mediakey_length =
        parse_hex(value, cfg->mediakey, sizeof(cfg->mediakey));
    if (cfg->mediakey_length == sizeof(cfg->mediakey))
      return;
    cfg->mediakey_length = base64_decode(cfg->mediakey, sizeof(cfg->mediakey),
                                         value, strlen(value));
    if (cfg->mediakey_length == sizeof(cfg->mediakey))
      return;
    fprintf(stderr, "[-] invalid key, need %u-bytes encoded as hex or base64\n",
            (unsigned)sizeof(cfg->mediakey));
    exit(1);
  } else if (strcmp(name, "in") == 0 || strcmp(name, "filename") == 0 ||
             strcmp(name, "infilename") == 0) {
    if (strlen(value) + 1 >= sizeof(cfg->infilename)) {
      fprintf(stderr, "[-] infilename too long\n");
      exit(1);
    } else {
      snprintf(cfg->infilename, sizeof(cfg->infilename), "%s", value);
    }
  } else if (strcmp(name, "out") == 0 || strcmp(name, "outfilename") == 0) {
    if (strlen(value) + 1 >= sizeof(cfg->outfilename)) {
      fprintf(stderr, "[-] outfilename too long\n");
      exit(1);
    } else {
      snprintf(cfg->outfilename, sizeof(cfg->outfilename), "%s", value);
    }
  } else {
    fprintf(stderr, "[-] unknown parameter: --%s (try --help)\n", name);
    exit(1);
  }
}

struct configuration parse_command_line(int argc, char *argv[]) {
  int i;
  struct configuration cfg = {0};

  for (i = 1; i < argc; i++) {
    if (argv[i][0] != '-') {
      fprintf(stderr, "[-] unexpected param: %s\n", argv[i]);
      break;
    }
    switch (argv[i][1]) {
    case '-':
      if (i + 1 < argc) {
        if (strcmp(argv[i], "--help") == 0)
          print_help();

        /* Of the form '--foo bar' */
        parse_param(&cfg, argv[i] + 2, argv[i + 1]);
        i++;
      } else {
        fprintf(stderr, "[-] missing expected parameter after '%s'\n", argv[i]);
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
 * Decrypts the encrypted file as a stream, one 16-byte AES block at a time,
 * until we reach the end. The last read from the file will be 10 bytes
 * of the "message authentication code". The 16-byte block before that
 * will contain padding.
 * @param fp_in
 *      The encrypted ciphertext from WhatsApp, the ".enc" file that we
 *      read from.
 * @param fp_out
 *      The file we write to that will contain the unencrypted plaintext.
 * @param aeskey
 *      The 256-bit (32-byte) AES encryption key.
 * @param iv
 *      The 128-bit (16-byte) initialization vector (aka. nonce) for
 *      initializing the decryption.
 * @param mackey
 *      The key for the keyed-hash we use to verify that the file hasn't
 *      been corrupted, either unintentionally or intentionally.
 */
void decrypt_stream(FILE *fp_in, FILE *fp_out, const unsigned char *aeskey,
                    const unsigned char *iv, const unsigned char *mackey) {
  unsigned char prevblock[16];
  size_t bytes_read;
  struct AES_ctx ctx;
  HMAC_CTX hmac;

  /*
   * Initialize the decryptions
   */
  AES_init_ctx_iv(&ctx, aeskey, iv);
  hmac_sha256_init(&hmac, mackey, 32);
  hmac_sha256_update(&hmac, iv, 16);

  /*
   * Read in at least one full block
   */
  bytes_read = fread(prevblock, 1, sizeof(prevblock), fp_in);
  if (bytes_read != sizeof(prevblock)) {
    printf("[-] file too short (%u bytes read, expected at least 16)\n",
           (unsigned)bytes_read);
    exit(1);
  }
  hmac_sha256_update(&hmac, prevblock, sizeof(prevblock));
  AES_CBC_decrypt_buffer(&ctx, prevblock, sizeof(prevblock));
  printbuf("[+] block[0] = ", prevblock, sizeof(prevblock));

  for (;;) {
    unsigned char block[16];
    size_t bytes_written;

    /*
     * Read the next block
     */
    bytes_read = fread(block, 1, sizeof(block), fp_in);

    /*
     * If a full block, then process it
     */
    if (bytes_read == sizeof(block)) {
      /* flush the previous block */
      bytes_written = fwrite(prevblock, 1, sizeof(prevblock), fp_out);
      if (bytes_written != sizeof(prevblock)) {
        printf("[-] error writing decrypted output\n");
        exit(1);
      }

      /* decrypt this block and store if for later */
      memcpy(prevblock, block, sizeof(prevblock));
      hmac_sha256_update(&hmac, prevblock, sizeof(prevblock));
      AES_CBC_decrypt_buffer(&ctx, prevblock, sizeof(prevblock));
      continue;
    }

    /* We've reached the end of the file. The current read needs to
     * be 10-bytes long representing the 'MAC'. The previous block
     * may be padded */
    if (bytes_read != 10) {
      printf("[-] expected 10 remaining bytes at end of file, found %u\n",
             (unsigned)bytes_read);
      exit(1);
    } else {
      unsigned padding_length = prevblock[15];
      unsigned last_length = sizeof(prevblock) - padding_length;
      if (padding_length > 16) {
        printf("[-] invalid padding length: %u (must be 16 or less)\n",
               padding_length);
        exit(1);
      }
      printbuf("[+] block[n] = ", prevblock, last_length);
      printbuf("[+]*padding = ", prevblock + last_length, padding_length);
      printbuf("[+]*mac = ", block, bytes_read);

      /* Write the last block */
      bytes_written = fwrite(prevblock, 1, last_length, fp_out);
      if (bytes_written != last_length) {
        printf("[-] error writing decrypted output\n");
        exit(1);
      }

      /* calcualte the expected match and see if they match */
      {
        unsigned char finalmac[32];
        hmac_sha256_final(&hmac, finalmac, sizeof(finalmac));
        printbuf("[+] MAC = ", finalmac, sizeof(finalmac));
        if (memcmp(block, finalmac, 10) == 0) {
          printf("[+] matched! (verified not corrupted)\n");
        } else {
          printf("[-] match failed, file corrupted\n");
        }
      }

      break;
    }
  }
}

int main(int argc, char *argv[]) {
  struct configuration cfg;
  unsigned char okm[112] = {0};
  unsigned char iv[16] = {0};
  unsigned char aeskey[32] = {0};
  unsigned char mackey[32] = {0};
  FILE *fp_in;
  FILE *fp_out;

  /* Do a simple verification the encryption is working
   * correctly */
  if (selftest() != 0) {
    fprintf(stderr, "[-] selftest failed\n");
    return 1;
  }

  /* Read in the command-line configuration */
  cfg = parse_command_line(argc, argv);

  /*
   * Verify we have all the necessary parameters
   */
  if (cfg.mediakey_length == 0) {
    fprintf(stderr, "[-] missing key, use '--key' parameter\n");
    return 1;
  }
  if (cfg.infilename[0] == '\0') {
    fprintf(stderr, "[-] missing input file, use '--infilename' parameter\n");
    return 1;
  }
  if (cfg.outfilename[0] == '\0') {
    fprintf(stderr, "[-] missing output file, use '--outfilename' parameter\n");
    return 1;
  }

  /*
   * Expand the key
   * This is a common issue with encryption in that we need more than
   * a simple 'key', but also an 'initialization vector' (aka. 'nonce')
   * and a verification or 'message authentication code' key. Thus,
   * we need to take the original input 'mediakey' and expand or stretch
   * it using a pseudo-random function.
   */
  crypto_hkdf(0, 0, cfg.mediakey, cfg.mediakey_length,
              (const unsigned char *)"WhatsApp Video Keys", 19, okm,
              sizeof(okm));
  memcpy(iv, okm + 0, sizeof(iv));
  memcpy(aeskey, okm + 16, sizeof(aeskey));
  memcpy(mackey, okm + 48, sizeof(mackey));

  /* Print the extracted values */
  printf("[+] ciphertext = %s\n", cfg.infilename);
  printf("[+] plaintext  = %s\n", cfg.outfilename);
  printbuf("[+] mediakey = ", cfg.mediakey, cfg.mediakey_length);
  printbuf("[+] mediakey.iv = ", iv, sizeof(iv));
  printbuf("[+] mediakey.aeskey = ", aeskey, sizeof(aeskey));
  printbuf("[+] mediakey.mackey = ", mackey, sizeof(mackey));

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

  decrypt_stream(fp_in, fp_out, aeskey, iv, mackey);

  fclose(fp_in);
  fclose(fp_out);

  return 0;
}