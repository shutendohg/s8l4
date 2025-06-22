#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BUF_SIZE 1024
#define NUM_ITERATIONS 10000
#define IV_SIZE 16
#define KEY_SIZE 32

#ifdef USE_OPENSSL
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#elif defined(USE_WOLFSSL)
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/settings.h>
#endif

void handleErrors(void) {
  ERR_print_errors_fp(stderr);
  abort();
}

int cipher(const unsigned char *input, unsigned char *output, int input_len,
           const unsigned char *key, const unsigned char *iv, int do_encrypto) {
  int output_len = 0, tmplen = 0;

#ifdef USE_OPENSSL
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    printf("Failed ctx new\n");
    handleErrors();
  }
  if (1 !=
      EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv, do_encrypto)) {
    printf("Failed CipherInit\n");
    EVP_CIPHER_CTX_free(ctx);
    handleErrors();
  }
  if (1 != EVP_CipherUpdate(ctx, output, &output_len, input, input_len)) {
    printf("Failed CipherUpdate\n");
    EVP_CIPHER_CTX_free(ctx);
    handleErrors();
  }
  if (1 != EVP_CipherFinal_ex(ctx, output + output_len, &tmplen)) {
    printf("Failed CipherFinal\n");
    EVP_CIPHER_CTX_free(ctx);
    handleErrors();
  }
  output_len += tmplen;
  EVP_CIPHER_CTX_free(ctx);
#elif defined(USE_WOLFSSL)
  Aes aes;
  int ret = 0;

  if (do_encrypto) {
    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesSetKey(&aes, key, KEY_SIZE, iv, AES_ENCRYPTION);
    ret = wc_AesCbcEncrypt(&aes, output, input, input_len);
  } else {
    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesSetKey(&aes, key, KEY_SIZE, iv, AES_DECRYPTION);
    ret = wc_AesCbcDecrypt(&aes, output, input, input_len);
  }
  output_len = input_len;
  if (ret != 0) {
    printf("WolfSSL AES operation filed with error: %d\n", ret);
    handleErrors();
  }

  wc_AesFree(&aes);
#endif

  return output_len;
}

#ifdef USE_WOLFSSL
void generate_random_bytes(unsigned char *output, int output_size) {
  int ret = 0;
  WC_RNG rng;
  wc_InitRng(&rng);

  ret = wc_RNG_GenerateBlock(&rng, output, output_size);
  wc_FreeRng(&rng);
}
#endif

int main(void) {
  unsigned char input[BUF_SIZE], output[BUF_SIZE + EVP_MAX_BLOCK_LENGTH];
  unsigned char key[32], iv[16];
  clock_t start, end;
  int encrypt_len;
  double cpu_time_used;

  memset(output, 0, sizeof(output)); // Initialize output

#ifdef USE_OPENSSL
  RAND_bytes(input, BUF_SIZE);
  RAND_bytes(key, KEY_SIZE);
  RAND_bytes(iv, IV_SIZE);
#elif defined(USE_WOLFSSL)
  generate_random_bytes(input, BUF_SIZE);
  generate_random_bytes(key, KEY_SIZE);
  generate_random_bytes(iv, IV_SIZE);
#endif
  start = clock();
  for (int i = 0; i < NUM_ITERATIONS; ++i) {
    encrypt_len = cipher(input, output, BUF_SIZE, key, iv, 1);
  }
  end = clock();
  cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
  printf("Encryption: %f seconds\n", cpu_time_used);

  start = clock();
  for (int i = 0; i < NUM_ITERATIONS; ++i) {
    cipher(output, input, encrypt_len, key, iv, 0);
  }
  end = clock();
  cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
  printf("Decryption: %f seconds\n", cpu_time_used);

  return 0;
}
