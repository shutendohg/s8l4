#include <stdio.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define BUF_SIZE 1024
#define NUM_ITERATIONS 10000
#define IV_SIZE 16
#define KEY_SIZE 32

void handleErrors(void){
	ERR_print_errors_fp(stderr);
	abort();
}

int cipher_openssl(const unsigned char *input, unsigned char *output, int input_len, const unsigned char *key, const unsigned char *iv, int do_encrypto){
	int output_len = 0, tmplen =0;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	if(!ctx) {
		printf("Failed ctx new\n");
		handleErrors();
	}
	if(1 != EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv, do_encrypto)) {
		printf("Failed CipherInit\n");
		EVP_CIPHER_CTX_free(ctx);
		handleErrors();
	}
	if(1 != EVP_CipherUpdate(ctx, output, &output_len, input, input_len)) {
		printf("Failed CipherUpdate\n");
		EVP_CIPHER_CTX_free(ctx);
		handleErrors();
	}
	if(1 != EVP_CipherFinal_ex(ctx, output+output_len, &tmplen)) {
		printf("Failed CipherFinal\n");
		EVP_CIPHER_CTX_free(ctx);
		handleErrors();
	}
	output_len += tmplen;
	EVP_CIPHER_CTX_free(ctx);
	return output_len;
}

int main(void){
	unsigned char input[BUF_SIZE], output[BUF_SIZE + EVP_MAX_BLOCK_LENGTH];
	unsigned char key[32], iv[16];
	clock_t start, end;
	int encrypt_len;
	double cpu_time_used;

	RAND_bytes(input, BUF_SIZE);
	RAND_bytes(key, KEY_SIZE);
	RAND_bytes(iv, IV_SIZE);

	start = clock();
	for (int i = 0; i < NUM_ITERATIONS; ++i){
		encrypt_len = cipher_openssl(input, output, BUF_SIZE, key, iv, 1);
	}
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	printf("OpenSSL Encryption: %f seconds\n", cpu_time_used);

	start = clock();
	for (int i = 0; i < NUM_ITERATIONS; ++i){
		cipher_openssl(output, input, encrypt_len, key, iv, 0);
	}
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	printf("OpenSSL Decryption: %f seconds\n", cpu_time_used);

	return 0;
}
