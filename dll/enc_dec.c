#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "sodium.h"
#include "enc_dec.h"

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))

#define SODIUM_BLOCK_SIZE   64

static int brealloc(buffer_t *ptr, size_t len, size_t capacity)
{
    size_t real_capacity = 0;
    if (ptr == NULL)
        return -1;
    real_capacity = max(len, capacity);
    if (ptr->capacity < real_capacity) {
        ptr->data     = (char *)realloc(ptr->data, real_capacity);
        ptr->capacity = real_capacity;
    }
    return real_capacity;
}

void stream_ctx_init(cipher_ctx_t  *cipher_ctx, int isClient)
{
    sodium_memzero(cipher_ctx, sizeof(cipher_ctx_t));
    cipher_ctx->nonce_len = crypto_stream_chacha20_NONCEBYTES;
    if(isClient) {
        randombytes_buf(cipher_ctx->nonce, sizeof(cipher_ctx->nonce));
    }
}

int stream_encrypt(buffer_t *plaintext, cipher_ctx_t *cipher_ctx, size_t capacity,const unsigned char *key)
{
    size_t nonce_len = 0;
    int padding = 0;
    static buffer_t tmp = { NULL,0, 0 };
    buffer_t *ciphertext = &tmp;
    if(!cipher_ctx->init) {
        nonce_len = cipher_ctx->nonce_len;
    }

    brealloc(&tmp, nonce_len + plaintext->len, capacity);
    ciphertext->len = plaintext->len;

    if(!cipher_ctx->init) {
        // fill nonce
        memcpy(ciphertext->data, cipher_ctx->nonce, nonce_len);
        cipher_ctx->encrypt_counter = 0;
        cipher_ctx->init    = 1;
    }

    padding = cipher_ctx->encrypt_counter % SODIUM_BLOCK_SIZE;
    brealloc(ciphertext, nonce_len + (padding + ciphertext->len) * 2, capacity);
    if (padding) {
        brealloc(plaintext, plaintext->len + padding, capacity);
        memmove(plaintext->data + padding, plaintext->data, plaintext->len);
        sodium_memzero(plaintext->data, padding);
    }

    crypto_stream_chacha20_xor_ic((uint8_t *)(ciphertext->data + nonce_len),
                                  (const uint8_t *)plaintext->data,
                                  (uint64_t)(plaintext->len + padding),
                                  (const uint8_t *)cipher_ctx->nonce,
                                  cipher_ctx->encrypt_counter / SODIUM_BLOCK_SIZE, key);

    cipher_ctx->encrypt_counter += plaintext->len;
    if (padding) {
        memmove(ciphertext->data + nonce_len,
                ciphertext->data + nonce_len + padding, ciphertext->len);
    }

    brealloc(plaintext, nonce_len + ciphertext->len, capacity);
    memcpy(plaintext->data, ciphertext->data, nonce_len + ciphertext->len);
    plaintext->len = nonce_len + ciphertext->len;
    return 0;
}

int stream_decrypt(buffer_t *ciphertext, cipher_ctx_t *cipher_ctx, size_t capacity,const unsigned char *key)
{
    int padding = 0;
	size_t nonce_len=0;
    buffer_t *plaintext = NULL;
    static buffer_t tmp = { NULL,0, 0 };
    if(ciphertext->len == 0 || ciphertext->data == NULL) {
        return -1;
    }

    brealloc(&tmp, ciphertext->len, capacity);
    plaintext = &tmp;
    plaintext->len = ciphertext->len;

    if(!cipher_ctx->init) {
        if(ciphertext->len < cipher_ctx->nonce_len) {
            return -1;
        }
        //fetch nonce
		nonce_len = cipher_ctx->nonce_len;
        memcpy(cipher_ctx->nonce, ciphertext->data, nonce_len);
		ciphertext->len -= nonce_len;
        cipher_ctx->decrypt_counter = 0;
        cipher_ctx->init    = 1;
    }

	// only contain nonce
    if(ciphertext->len == 0) {
        return -1;
    }

    padding = cipher_ctx->decrypt_counter % SODIUM_BLOCK_SIZE;
    brealloc(plaintext, (plaintext->len + padding) * 2, capacity);

    if (padding) {
        brealloc(ciphertext, ciphertext->len + padding, capacity);
        memmove(ciphertext->data + padding, ciphertext->data,ciphertext->len);
        sodium_memzero(ciphertext->data, padding);
    }

    crypto_stream_chacha20_xor_ic((uint8_t *)(plaintext->data),
                                  (const uint8_t *)(ciphertext->data + nonce_len),
                                  (uint64_t)(ciphertext->len + padding),
                                  (const uint8_t *)cipher_ctx->nonce,
                                  cipher_ctx->decrypt_counter / SODIUM_BLOCK_SIZE, key);
    cipher_ctx->decrypt_counter += ciphertext->len;
    if (padding) {
        memmove(plaintext->data, plaintext->data + padding, plaintext->len);
    }

    brealloc(ciphertext, plaintext->len - nonce_len, capacity);
    memcpy(ciphertext->data, plaintext->data, plaintext->len - nonce_len);
    ciphertext->len = (plaintext->len - nonce_len);
    return 0;
}
