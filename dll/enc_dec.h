#ifndef __SODIUM_ENCRYPT_C_H__
#define __SODIUM_ENCRYPT_C_H__

#include "sodium/export.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct buffer {
	char   *data;
    size_t len;
    size_t capacity;
} buffer_t;

typedef struct {
    int init;
    uint64_t encrypt_counter;
	uint64_t decrypt_counter;
    uint8_t nonce[crypto_stream_chacha20_NONCEBYTES];
    uint8_t nonce_len;
} cipher_ctx_t;

#define BREAK_UINT32( var, ByteNum ) \
          (unsigned char)((unsigned int)(((var) >>((ByteNum) * 8)) & 0x00FF))

#define BUILD_UINT32(Byte0, Byte1, Byte2, Byte3) \
          ((unsigned int)((unsigned int)((Byte0) & 0x00FF) \
          + ((unsigned int)((Byte1) & 0x00FF) << 8) \
          + ((unsigned int)((Byte2) & 0x00FF) << 16) \
          + ((unsigned int)((Byte3) & 0x00FF) << 24)))

#define BUILD_UINT16(loByte, hiByte) \
          ((short)(((loByte) & 0x00FF) + (((hiByte) & 0x00FF) << 8)))

#define HI_UINT16(a) (((a) >> 8) & 0xFF)
#define LO_UINT16(a) ((a) & 0xFF)

#define BUILD_UINT8(hiByte, loByte) \
          ((unsigned char)(((loByte) & 0x0F) + (((hiByte) & 0x0F) << 4)))

#define HI_UINT8(a) (((a) >> 4) & 0x0F)
#define LO_UINT8(a) ((a) & 0x0F)

SODIUM_EXPORT
void stream_ctx_init(cipher_ctx_t  *cipher_ctx, int enc)
	__attribute__ ((nonnull(1)));

SODIUM_EXPORT
int stream_encrypt(buffer_t *plaintext, cipher_ctx_t *cipher_ctx, size_t capacity,const uint8_t *key)
	__attribute__((nonnull(1,2,4)));

SODIUM_EXPORT
int stream_decrypt(buffer_t *ciphertext, cipher_ctx_t *cipher_ctx, size_t capacity,const uint8_t *key)
    __attribute__((nonnull(1,2,4)));

#ifdef __cplusplus
}
#endif

#endif
