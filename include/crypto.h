#ifndef _CRYPTO_H_
#define _CRYPTO_H_
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif
	/* RSA2048 */
	typedef struct _RSA2048_KEY_BLOB_
	{
		void*		blob;
		uint32_t	blob_len;
	} RSA2048_KEY_BLOB;

	bool rsa2048_key_generate(RSA2048_KEY_BLOB* pub_key, RSA2048_KEY_BLOB* priv_key);
	bool rsa2048_make_pubkey(uint32_t exponent, uint8_t* modulus, uint32_t modulus_len, RSA2048_KEY_BLOB* pubkey);
	int rsa2048_encrypt(void* inbuf, uint32_t buflen, RSA2048_KEY_BLOB* priv_key, void** outbuf);
	int rsa2048_decrypt(void* inbuf, uint32_t buflen, RSA2048_KEY_BLOB* pub_key, void** outbuf);

	/* base64 */
	int base64_encode(void* in, int in_len, void** out);
	int base64_decode(void* in, int in_len, void** out);

	/* blowfish */
	int bf_encode(void* in, int in_len, void* key, int keylen, void** out);
	int bf_decode(void* in, int in_len, void* key, int keylen, void** out);

	/* crc16 */
	uint16_t crc_16(const unsigned char *input_str, size_t num_bytes);
#ifdef __cplusplus
}
#endif
#endif