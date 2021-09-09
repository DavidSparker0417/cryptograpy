#ifndef _CRYPTO_H_
#define _CRYPTO_H_
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif
	/* RSA2048 */
	bool rsa2048_init();
	void rsa2048_get_key(void* pubkey);
	int rsa2048_encrypt(void* inbuf, uint32_t buflen, void** outbuf);
	int rsa2048_decrypt(void* inbuf, int in_len, void** outbuf, void* deckey);

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