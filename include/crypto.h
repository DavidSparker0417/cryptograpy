#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#ifdef __cplusplus
extern "C" {
#endif
	/* RSA2048 */
	int rsa2048_encrypt(void* inbuf, void* outbuf, void* enckey, uint32_t buflen);
	int rsa2048_decrypt(void* inbuf, void* outbuf, void* deckey, uint32_t buflen);

	/* base64 */
	int base64_encode(void* in, int in_len, void** out);
	int base64_decode(void* in, int in_len, void** out);

	/* blowfish */
	int bf_encode(void* in, int in_len, void* key, int keylen, void** out);
	int bf_decode(void* in, int in_len, void* key, int keylen, void** out);
#ifdef __cplusplus
}
#endif
#endif