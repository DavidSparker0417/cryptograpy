#include<stdint.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

/************************************************************************/
/*-------------------------- RSA2048 -----------------------------------*/
/************************************************************************/
#include "rsa.h"
#include "keys.h"

static uint8_t public_exp[] = { 1, 0, 1 }; // 65537
int rsa2048_encrypt(void* inbuf, void* outbuf, void* enckey, uint32_t buflen)
{
	rsa_sk_t priv_key = { 0 };
	int enc_len;

	priv_key.bits = KEY_M_BITS;
	memcpy(priv_key.modulus, enckey, RSA_MAX_MODULUS_LEN);
	memcpy(&priv_key.public_exponet[RSA_MAX_MODULUS_LEN - sizeof(public_exp)], public_exp, sizeof(public_exp));

	memcpy(&priv_key.exponent[RSA_MAX_MODULUS_LEN - sizeof(key_pe)], key_pe, sizeof(key_pe));
	memcpy(&priv_key.prime1[RSA_MAX_PRIME_LEN - sizeof(key_p1)], key_p1, sizeof(key_p1));
	memcpy(&priv_key.prime2[RSA_MAX_PRIME_LEN - sizeof(key_p2)], key_p2, sizeof(key_p2));
	memcpy(&priv_key.prime_exponent1[RSA_MAX_PRIME_LEN - sizeof(key_e1)], key_e1, sizeof(key_e1));
	memcpy(&priv_key.prime_exponent2[RSA_MAX_PRIME_LEN - sizeof(key_e2)], key_e2, sizeof(key_e2));
	memcpy(&priv_key.coefficient[RSA_MAX_PRIME_LEN - sizeof(key_c)], key_c, sizeof(key_c));
	if (rsa_private_encrypt(outbuf, &enc_len, inbuf, buflen, &priv_key) != 0)
		return -1;
	return enc_len;
}

int rsa2048_decrypt(void* inbuf, void* outbuf, void* deckey, uint32_t buflen)
{
	rsa_pk_t pub_key = { 0 };
	int dec_len;

	pub_key.bits = KEY_M_BITS;
	memcpy(pub_key.modulus, deckey, RSA_MAX_MODULUS_LEN);
	memcpy(&pub_key.exponent[RSA_MAX_MODULUS_LEN - sizeof(public_exp)], public_exp, sizeof(public_exp));

	if (rsa_public_decrypt(outbuf, &dec_len, inbuf, buflen, &pub_key) != 0)
		return -1;
	return dec_len;
}

/************************************************************************/
/*-------------------------- BlowFish ----------------------------------*/
/************************************************************************/
#include "blowfish.h"

int bf_encode(void* in, int in_len, void* key, int keylen, void** out)
{
	blowfish_context_t ctx;
	uint8_t endloop = 0;
	int pos = 0;
	uint32_t* p_out;
	int o_alloc_len = ((in_len + 7) / 8) * 8;

	if (in == NULL || in_len == 0 || out == NULL)
		return -1;

	*out = malloc(o_alloc_len);
	p_out = (uint32_t*)*out;
	memset(p_out, 0, o_alloc_len);
	memcpy(p_out, in, in_len);
	blowfish_initiate(&ctx, key, keylen);
	for (pos = 0; pos < o_alloc_len; pos += 8, p_out += 2)
		blowfish_encryptblock(&ctx, &p_out[0], &p_out[1]);

	return o_alloc_len;
}

int bf_decode(void* in, int in_len, void* key, int keylen, void** out)
{
	blowfish_context_t ctx;
	uint8_t endloop = 0;
	int pos = 0;
	uint32_t* p_out;
	int o_alloc_len = ((in_len + 7) / 8) * 8;

	if (in == NULL || in_len == 0 || out == NULL)
		return -1;

	*out = malloc(o_alloc_len);
	p_out = (uint32_t*)*out;
	memset(p_out, 0, o_alloc_len);
	memcpy(p_out, in, in_len);
	blowfish_initiate(&ctx, key, keylen);
	for (pos = 0; pos < o_alloc_len; pos += 8, p_out += 2)
		blowfish_decryptblock(&ctx, &p_out[0], &p_out[1]);

	return in_len;
}