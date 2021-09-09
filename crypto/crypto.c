#include<stdint.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#include <windows.h>
#include <wincrypt.h>
#include <stdint.h>
#include <stdbool.h>

/************************************************************************/
/*-------------------------- RSA2048 -----------------------------------*/
/************************************************************************/
#include "rsa.h"

#define RSA2048BIT_KEY 0x8000000
#define SAFE_FREE(x) if(x) { free(x); x=NULL; }
#define KEY_M_BITS      2048

static HCRYPTKEY g_key = 0;
static HCRYPTPROV g_provider = 0;
rsa_pk_t g_pub_key;
rsa_sk_t g_priv_key;

static HCRYPTPROV init_context()
{
	HCRYPTPROV provider = 0;

	if (!CryptAcquireContext(&provider, NULL, NULL, PROV_RSA_FULL, 0))
	{
		if (GetLastError() == NTE_BAD_KEYSET)
		{
			if (!CryptAcquireContext(&provider, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET))
				return 0;
		}
		else
			return 0;
	}

	return provider;
}

bool rsa2048_init()
{
	unsigned long publicKeyLen = 0;
	unsigned long privateKeyLen = 0;
	uint8_t *pubkey_blob, *privkey_blob;
	PUBLICKEYSTRUC  *publickeystruc;
	RSAPUBKEY *rsapubkey;
	uint8_t* keyptr;
	uint32_t keylen;

	g_provider = init_context();

	if (g_provider == 0)
		return false;

	if (!CryptGenKey(g_provider, AT_KEYEXCHANGE, RSA2048BIT_KEY | CRYPT_EXPORTABLE, &g_key))
		return false;

	if (!CryptExportKey(g_key, 0, PUBLICKEYBLOB, 0, NULL, &publicKeyLen))
	{
		if (g_key) CryptDestroyKey(g_key);
		return false;
	}

	pubkey_blob = (unsigned char *)malloc(publicKeyLen * sizeof(unsigned char));
	if (pubkey_blob == NULL)
	{
		if (g_key) CryptDestroyKey(g_key);
		return false;
	}
	SecureZeroMemory(pubkey_blob, publicKeyLen * sizeof(unsigned char));

	// --------- public key
	if (!CryptExportKey(g_key, 0, PUBLICKEYBLOB, 0, pubkey_blob, &publicKeyLen))
	{
		SAFE_FREE(pubkey_blob);
		if (g_key) CryptDestroyKey(g_key);
		return false;
	}

	publickeystruc = (PUBLICKEYSTRUC*)pubkey_blob;
	rsapubkey = (RSAPUBKEY*)(publickeystruc + 1);
	g_pub_key.bits = rsapubkey->bitlen;
	*(uint32_t*)(g_pub_key.exponent + RSA_MAX_MODULUS_LEN - 3) = rsapubkey->pubexp;
	memcpy(g_pub_key.modulus, rsapubkey + 1, g_pub_key.bits / 8);

	// --------- private key
	if (!CryptExportKey(g_key, 0, PRIVATEKEYBLOB, 0, NULL, &privateKeyLen))
	{
		SAFE_FREE(pubkey_blob);
		if (g_key) CryptDestroyKey(g_key);
		return false;
	}

	privkey_blob = (unsigned char *)malloc(privateKeyLen * sizeof(unsigned char));
	if (privkey_blob == NULL)
	{
		SAFE_FREE(pubkey_blob);
		if (g_key) CryptDestroyKey(g_key);
		return false;
	}
	SecureZeroMemory(privkey_blob, privateKeyLen * sizeof(unsigned char));

	if (!CryptExportKey(g_key, 0, PRIVATEKEYBLOB, 0, privkey_blob, &privateKeyLen))
	{
		SAFE_FREE(pubkey_blob);
		SAFE_FREE(privkey_blob);
		if (g_key) CryptDestroyKey(g_key);
		return false;
	}

	publickeystruc = (PUBLICKEYSTRUC*)privkey_blob;
	rsapubkey = (RSAPUBKEY*)(publickeystruc + 1);
	g_priv_key.bits = rsapubkey->bitlen;
	*(uint32_t*)(g_priv_key.public_exponet + RSA_MAX_MODULUS_LEN - 3) = rsapubkey->pubexp;

	keyptr = (uint8_t*)(rsapubkey + 1);
	keylen = rsapubkey->bitlen / 8;
	memcpy(g_priv_key.modulus, keyptr, keylen);

	keyptr += keylen;
	keylen = rsapubkey->bitlen / 16;
	memcpy(g_priv_key.prime1, keyptr, keylen);

	keyptr += keylen;
	memcpy(g_priv_key.prime2, keyptr, keylen);
	
	keyptr += keylen;
	memcpy(g_priv_key.prime_exponent1, keyptr, keylen);

	keyptr += keylen;
	memcpy(g_priv_key.prime_exponent2, keyptr, keylen);

	keyptr += keylen;
	memcpy(g_priv_key.coefficient, keyptr, keylen);

	keyptr += keylen;
	keylen = rsapubkey->bitlen / 8;
	memcpy(g_priv_key.exponent, keyptr, keylen);

	CryptDestroyKey(g_key);
	CryptReleaseContext(g_provider, 0);
	return true;
}

void rsa2048_get_key(void* pubkey)
{
	memcpy(pubkey, g_pub_key.modulus, RSA_MAX_MODULUS_LEN);
}

int rsa2048_encrypt(void* inbuf, uint32_t buflen, void** outbuf)
{
	int enc_len;

	*outbuf = malloc((g_priv_key.bits / 8) + 1);
	if (rsa_private_encrypt(*outbuf, &enc_len, inbuf, buflen, &g_priv_key) != 0)
		return -1;
	return enc_len;
}

static uint8_t public_exp[] = { 1, 0, 1 }; // 65537
int rsa2048_decrypt(void* inbuf, int in_len, void** outbuf, void* deckey)
{
	rsa_pk_t pub_key = { 0 };
	int dec_len;

	pub_key.bits = KEY_M_BITS;
	memcpy(pub_key.modulus, deckey, RSA_MAX_MODULUS_LEN);
	memcpy(&pub_key.exponent[RSA_MAX_MODULUS_LEN - sizeof(public_exp)], public_exp, sizeof(public_exp));

	*outbuf = malloc(in_len);

	if (rsa_public_decrypt((uint8_t*)*outbuf, &dec_len, inbuf, in_len, &g_pub_key) != 0)
	{
		free(*outbuf);
		return -1;
	}
	return dec_len;
}

/************************************************************************/
/*-------------------------- BlowFish ----------------------------------*/
/************************************************************************/
#include "blowfish.h"

int bf_encode(void* in, int in_len, void* key, int keylen, void** out)
{
	blowfish_context_t ctx;
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