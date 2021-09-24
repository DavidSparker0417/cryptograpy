#include<stdint.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#include <windows.h>
#include <wincrypt.h>
#include <stdint.h>
#include <stdbool.h>
#include "crypto.h"
#include "rsa.h"

#define RSA2048_KEYBOLOB_PUBKEY_LEN		276
#define RSA2048_KEYBOLOB_PRIVKEY_LEN	1172

#define SAFE_FCLOSE(x) if(x) { fclose(x); x=NULL; }
/************************************************************************/
/*-------------------------- RSA2048 -----------------------------------*/
/************************************************************************/

#define SWAP_LONG(x)	((((uint32_t)(x)) & 0xFF000000) >> 24)	| \
						((((uint32_t)(x)) & 0x00FF0000) >> 8)	|	\
						((((uint32_t)(x)) & 0x0000FF00) << 8)	|	\
						((((uint32_t)(x)) & 0x000000FF) << 24)
#define RSA2048BIT_KEY 0x8000000

static HCRYPTPROV rsa2048_init_context()
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

bool rsa2048_key_generate(RSA2048_KEY_BLOB* pub_key, RSA2048_KEY_BLOB* priv_key)
{
	HCRYPTPROV prov = 0;
	HCRYPTKEY key = 0;
	unsigned long publicKeyLen, privateKeyLen;
	if (priv_key == NULL || pub_key == NULL)
		return false;

	prov = rsa2048_init_context();
	if (prov == 0)
		return false;
	
	/* Get public key blob */
	if (!CryptGenKey(prov, AT_KEYEXCHANGE, RSA2048BIT_KEY | CRYPT_EXPORTABLE, &key))
		goto _exit;

	if (!CryptExportKey(key, 0, PUBLICKEYBLOB, 0, NULL, &publicKeyLen))
		goto _exit;

	pub_key->blob = malloc(publicKeyLen);
	pub_key->blob_len = publicKeyLen;
	if (!CryptExportKey(key, 0, PUBLICKEYBLOB, 0, pub_key->blob, &publicKeyLen))
		goto _exit;
	
	/* Get private key blob*/
	if (!CryptExportKey(key, 0, PRIVATEKEYBLOB, 0, NULL, &privateKeyLen))
		goto _exit;

	priv_key->blob = malloc(privateKeyLen);
	priv_key->blob_len = privateKeyLen;
	if (!CryptExportKey(key, 0, PRIVATEKEYBLOB, 0, priv_key->blob, &privateKeyLen))
		goto _exit;

	if (key) CryptDestroyKey(key);
	if (prov) CryptReleaseContext(prov, 0);
	return true;

_exit:
	if (key) CryptDestroyKey(key);
	if (prov) CryptReleaseContext(prov, 0);
	SAFE_FREE(pub_key->blob);
	SAFE_FREE(pub_key->blob);
	return false;
}

bool rsa2048_import_key_from_file(char* pubkey_file, RSA2048_KEY_BLOB* pub_key, char* privkey_file, RSA2048_KEY_BLOB* priv_key, uint8_t filemode)
{
	FILE* fp;
	
	if (pubkey_file == NULL || pub_key == NULL || pub_key->blob ||
		privkey_file == NULL || priv_key == NULL || priv_key->blob)
		return false;

	// read public key from file
	fp = fopen(pubkey_file, "rb");
	if (fp == NULL)
		return false;
	fseek(fp, 0, SEEK_END);
	pub_key->blob_len = ftell(fp);
	if (pub_key->blob_len < RSA2048_KEYBOLOB_PUBKEY_LEN)
		goto _err_exit_;
	pub_key->blob = malloc(pub_key->blob_len);
	fseek(fp, 0, SEEK_SET);
	fread(pub_key->blob, 1, pub_key->blob_len, fp);
	SAFE_FCLOSE(fp);

	// read private key from file
	fp = fopen(privkey_file, "rb");
	if (fp == NULL)
		return false;
	fseek(fp, 0, SEEK_END);
	priv_key->blob_len = ftell(fp);
	if (priv_key->blob_len < RSA2048_KEYBOLOB_PUBKEY_LEN)
		goto _err_exit_;
	priv_key->blob = malloc(priv_key->blob_len);
	fseek(fp, 0, SEEK_SET);
	fread(priv_key->blob, 1, priv_key->blob_len, fp);
	SAFE_FCLOSE(fp);

	return true;
_err_exit_:
	SAFE_FCLOSE(fp);
	SAFE_FREE(pub_key->blob);
	SAFE_FREE(priv_key->blob);
	return false;
}

int rsa2048_encrypt(void* inbuf, uint32_t buflen, RSA2048_KEY_BLOB* priv_key, void** outbuf)
{
	uint32_t enclen;
	rsa_sk_t pkey = { 0 };
	PUBLICKEYSTRUC* publickeystruc;
	RSAPUBKEY* rsapubkey;
	uint8_t* ptr;
	uint32_t klen = 0;
	int i = 0;

	if (inbuf == NULL || !buflen || outbuf == NULL)
		return -1;

	publickeystruc = priv_key->blob;
	rsapubkey = (RSAPUBKEY*)(publickeystruc + 1);
	ptr = (uint8_t*)(rsapubkey + 1);
	klen = rsapubkey->bitlen / 8;
	
	pkey.bits = rsapubkey->bitlen;
	*(uint32_t*)(pkey.public_exponet + RSA_MAX_MODULUS_LEN - 4) = SWAP_LONG(rsapubkey->pubexp);

	/*memcpy(pkey.modulus, ptr, klen);*/
	for (i = 0; i < klen; i++)
		pkey.modulus[RSA_MAX_MODULUS_LEN - i - 1] = ptr[i];
	ptr += klen;

	/*memcpy(pkey.prime1, ptr, klen);*/
	klen = rsapubkey->bitlen / 16;
	for (i = 0; i < klen; i++)
		pkey.prime1[RSA_MAX_PRIME_LEN - i - 1] = ptr[i];
	ptr += klen;

	/*memcpy(pkey.prime2, ptr, klen);*/
	for (i = 0; i < klen; i++)
		pkey.prime2[RSA_MAX_PRIME_LEN - i - 1] = ptr[i];
	ptr += klen;

	/*memcpy(pkey.prime_exponent1, ptr, klen);*/
	for (i = 0; i < klen; i++)
		pkey.prime_exponent1[RSA_MAX_PRIME_LEN - i - 1] = ptr[i];
	ptr += klen;

	/*memcpy(pkey.prime_exponent2, ptr, klen);*/
	for (i = 0; i < klen; i++)
		pkey.prime_exponent2[RSA_MAX_PRIME_LEN - i - 1] = ptr[i];
	ptr += klen;

	/*memcpy(pkey.coefficient, ptr, klen); ptr += klen;*/
	for (i = 0; i < klen; i++)
		pkey.coefficient[RSA_MAX_PRIME_LEN - i - 1] = ptr[i];
	ptr += klen;

	klen = rsapubkey->bitlen / 8;
	/*memcpy(pkey.exponent, ptr, klen);*/
	for (i = 0; i < klen; i++)
		pkey.exponent[RSA_MAX_MODULUS_LEN - i - 1] = ptr[i];

	*outbuf = malloc(256);
	if (rsa_private_encrypt(*outbuf, &enclen, inbuf, buflen, &pkey) != 0)
		goto _err_exit;

	return enclen;
_err_exit:
	SAFE_FREE(*outbuf);
	return -1;
}

int rsa2048_decrypt(void* inbuf, uint32_t buflen, RSA2048_KEY_BLOB* pub_key, void** outbuf)
{
	unsigned long decLen = 0;
	rsa_pk_t pkey = { 0 };
	PUBLICKEYSTRUC* publickeystruc;
	RSAPUBKEY* rsapubkey;
	uint8_t* ptr;
	uint32_t klen = 0;
	int i = 0;

	if (inbuf == NULL || !buflen || outbuf == NULL)
		return -1;

	*outbuf = malloc(buflen);
	SecureZeroMemory(*outbuf, buflen);
	
	publickeystruc = pub_key->blob;
	rsapubkey = (RSAPUBKEY*)(publickeystruc + 1);
	ptr = (uint8_t*)(rsapubkey + 1);
	klen = rsapubkey->bitlen / 8;
	pkey.bits = rsapubkey->bitlen;
	*(uint32_t*)(pkey.exponent + RSA_MAX_MODULUS_LEN - 4) = SWAP_LONG(rsapubkey->pubexp);
	/*memcpy(pkey.modulus, ptr, klen);*/
	for (i = 0; i < klen; i++)
		pkey.modulus[RSA_MAX_MODULUS_LEN - i - 1] = ptr[i];
	
	if (rsa_public_decrypt(*outbuf, &decLen, inbuf, buflen, &pkey) != 0)
		goto _err_exit;

	return decLen;

_err_exit:
	
	SAFE_FREE(*outbuf);
	return -1;
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

/************************************************************************/
/*----------------------------- CRC16 ----------------------------------*/
/************************************************************************/
uint16_t CRC16(void *input_str, int num_bytes)
{
	return crc_16((uint8_t*)input_str, num_bytes);
}

/************************************************************************/
/*---------------------------- SHA256 ----------------------------------*/
/************************************************************************/
#include "sha256.h"
bool SHA256_hash(void* buf, int len, void* hash)
{
	SHA256_CTX ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, (uint8_t*)buf, len);
	sha256_final(&ctx, hash);
	return true;
}