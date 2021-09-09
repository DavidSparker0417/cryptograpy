#include<stdint.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#include <windows.h>
#include <wincrypt.h>
#include <stdint.h>
#include <stdbool.h>
#include "crypto.h"

/************************************************************************/
/*-------------------------- RSA2048 -----------------------------------*/
/************************************************************************/

#define RSA2048BIT_KEY 0x8000000
#define SAFE_FREE(x) if(x) { free(x); x=NULL; }

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
	if (pub_key->blob) free(pub_key->blob);
	if (priv_key->blob) free(pub_key->blob);
	return false;
}

int rsa2048_encrypt(void* inbuf, uint32_t buflen, RSA2048_KEY_BLOB* priv_key, void** outbuf)
{
	HCRYPTPROV prov = 0;
	HCRYPTKEY key = 0;
	unsigned long encLen = 0, len = 0;

	if (inbuf == NULL || !buflen || outbuf == NULL)
		return -1;
	
	prov = rsa2048_init_context();
	if (prov == 0)
		goto _err_exit;

	if (!CryptImportKey(prov, priv_key->blob, priv_key->blob_len, 0, CRYPT_OAEP, &key))
		goto _err_exit;

	len = buflen + 1;
	if (!CryptEncrypt(key, 0, TRUE, 0, NULL, &len, 0))
		goto _err_exit;

	encLen = len;
	*outbuf = malloc(encLen);
	SecureZeroMemory(*outbuf, encLen);
	memcpy_s(*outbuf, encLen, inbuf, buflen);
	len = buflen + 1;
	if (!CryptEncrypt(key, 0, TRUE, CRYPT_OAEP, *outbuf, &len, encLen))
		goto _err_exit;

	if (key) CryptDestroyKey(key);
	if (prov) CryptReleaseContext(prov, 0);
	return encLen;

_err_exit:
	if (key) CryptDestroyKey(key);
	if (prov) CryptReleaseContext(prov, 0);
	if (*outbuf) free(*outbuf);
	return -1;
}

int rsa2048_decrypt(void* inbuf, uint32_t buflen, RSA2048_KEY_BLOB* pub_key, void** outbuf)
{
	HCRYPTPROV prov = 0;
	HCRYPTKEY key = 0;
	unsigned long len = 0, decLen;

	if (inbuf == NULL || !buflen || outbuf == NULL)
		return -1;

	prov = rsa2048_init_context();
	if (prov == 0)
		goto _err_exit;

	if (!CryptImportKey(prov, pub_key->blob, pub_key->blob_len, 0, CRYPT_OAEP, &key))
		goto _err_exit;

	*outbuf = malloc(buflen);
	SecureZeroMemory(*outbuf, buflen);
	memcpy_s(*outbuf, buflen, inbuf, buflen);

	decLen = buflen;
	if (!CryptDecrypt(key, 0, TRUE, CRYPT_OAEP, *outbuf, &decLen))
		goto _err_exit;

	if (key) CryptDestroyKey(key);
	if (prov) CryptReleaseContext(prov, 0);
	return decLen;

_err_exit:
	if (key) CryptDestroyKey(key);
	if (prov) CryptReleaseContext(prov, 0);
	if (*outbuf) free(*outbuf);
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