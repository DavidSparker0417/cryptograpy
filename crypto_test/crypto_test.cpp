// crypto_test.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdarg.h>

#include "crypto.h"

#pragma comment(lib, "crypto")
#pragma comment(lib, "Crypt32")

void buf_print(uint8_t* buf, int len, char* fmt, ...)
{
	va_list va;
	int i;

	va_start(va, fmt);
	vprintf(fmt, va);
	va_end(va);

	if (buf == NULL || len == 0)
	{
		printf("\n");
		return;
	}
	for (i = 0; i < len; i++)
	{
		if (i % 16 == 0)
			printf("\n");
		else if (i % 8 == 0)
			printf("- ");
		printf("%02X ", buf[i]);
	}
	printf("\n");
}

void test_rsa2048()
{
	char *test_buf = "Testing rsa-2048 encode/decode...";
	void *enc_buf, *dec_buf;
	uint32_t i;
	int enc_len, dec_len, inp_len;
	RSA2048_KEY_BLOB pub_key = { 0 }, priv_key = { 0 };

	printf("++++++++++++++ RSA-2048 +++++++++++++++\n");
	rsa2048_key_generate(&pub_key, &priv_key);
	buf_print((uint8_t*)pub_key.blob, pub_key.blob_len, "[RSA2048] public key");

	printf("[RSA2048] plain buffer.\n\t%s\n", test_buf);
	inp_len = strlen(test_buf);
	enc_len = rsa2048_encrypt(test_buf, inp_len, &priv_key, &enc_buf);
	if (enc_len < 0)
	{
		printf("Failed to encrypt!\n");
		return;
	}
	buf_print((uint8_t*)enc_buf, enc_len, "[RSA2048] Encoded buffer");

	dec_len = rsa2048_decrypt(enc_buf, enc_len, &pub_key, &dec_buf);
	if (dec_len < 0)
	{
		printf("Failed to decrypt!\n");
		return;
	}

	printf("[RSA2048] Decoded result\n\t%s\n", dec_buf);

	free(enc_buf);
	free(dec_buf);
	if (pub_key.blob) free(pub_key.blob);
	if (priv_key.blob) free(priv_key.blob);
}

void test_base64()
{
	char *test_buf = "Testing base64 encode/decode...";
	int b64_len = 0, inlen = 0;
	uint8_t *b64_ebuf, *b64_dbuf;

	printf("++++++++++++++ BASE64 +++++++++++++++\n");
	printf("[BASE64] plain buffer.\n\t%s\n", test_buf);
	inlen = strlen(test_buf);
	/* Base64 encoding */
	b64_len = base64_encode(test_buf, inlen, (void**)&b64_ebuf);
	if (b64_len < 0)
	{
		printf("[BASE64] Encoding error!\n");
		return;
	}

	b64_ebuf[b64_len] = 0;
	printf("[BASE64] Encoded result\n\t%s\n", b64_ebuf);

	/* Base64 decoding */
	b64_len = base64_decode(b64_ebuf, b64_len, (void**)&b64_dbuf);
	b64_dbuf[b64_len] = 0;
	printf("[BASE64] Decoded result\n\t%s\n", b64_dbuf);
	free(b64_ebuf);
	free(b64_dbuf);
}

void test_blowfish()
{
	char *test_buf = "Testing blowfish encode/decode...";
	uint8_t* encbuf = NULL;
	uint8_t* decbuf = NULL;
	int len, enc_len, dec_len;

	printf("++++++++++++++ BLOWFISH +++++++++++++++\n");
	printf("[BlowFish] plain buffer.\n\t%s\n", test_buf);
	len = strlen(test_buf);
	enc_len = bf_encode(test_buf, len, "TESTKEY", 7, (void**)&encbuf);
	buf_print(encbuf, enc_len, "[BlowFish] Encoded buffer");

	dec_len = bf_decode(encbuf, enc_len, "TESTKEY", 7, (void**)&decbuf);
	printf("[BlowFish] Decoded buffer.\n\t%s\n", decbuf);

	free(encbuf);
	free(decbuf);
}

void test_crc16()
{
	char *test_buf = "Testing crc16!";
	uint16_t crc;
	printf("++++++++++++++ CRC16 +++++++++++++++\n");
	printf("[CRC16] plain buffer.\n\t%s\n", test_buf);
	crc = CRC16((uint8_t*)test_buf, strlen(test_buf));
	printf("[CRC16] crc = .\n\t0x%04X\n", crc);
}

void test_keygen()
{
	char *test_buf = "12345678";
	char *activation_code = NULL;
	RSA2048_KEY_BLOB priv_key = { 0 };
	RSA2048_KEY_BLOB pub_key = { 0 };
	
	printf("++++++++++++++ KEYGEN +++++++++++++++\n");
	printf("[KEYGEN] device id = %s\n", test_buf);

	if (!rsa2048_key_generate(&pub_key, &priv_key))
		goto _exit;

	activation_code = crypto_keygen(test_buf, strlen(test_buf), &priv_key);
	if (activation_code)
		printf("[KEYGEN] activation code = %s\n", activation_code);
	

	if (activation_checkout(activation_code, test_buf, strlen(test_buf), &pub_key))
		printf("[KEYGEN] check ok!\n");
	else
		printf("[KEYGEN] check failed!\n");

	SAFE_FREE(activation_code);

_exit:
	SAFE_FREE(pub_key.blob);
	SAFE_FREE(priv_key.blob);
	SAFE_FREE(activation_code);
}

int _tmain(int argc, _TCHAR* argv[])
{
	/*test_rsa2048();
	test_base64();
	test_blowfish();
	test_crc16();*/
	test_keygen();
	return 0;
}

