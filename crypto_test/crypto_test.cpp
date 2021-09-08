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

static uint8_t key_m[] = {
	0xb7, 0xe9, 0x74, 0x4b, 0x45, 0xfa, 0xa6, 0x20, 0xd3, 0x1c, 0x30, 0xe9, 0x63, 0x86, 0xe9, 0xcd,
	0x5f, 0xb9, 0x93, 0xde, 0xca, 0x45, 0xc9, 0xd6, 0x08, 0x94, 0xf7, 0x7d, 0xb9, 0xee, 0xa9, 0xd0,
	0x78, 0x45, 0x76, 0x94, 0x80, 0x9d, 0xf7, 0x05, 0x24, 0xd7, 0x30, 0xe2, 0xc0, 0x0f, 0x04, 0x6e,
	0x60, 0x53, 0x23, 0xbd, 0x50, 0x03, 0xbf, 0x2c, 0xa9, 0xbb, 0xb4, 0x5c, 0xc5, 0x11, 0x5a, 0x1d,
	0xce, 0x25, 0x7d, 0x42, 0x03, 0x4f, 0x7e, 0x1c, 0x7a, 0x3e, 0x1a, 0x68, 0xe8, 0x9a, 0x00, 0x10,
	0x8d, 0x18, 0x28, 0xac, 0x26, 0xbd, 0x71, 0xae, 0x4a, 0xc9, 0xb9, 0x23, 0x0b, 0x9b, 0xc1, 0x01,
	0x67, 0x46, 0xa9, 0x01, 0x5e, 0x70, 0xf1, 0xd9, 0xbd, 0x7f, 0x56, 0x4b, 0x97, 0x61, 0x64, 0xff,
	0xc1, 0xd9, 0x6e, 0x93, 0xab, 0x40, 0x66, 0xd5, 0xcb, 0xf4, 0x02, 0xf5, 0xfc, 0x53, 0x11, 0x51,
	0xa9, 0x80, 0x5c, 0x07, 0x16, 0xab, 0xcb, 0x98, 0x25, 0xfe, 0x02, 0xf3, 0x89, 0x7e, 0x57, 0x91,
	0x7a, 0x64, 0xcc, 0x2c, 0x7a, 0x71, 0xe8, 0x83, 0x33, 0x59, 0x0a, 0xa9, 0x59, 0x23, 0xcf, 0x4a,
	0x6b, 0xe4, 0x24, 0x1a, 0xf7, 0x8c, 0xa9, 0x04, 0x5d, 0x65, 0xb6, 0x74, 0x87, 0x19, 0x42, 0x49,
	0xe3, 0x69, 0x03, 0xdd, 0xa4, 0xc9, 0x75, 0xfe, 0xa7, 0x3c, 0x07, 0xc1, 0x91, 0x67, 0x54, 0x45,
	0xfe, 0x5f, 0xcf, 0x45, 0x72, 0xf8, 0xbd, 0x47, 0x95, 0xba, 0x81, 0xa7, 0x54, 0x50, 0x55, 0x29,
	0x92, 0x2f, 0x81, 0x82, 0x71, 0x9b, 0x43, 0x1c, 0xeb, 0x27, 0x16, 0xca, 0x87, 0xe2, 0xba, 0x83,
	0xa0, 0x1e, 0x85, 0xef, 0x75, 0xe4, 0x63, 0x88, 0x2d, 0x0b, 0x53, 0x76, 0xb6, 0xb3, 0xd6, 0x68,
	0x19, 0xe2, 0x6c, 0x2b, 0x67, 0x4f, 0x0a, 0x9d, 0xde, 0xfe, 0x93, 0x42, 0x43, 0xce, 0x87, 0xad };
void test_rsa2048()
{
	char *test_buf = "Testing rsa-2048 encode/decode...";
	uint8_t enc_buf[256];
	uint8_t dec_buf[256];
	uint32_t i;
	int enc_len, dec_len, inp_len;

	printf("++++++++++++++ RSA-2048 +++++++++++++++\n");
	printf("[RSA2048] plain buffer.\n\t%s\n", test_buf);
	inp_len = strlen(test_buf);
	enc_len = rsa2048_encrypt(test_buf, enc_buf, key_m, inp_len);
	if (enc_len < 0)
	{
		printf("Failed to encrypt!\n");
		return;
	}
	buf_print(enc_buf, enc_len, "[RSA2048] Encoded buffer");

	dec_len = rsa2048_decrypt(enc_buf, dec_buf, key_m, enc_len);
	if (dec_len < 0)
	{
		printf("Failed to decrypt!\n");
		return;
	}
	dec_buf[dec_len] = 0;
	printf("[RSA2048] Decoded result\n\t%s\n", dec_buf);
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

int _tmain(int argc, _TCHAR* argv[])
{
	test_rsa2048();
	test_base64();
	test_blowfish();
	return 0;
}

