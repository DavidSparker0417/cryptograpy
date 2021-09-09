#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

/*
** Translation Table as described in RFC1113
*/
static const char cb64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
** Translation Table to decode (created by author)
*/
static const char cd64[] = "|$$$}rstuvwxyz{$$$$$$$>?@ABCDEFGHIJKLMNOPQRSTUVW$$$$$$XYZ[\\]^_`abcdefghijklmnopq";

void encodeblock(unsigned char *in, unsigned char *out, int len)
{
	out[0] = (unsigned char)cb64[(int)(in[0] >> 2)];
	out[1] = (unsigned char)cb64[(int)(((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4))];
	out[2] = (unsigned char)(len > 1 ? cb64[(int)(((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6))] : '=');
	out[3] = (unsigned char)(len > 2 ? cb64[(int)(in[2] & 0x3f)] : '=');
}

/*
** decodeblock
**
** decode 4 '6-bit' characters into 3 8-bit binary bytes
*/
void decodeblock(unsigned char *in, unsigned char *out)
{
	out[0] = (unsigned char)(in[0] << 2 | in[1] >> 4);
	out[1] = (unsigned char)(in[1] << 4 | in[2] >> 2);
	out[2] = (unsigned char)(((in[2] << 6) & 0xc0) | in[3]);
}

int base64_encode(void* in, int in_len, void** out)
{
	uint8_t *p_out = NULL, *p_in = (uint8_t*)in;
	int pos = 0;
	bool endloop = false;

	if (!in || !in_len)
		return -1;

	*out = malloc(in_len * 2);
	p_out = (uint8_t*)*out;
	while (!endloop && pos < in_len)
	{
		uint8_t in_blk[3];
		uint8_t blklen = 0;
		int i;

		for (i = 0; i < 3; i ++)
		{
			if (pos < in_len)
			{
				in_blk[i] = p_in[pos++];
				blklen ++;
			}
			else
			{
				in_blk[i] = 0;
				endloop = true;
			}
		}

		encodeblock(in_blk, p_out, blklen);
		p_out += 4;
	}

	return (p_out - (uint8_t*)*out);
}

int base64_decode(void* in, int in_len, void** out)
{
	uint8_t *p_out = NULL, *p_in = (uint8_t*)in;
	int pos = 0;
	bool endloop = false;
	uint8_t inblk[4] = { 0 };

	if (!in || !in_len)
		return -1;

	*out = malloc(in_len);
	p_out = (uint8_t*)*out;
	
	while (!endloop)
	{
		int v;
		int i = 0;
		int blklen = 0;

		for (i = 0; i < 4; i ++)
		{
			v = 0;
			while (v == 0)
			{
				if (pos == in_len)
				{
					endloop = true;
					break;
				}
				v = p_in[pos++];
				v = ((v < 43 || v > 122) ? 0 : (int)cd64[v - 43]);
				if (v)
					v = ((v == (int)'$') ? 0 : v - 61);
			}

			if (!endloop)
			{
				blklen ++;
				if (v)
					inblk[i] = (uint8_t)(v - 1);
			}
			else
				inblk[i] = 0;
		}

		if (blklen > 0)
		{
			decodeblock(inblk, p_out);
			p_out += (blklen-1);
		}
	}

	return p_out - (uint8_t*)*out;
}