/* /////////////// DISCLAIMER/////////////////////////////////
   This software is provided by the author and
   contributors ``as is'' and any express or implied
   warranties, including, but not limited to, the
   implied warranties of merchantability and
   fitness for a particular purpose are dis-
   claimed. In no event shall the author or con-
   tributors be liable for any direct, indirect,
   incidental, special, exemplary, or consequen-
   tial damages (including, but not limited to,
   procurement of substitute goods or services;
   loss of use, data, or profits; or business
   interruption) however caused and on any
   theory of liability, whether in contract,
   strict liability, or tort (including negligence
   or otherwise) arising in any way out of the use
   of this software, even if advised of the poss-
   ibility of such damage.
//////////////////////////////////////////////////////*/
#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "F5crypt.h"

#include "sha1.cu"
#include "hash_sha1.cu"

__device__ char deZigZag[] = {  0,  1,  5,  6, 14, 15, 27, 28,
                     2,  4,  7, 13, 16, 26, 29, 42,
                     3,  8, 12, 17, 25, 30, 41, 43,
                     9, 11, 18, 24, 31, 40, 44, 53,
                    10, 19, 23, 32, 39, 45, 52, 54,
                    20, 22, 33, 38, 46, 51, 55, 60,
                    21, 34, 37, 47, 50, 56, 59, 61,
                    35, 36, 48, 49, 57, 58, 62, 63};

__device__ char pk_sentinal[] = "----* PK v 1.0 REQUIRES PASSWORD ----*";


__device__ void F5gen_next_batch(f5_rand_state *st) {
	// From SecureRandom.getEngineNextBytes
	// Conviently, the 20 state bytes get assembled in little endin order into 5 integers
	SHA1(st->output, st->state, 20);

	// From SecureRandom.updateState
	st->last = 1;
	st->v = 0;
	st->t = 0;
	st->zf = 0;  //using as bool

	for (int j = 0; j < 20; j++)
	{
		st->v = (int)st->state[j] + (int)st->output[j] + st->last;
		st->t = (uint8_t)st->v;   //lower 8 bits only
		st->zf = st->zf | (st->state[j] != st->t);
		st->state[j] = st->t;
		st->last = st->v >> 8;
	}

	if (!st->zf) st->state[0]++;  // make sure at least one bit changes

	// reset output position
	st->output_pos = 0;
}

__device__ void F5gen_rand_seed(char *seed, int seed_len, f5_rand_state *st)
{
	/*
	ALT_SHA1(st->state, seed, seed_len);

	printf("alt sha1 ");
	for (int offset = 0; offset < 20; offset++) {
		printf("%02x", st->state[offset] & 0xff);
	}
	printf("\n");
	*/
	SHA1(st->state, seed, seed_len);
	/*
	printf("sha1 ");
	for (int offset = 0; offset < 20; offset++) {
		printf("%02x", st->state[offset] & 0xff);
	}
	printf("\n");
	*/
	F5gen_next_batch(st);
}

__device__ int F5gen_rand_next(f5_rand_state *st)
{
	int rand = st->output[st->output_pos++];
	// Generate in blocks of 5 ints
	if (st->output_pos >= 20) {
		F5gen_next_batch(st);
	}
	return rand;
}

__device__ void F5permutation(f5_rand_state *st, int *shuffled, int size)
{                                     /*modifies*/
	// finishes what F5Random does
	// then builds the permutation table
	int random_index;
	int tmp;
	int max_random;

	for (int i = 0; i < size; i++) {
		shuffled[i] = i;
	}
	max_random = size;
	for (int i = 0; i < size; i++)
	{
		// F5Random.getNextValue
		random_index = F5gen_rand_next(st) | F5gen_rand_next(st) << 8 | F5gen_rand_next(st) << 16 | F5gen_rand_next(st) << 24;
		random_index %= max_random;
		if (random_index < 0) {
			random_index += max_random;
		}

		max_random--;

		tmp = shuffled[random_index];
		shuffled[random_index] = shuffled[max_random];
		shuffled[max_random] = tmp;
	}
	
#ifdef DEBUG
	FILE *debug_dump;
	debug_dump = fopen("permutation_dump.dat", "wb");
	if (debug_dump) fwrite(shuffled, 4, size, debug_dump);
	fclose(debug_dump);
#endif
}

__device__ int F5extract(short *coeff, int coeff_len, int* shuffled, f5_rand_state *st, int max_msg_length, char *message, int *message_len, int mode)
{
	int msg_pos = 0;
	// Taken strate from Extract.java
	char extractedByte = 0;
	int  availableExtractedBits = 0;
	int  extractedFileLength = 0;
	int  nBytesExtracted = 0;
	int  shuffledIndex = 0;
	int  extractedBit = 0;
	int  i;  //not only an iterator

	//extract the length of the hidden message
	for (i = 0; availableExtractedBits < 32; i++)
	{
		if (i >= coeff_len) {
			return 0;
		}
		shuffledIndex = shuffled[i];
		if (shuffledIndex % 64 == 0) continue; //Skip DCs
		shuffledIndex = shuffledIndex - (shuffledIndex % 64) + deZigZag[shuffledIndex % 64];
		if (coeff[shuffledIndex] == 0) continue; //Skip zeros
		if (coeff[shuffledIndex] > 0)
			extractedBit = coeff[shuffledIndex] & 1;        // if coefficent is greater than 0 then take LSB literally
		else
			extractedBit = 1 - (coeff[shuffledIndex] & 1);  // else, take the INVERSE of the LSB
		extractedFileLength |= extractedBit << availableExtractedBits++;
	}

	// remove pad
	extractedFileLength ^= F5gen_rand_next(st);
	extractedFileLength ^= F5gen_rand_next(st) << 8;
	extractedFileLength ^= F5gen_rand_next(st) << 16;
	extractedFileLength ^= F5gen_rand_next(st) << 24;
	int k = (extractedFileLength >> 24);
	k %= 32;
	int n = (1 << k) - 1;
	extractedFileLength &= 0x007fffff;

	// quick retun of message length is beyond  max reasonable size
	if ((extractedFileLength > max_msg_length) || (extractedFileLength < 16)) {
		return 0;
	}

	// pixel knot 
	if ((mode > 0) && (extractedFileLength < mode)) {
		return 0;
	}

	//	printf("file length %d\n", extractedFileLength);

	// Proceed with decode
	availableExtractedBits = 0;
	if (n > 0)
	{
		int startOfN = i;
		int hash;

		while (1)
		{
			// read places and calculate bits
			hash = 0;
			int code = 1;
			for (i = 0; code <= n; i++)
			{
				if (startOfN + i >= coeff_len) return 0;
				shuffledIndex = shuffled[startOfN + i];
				if (shuffledIndex % 64 == 0) continue; //skip DCs
				shuffledIndex = shuffledIndex - (shuffledIndex % 64) + deZigZag[shuffledIndex % 64];
				if (coeff[shuffledIndex] == 0) continue; //skip zeros
				if (coeff[shuffledIndex] > 0)
					extractedBit = coeff[shuffledIndex] & 1;
				else
					extractedBit = (1 - coeff[shuffledIndex]) & 1;
				if (extractedBit == 1) hash ^= code;
				code++;
			}
			startOfN += i;

			// write k bits bytewise
			for (i = 0; i < k; i++)
			{
				extractedByte |= ((hash >> i) & 1) << availableExtractedBits++;
				if (availableExtractedBits == 8)
				{
					// remove pad and save byte
					extractedByte ^= F5gen_rand_next(st);
					message[msg_pos++] = extractedByte;
					extractedByte = 0;
					availableExtractedBits = 0;
					nBytesExtracted++;

					// PixelKnot specific check
					if (mode > 0) {
						if (message[msg_pos - 1] != pk_sentinal[msg_pos - 1]) {
							// printf("wrong byte decoded\n");
							return 0;
						}
						if (msg_pos > mode) {
							printf("decoded enough matching bytes %d/%d\n", nBytesExtracted, extractedFileLength);
							*message_len = msg_pos;
							return 1;
						}
					}
				}
				// check for pending end of embedded data
				if (nBytesExtracted == extractedFileLength)
				{
					printf("extracted all bytes at %d\n", nBytesExtracted);
					*message_len = msg_pos;
					return nBytesExtracted > 1; //woohoo!
				}
			}
		}
	}
	else  //Default code used
	{
		for (/*see above*/; i < coeff_len; i++)
		{
			shuffledIndex = shuffled[i];
			if (shuffledIndex % 64 == 0) continue; //skip DCs
			shuffledIndex = shuffledIndex - (shuffledIndex % 64) + deZigZag[shuffledIndex % 64];
			if (coeff[shuffledIndex] == 0) continue; //skip zeros
			if (coeff[shuffledIndex] > 0)
				extractedBit = coeff[shuffledIndex] & 1;
			else
				extractedBit = 1 - (coeff[shuffledIndex] & 1);
			extractedByte |= extractedBit << availableExtractedBits++;
			if (availableExtractedBits == 8)
			{
				// remove pseudo random pad
				extractedByte ^= F5gen_rand_next(st);
				message[msg_pos++] = extractedByte;
				extractedByte = 0;
				availableExtractedBits = 0;
				nBytesExtracted++;

				// PixelKnot specific check
				if (mode > 0) {
					if (message[msg_pos - 1] != pk_sentinal[msg_pos - 1]) {
						// printf("wrong byte decoded\n");
						return 0;
					}
					if (msg_pos > mode) {
						printf("decoded enough matching bytes %d/%d\n", nBytesExtracted, extractedFileLength);
						*message_len = msg_pos;
						return 1;
					}
				}

				// extracted all requested bytes
				if (nBytesExtracted == extractedFileLength)
				{
					printf("extracted all bytes at %d\n", nBytesExtracted);
					*message_len = msg_pos;
					return nBytesExtracted > 0;
				}
			}
		}
	}

//	printf("decode failed at %d\n", nBytesExtracted);

	if (nBytesExtracted < extractedFileLength)
		return 0;

	return 0;  //shouldn't ever get to here
}

