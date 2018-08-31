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

#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> 

#include "F5crypt.h"
#include "F5crypt.cu"

__device__ int device_strlen(char *str)
{
	if (!str) {
		return 0;
	}

	char *ptr = str;
	while (*str) {
		++str;
	}

	return str - ptr;
}

__device__ void device_decode(int idx, short *coeff, int coeff_len, int * perm_buffer, char * passwords, char * results, int max_msg_len, int max_pass, int max_decode)
{
	char * pass;
	int pass_len;
	f5_rand_state  rstate;
	int * perms = &(perm_buffer[idx * coeff_len]);
	pass = &(passwords[idx * max_pass]);
	pass_len = device_strlen(pass);
	// printf("%d perm: %p trying pass: \"%s\" len %d\n", idx, perms, pass, pass_len);
	F5gen_rand_seed(pass, pass_len, &rstate);
	/*
	printf("initial rands: ");
	for (int offset = 0; offset < 20; offset++) {
		printf("%02x", rstate->output[offset] & 0xff);
	}
	printf("\n");
	*/

	F5permutation(&rstate, perms, coeff_len);
	/*
	for (int j = 0; j < 10; j++) {
		printf("%d %s msg %p [%d] : %p = %d\n", idx, pass, perms, j, &(perms[j]), perms[j]);
	}
	*/

	char *msg = &(results[idx * (max_decode+1)]);
	int msg_len = 0;
	// 4. Attempt extraction
	// Return 1 on success, 0 on failure. On success message and message_len will be modified.
	int ret = F5extract(coeff, coeff_len, perms, &rstate, max_msg_len, msg, &msg_len, max_decode);
	msg[msg_len] = '\0';
	// 5. Write results if password found
	if (ret)
	{
		printf(">>>>> Password Hit: \"%s\" <<<<<\n", pass);
		printf("%s == %s\n", pass, msg);
	}
}

__global__ void decode(short *coeff, int coeff_len, int * perm_buffer, char * passwords, char * results, int max_msg_len, int max_pass, int max_decode)
{
	device_decode(blockIdx.x * blockDim.x + threadIdx.x, coeff, coeff_len, perm_buffer, passwords, results, max_msg_len, max_pass, max_decode);
}

int getline(char line[256], size_t *n, FILE *stream);
int load_coeff(char* filename, short** coeffptr, int* coeff_len, int *max_msg_len);
#define CUDA_ERR_CHECK 			if (cudaStatus != cudaSuccess) { fprintf(stderr, "%d cuda returned error code %d : %s!\n", __LINE__, cudaStatus, cudaGetErrorString(cudaStatus)); return 1; }


void usage()
{
	printf("--- BruthCrackF5CUDA ---\n");
	printf("Reads a provided coefficent dump from a JPEG file (TODO: jpeglib) and tests it\n");
	printf("against a seriesof passwords provided as a password file.\n");
	printf("\nUsage: brutecrackf5 filename [OPTION]...\n\nOptions:\n");
	printf(" --pass FILENAME Password list. Expected to be seperated by new-line charactors.\n");
	printf(" --gpu number\n");
	printf("                 Default: 0\n");
	printf(" --blocks count\n");
	printf("                 Default: 4\n");
	printf(" --threads count\n");
	printf("                 Default: 4\n");
	printf(" --max-pass max length of password\n");
	printf("                 Default: 8\n");
	printf(" --max-decode max number of bytes matching PixelKnot header to decode\n");
	printf("                 Default: 4\n");
	printf(" --suffix try all suffix of each password up to length\n");
	printf("                 Default: 0\n");
	printf(" --skip skip lines of password file\n");
	printf("                 Default: 0\n");

	exit(0);
}



int main(int argc, char** argv)
{
	char  * coeff_file = 0;
	char  * pass_file = 0;

	int n_blocks = 32;
	int n_threads = 32;

	int max_pass = 8;
	int max_decode = 4;
	int suffix_length = 0;
	int skip = 0;
	int gpu_id = 0;
	//Parse Args
	for (int i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "--pass") == 0 || strcmp(argv[i], "-p") == 0)
		{
			if (i + 1 == argc) usage();
			pass_file = argv[++i];
			continue;
		}
		if (strcmp(argv[i], "--gpu") == 0 || strcmp(argv[i], "-g") == 0)
		{
			if (i + 1 == argc) usage();
			skip = strtol(argv[++i], NULL, 10);
			continue;
		}
		if (strcmp(argv[i], "--skip") == 0 || strcmp(argv[i], "-sk") == 0)
		{
			if (i + 1 == argc) usage();
			skip = strtol(argv[++i], NULL, 10);
			continue;
		}
		if (strcmp(argv[i], "--blocks") == 0 || strcmp(argv[i], "-b") == 0)
		{
			if (i + 1 == argc) usage();
			n_blocks = strtol(argv[++i], NULL, 10);
			continue;
		}
		if (strcmp(argv[i], "--threads") == 0 || strcmp(argv[i], "-t") == 0)
		{
			if (i + 1 == argc) usage();
			n_threads = strtol(argv[++i], NULL, 10);
			continue;
		}
		if (strcmp(argv[i], "--max-pass") == 0 || strcmp(argv[i], "-mp") == 0)
		{
			if (i + 1 == argc) usage();
			max_pass = strtol(argv[++i], NULL, 10);
			continue;
		}
		if (strcmp(argv[i], "--max-decode") == 0 || strcmp(argv[i], "-md") == 0)
		{
			if (i + 1 == argc) usage();
			max_decode = strtol(argv[++i], NULL, 10);
			continue;
		}
		if (strcmp(argv[i], "--suffix") == 0 || strcmp(argv[i], "-s") == 0)
		{
			if (i + 1 == argc) usage();
			suffix_length = strtol(argv[++i], NULL, 10);
			continue;
		}

		//fall through

		if (!coeff_file)
		{
			coeff_file = argv[i];
			continue;
		}
		//anything else
		usage();
	}
	if (!coeff_file)
		usage();
	if (!pass_file)
		usage();

	int max_batch = n_blocks * n_threads;

	char * password_buffer;
	char * result_buffer;
	short * coeff_buffer;
	int * perm_buffer;

	short *coeff = 0;                      // coefficent dump from a JPEG file
	int    coeff_len;
	int    max_msg_len;                    // max legit message length
	cudaError_t cudaStatus;

	clock_t start, end;
	float seconds;
	start = clock();

	FILE * fp;
	char line[256];
	size_t len = 0;
	int read;

	printf("setting gpu to %d\n", gpu_id);
	// Choose which GPU to run on, change this on a multi-GPU system.
	cudaStatus = cudaSetDevice(gpu_id);
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaSetDevice failed!  Do you have a CUDA-capable GPU and drivers installed?");
		return 1;
	}

	// load coefs and copy to GPU
	printf("loading coeff file %s\n", coeff_file);
	load_coeff(coeff_file, &coeff, &coeff_len, &max_msg_len);

	printf("allocating memory for batches of %d * (%d coeff + %d pass + %d decode)\n", max_batch, coeff_len, max_pass, max_decode + 1);
	cudaStatus = cudaMalloc(&coeff_buffer, (sizeof(short) * coeff_len)); CUDA_ERR_CHECK;
	cudaStatus = cudaMemcpy(coeff_buffer, coeff, coeff_len * sizeof(short), cudaMemcpyHostToDevice); CUDA_ERR_CHECK;

	// allocate room for passwords and results
	cudaStatus = cudaMalloc(&perm_buffer, (sizeof(int) * max_batch * coeff_len)); CUDA_ERR_CHECK;
	cudaStatus = cudaMalloc(&password_buffer, (sizeof(char) * max_batch * max_pass)); CUDA_ERR_CHECK;
	cudaStatus = cudaMalloc(&result_buffer, (sizeof(char) * max_batch * (max_decode + 1))); CUDA_ERR_CHECK;

	char * passwords = (char *)malloc(max_batch * max_pass * sizeof(char));
	char * results = (char *)malloc(max_batch * max_decode * sizeof(char));

	printf("opening password file %s\n", pass_file);
	fp = fopen(pass_file, "r");
	if (fp == NULL)
	{
		printf("could not open %s", pass_file);
		exit(EXIT_FAILURE);
	}

	int pass_count = 0;
	int processed = 0;

	if (skip > 0) {
		printf("skipping %d lines\n", skip);
	}

	while (skip-- > 0 && getline(line, &len, fp)) { ; }

	while ((read = getline(line, &len, fp)) != -1) {
//		printf("Retrieved line of length %d :\n", read);
//		printf("%s", line);
		int pass_len = read;
		int off = 0;
		while (pass_len >= suffix_length) {
//			printf("%s %d %d\n", &line[off], pass_len, max_pass);
			if (pass_len < max_pass) {
				memset(&(passwords[pass_count * max_pass]), '\0', max_pass);
				strncpy(&(passwords[pass_count * max_pass]), &line[off], pass_len);
				pass_count++;
				if (pass_count >= max_batch) {
					// printf("batch ready %d\n", pass_count);

					// batch is ready for processing
					cudaStatus = cudaMemcpy(password_buffer, passwords, max_batch * max_pass, cudaMemcpyHostToDevice); CUDA_ERR_CHECK;
					decode << <n_blocks, n_threads >> > (coeff_buffer, coeff_len, perm_buffer, password_buffer, result_buffer, max_msg_len, max_pass, max_decode);
					cudaStatus = cudaGetLastError(); CUDA_ERR_CHECK;
					cudaStatus = cudaDeviceSynchronize(); CUDA_ERR_CHECK;
					pass_count = 0;

					processed += max_batch;
					end = clock();
					seconds = end - start; // time difference is now a float
					seconds /= CLOCKS_PER_SEC; // this division is now floating point
					printf("processed %d pass in %.02f seconds = %.02f pass/sec @ %s\n", processed, seconds, processed / seconds, line);
				}
			}
//			else { printf("skipping %s,too long\n", &line[off]); }
			if (suffix_length == 0) { 
				// 0 means no suffixing
				pass_len = 0;
			}
			pass_len--;
			off++;
		}
	}

	if (pass_count > 0) {
		processed += pass_count;
		while (pass_count < max_batch) {
			memset(&(passwords[pass_count * max_pass]), '\0', max_pass);
			pass_count++;
		}
		cudaStatus = cudaMemcpy(password_buffer, passwords, max_batch * max_pass, cudaMemcpyHostToDevice); CUDA_ERR_CHECK;
		decode << <n_blocks, n_threads >> > (coeff_buffer, coeff_len, perm_buffer, password_buffer, result_buffer, max_msg_len, max_pass, max_decode);
		cudaStatus = cudaGetLastError(); CUDA_ERR_CHECK;
		cudaStatus = cudaDeviceSynchronize(); CUDA_ERR_CHECK;
		end = clock();
		seconds = end - start; // time difference is now a float
		seconds /= CLOCKS_PER_SEC; // this division is now floating point
		printf("processed %d pass in %.02f seconds = %.02f pass/sec complete\n", processed, seconds, processed / seconds);
	}

	printf("done\n");

	fclose(fp);

	cudaFree(coeff_buffer);
	cudaFree(perm_buffer);
	cudaFree(password_buffer);
	cudaFree(result_buffer);

	return 1;
}

int load_coeff(char* filename, short** coeffptr, int* coeff_len, int *max_msg_len)
{
	FILE *fp;
	short *coeff = 0;

	fp = fopen(filename, "rb");
	if (!fp)
	{
		fputs("File not found\n", stderr);
		return 1;
	}
	fseek(fp, 0, SEEK_END);
	*coeff_len = ftell(fp) / 2;
	rewind(fp);

	printf("File: %s   %i bytes.\n", filename, *coeff_len * 2);

	coeff = (short *)malloc(*coeff_len * sizeof(short));
	*coeffptr = coeff; //export the pointer

	if (fread(coeff, 2, *coeff_len, fp) != *coeff_len)
	{
		fputs("File error\n", stderr);
		return 1;
	}

	*max_msg_len = 0;
	for (int i = 0; i < *coeff_len; i++)
		if ((i % 64 != 0) & (coeff[i] != 0))
			(*max_msg_len)++;

	printf("Max theoretical message length: %i\n", *max_msg_len);
	return 0;
}

int getline(char line[256], size_t *n, FILE *stream)
{
	char *ptr;
	size_t len;

	if (ferror(stream))
		return -1;

	if (feof(stream))
		return -1;

	fgets(line, 256, stream);

	ptr = strchr(line, '\n');
	if (ptr)
		*ptr = '\0';

	len = strlen(line);

	return((int)len);
}
