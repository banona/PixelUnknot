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

// important notes on this:
// input buf unused bytes needs to be set to zero
// input buf needs to be in algorithm native byte order (md5 = LE, sha1 = BE, etc)
// input buf needs to be 64 byte aligned when using md5_update()
//#include "hash_common.cu"
//#include "hash_functions.cu"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t   u32;
typedef uint64_t  u64;

#define IS_NV 1
#define CUDA_ARCH 350

/*
__device__ uint32_t rotate(uint32_t input, unsigned amount)
{
	// With constant amount, the left/right masks are constants
	uint32_t rmask = 0xFF >> ((8 - amount) & 7);
	rmask = (rmask << 24 | rmask << 16 | rmask << 8 | rmask);
	uint32_t lmask = ~rmask;

	uint32_t lshift = input << amount;
	lshift &= lmask;
	if (amount == 1) {  // special case left-shift by 1 using an in-lane add instead of shift&mask
		lshift = __vadd4(input, input);
	}
	uint32_t rshift = input >> ((8 - amount) & 7);
	rshift &= rmask;

	uint32_t rotated = lshift | rshift;
	return rotated;
}
*/

__device__ u32 rotate(u32 n, unsigned int c)
{
	const unsigned int mask = (CHAR_BIT * sizeof(n) - 1);  // assumes width is a power of 2.

	// assert ( (c<=mask) &&"rotate by type width or more");
	c &= mask;
	return (n << c) | (n >> ((-c)&mask));
}
/*
__device__ u32 rotate(u32 var, u32 hops) {
	return (var << hops) | (var >> ((32 - hops) & 31));
}
*/
__device__ u32 rotl32_S (const u32 a, const u32 n)
{
  return rotate (a, n);
}

__device__ u32 hc_add3_S(const u32 a, const u32 b, const u32 c)
{
	return a + b + c;
}

#define SHA1_F0(x,y,z)  ((z) ^ ((x) & ((y) ^ (z))))
#define SHA1_F1(x,y,z)  ((x) ^ (y) ^ (z))
#define SHA1_F2(x,y,z)  (((x) & (y)) | ((z) & ((x) ^ (y))))
#define SHA1_F0o(x,y,z) (SHA1_F0 ((x), (y), (z)))
#define SHA1_F2o(x,y,z) (SHA1_F2 ((x), (y), (z)))

#define SHA1_STEP_S(f,a,b,c,d,e,x)    \
{                                     \
  e += K;                             \
  e  = hc_add3_S (e, x, f (b, c, d)); \
  e += rotl32_S (a,  5u);             \
  b  = rotl32_S (b, 30u);             \
}

#define SHA1_STEP(f,a,b,c,d,e,x)    \
{                                   \
  e += K;                           \
  e  = hc_add3 (e, x, f (b, c, d)); \
  e += rotl32 (a,  5u);             \
  b  = rotl32 (b, 30u);             \
}
typedef enum sha1_constants
{
	SHA1M_A = 0x67452301,
	SHA1M_B = 0xefcdab89,
	SHA1M_C = 0x98badcfe,
	SHA1M_D = 0x10325476,
	SHA1M_E = 0xc3d2e1f0,

	SHA1C00 = 0x5a827999,
	SHA1C01 = 0x6ed9eba1,
	SHA1C02 = 0x8f1bbcdc,
	SHA1C03 = 0xca62c1d6u

} sha1_constants_t;

typedef struct sha1_ctx
{
  u32 h[5];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int len;

} sha1_ctx_t;

__device__ void sha1_transform (const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, u32 *digest)
{
	/*
	printf("hash sha1 transform @ %02x%02x%02x%02x%02x ", digest[0], digest[1], digest[2], digest[3], digest[4]);
	for (int i = 0; i < 16; i++)
	{
		printf("%02x", ((w0[i >> 2] >> ((3 - (i & 3)) * 8)) & 255));
	}
	for (int i = 0; i < 16; i++)
	{
		printf("%02x", ((w1[i >> 2] >> ((3 - (i & 3)) * 8)) & 255));
	}
	for (int i = 0; i < 16; i++)
	{
		printf("%02x", ((w2[i >> 2] >> ((3 - (i & 3)) * 8)) & 255));
	}
	for (int i = 0; i < 16; i++)
	{
		printf("%02x", ((w3[i >> 2] >> ((3 - (i & 3)) * 8)) & 255));
	}
	printf("\n");
	*/
  u32 a = digest[0];
  u32 b = digest[1];
  u32 c = digest[2];
  u32 d = digest[3];
  u32 e = digest[4];

  u32 w0_t = w0[0];
  u32 w1_t = w0[1];
  u32 w2_t = w0[2];
  u32 w3_t = w0[3];
  u32 w4_t = w1[0];
  u32 w5_t = w1[1];
  u32 w6_t = w1[2];
  u32 w7_t = w1[3];
  u32 w8_t = w2[0];
  u32 w9_t = w2[1];
  u32 wa_t = w2[2];
  u32 wb_t = w2[3];
  u32 wc_t = w3[0];
  u32 wd_t = w3[1];
  u32 we_t = w3[2];
  u32 wf_t = w3[3];

  #define K SHA1C00

  SHA1_STEP_S (SHA1_F0o, a, b, c, d, e, w0_t);
  SHA1_STEP_S (SHA1_F0o, e, a, b, c, d, w1_t);
  SHA1_STEP_S (SHA1_F0o, d, e, a, b, c, w2_t);
  SHA1_STEP_S (SHA1_F0o, c, d, e, a, b, w3_t);
  SHA1_STEP_S (SHA1_F0o, b, c, d, e, a, w4_t);
  SHA1_STEP_S (SHA1_F0o, a, b, c, d, e, w5_t);
  SHA1_STEP_S (SHA1_F0o, e, a, b, c, d, w6_t);
  SHA1_STEP_S (SHA1_F0o, d, e, a, b, c, w7_t);
  SHA1_STEP_S (SHA1_F0o, c, d, e, a, b, w8_t);
  SHA1_STEP_S (SHA1_F0o, b, c, d, e, a, w9_t);
  SHA1_STEP_S (SHA1_F0o, a, b, c, d, e, wa_t);
  SHA1_STEP_S (SHA1_F0o, e, a, b, c, d, wb_t);
  SHA1_STEP_S (SHA1_F0o, d, e, a, b, c, wc_t);
  SHA1_STEP_S (SHA1_F0o, c, d, e, a, b, wd_t);
  SHA1_STEP_S (SHA1_F0o, b, c, d, e, a, we_t);
  SHA1_STEP_S (SHA1_F0o, a, b, c, d, e, wf_t);
  w0_t = rotl32_S ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP_S (SHA1_F0o, e, a, b, c, d, w0_t);
  w1_t = rotl32_S ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP_S (SHA1_F0o, d, e, a, b, c, w1_t);
  w2_t = rotl32_S ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP_S (SHA1_F0o, c, d, e, a, b, w2_t);
  w3_t = rotl32_S ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP_S (SHA1_F0o, b, c, d, e, a, w3_t);

  #undef K
  #define K SHA1C01

  w4_t = rotl32_S ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w4_t);
  w5_t = rotl32_S ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w5_t);
  w6_t = rotl32_S ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w6_t);
  w7_t = rotl32_S ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w7_t);
  w8_t = rotl32_S ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w8_t);
  w9_t = rotl32_S ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w9_t);
  wa_t = rotl32_S ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, wa_t);
  wb_t = rotl32_S ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, wb_t);
  wc_t = rotl32_S ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, wc_t);
  wd_t = rotl32_S ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, wd_t);
  we_t = rotl32_S ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, we_t);
  wf_t = rotl32_S ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, wf_t);
  w0_t = rotl32_S ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w0_t);
  w1_t = rotl32_S ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w1_t);
  w2_t = rotl32_S ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w2_t);
  w3_t = rotl32_S ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w3_t);
  w4_t = rotl32_S ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w4_t);
  w5_t = rotl32_S ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w5_t);
  w6_t = rotl32_S ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w6_t);
  w7_t = rotl32_S ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w7_t);

  #undef K
  #define K SHA1C02

  w8_t = rotl32_S ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP_S (SHA1_F2o, a, b, c, d, e, w8_t);
  w9_t = rotl32_S ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP_S (SHA1_F2o, e, a, b, c, d, w9_t);
  wa_t = rotl32_S ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP_S (SHA1_F2o, d, e, a, b, c, wa_t);
  wb_t = rotl32_S ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP_S (SHA1_F2o, c, d, e, a, b, wb_t);
  wc_t = rotl32_S ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP_S (SHA1_F2o, b, c, d, e, a, wc_t);
  wd_t = rotl32_S ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP_S (SHA1_F2o, a, b, c, d, e, wd_t);
  we_t = rotl32_S ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP_S (SHA1_F2o, e, a, b, c, d, we_t);
  wf_t = rotl32_S ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP_S (SHA1_F2o, d, e, a, b, c, wf_t);
  w0_t = rotl32_S ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP_S (SHA1_F2o, c, d, e, a, b, w0_t);
  w1_t = rotl32_S ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP_S (SHA1_F2o, b, c, d, e, a, w1_t);
  w2_t = rotl32_S ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP_S (SHA1_F2o, a, b, c, d, e, w2_t);
  w3_t = rotl32_S ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP_S (SHA1_F2o, e, a, b, c, d, w3_t);
  w4_t = rotl32_S ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP_S (SHA1_F2o, d, e, a, b, c, w4_t);
  w5_t = rotl32_S ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP_S (SHA1_F2o, c, d, e, a, b, w5_t);
  w6_t = rotl32_S ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP_S (SHA1_F2o, b, c, d, e, a, w6_t);
  w7_t = rotl32_S ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP_S (SHA1_F2o, a, b, c, d, e, w7_t);
  w8_t = rotl32_S ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP_S (SHA1_F2o, e, a, b, c, d, w8_t);
  w9_t = rotl32_S ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP_S (SHA1_F2o, d, e, a, b, c, w9_t);
  wa_t = rotl32_S ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP_S (SHA1_F2o, c, d, e, a, b, wa_t);
  wb_t = rotl32_S ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP_S (SHA1_F2o, b, c, d, e, a, wb_t);

  #undef K
  #define K SHA1C03

  wc_t = rotl32_S ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, wc_t);
  wd_t = rotl32_S ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, wd_t);
  we_t = rotl32_S ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, we_t);
  wf_t = rotl32_S ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, wf_t);
  w0_t = rotl32_S ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w0_t);
  w1_t = rotl32_S ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w1_t);
  w2_t = rotl32_S ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w2_t);
  w3_t = rotl32_S ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w3_t);
  w4_t = rotl32_S ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w4_t);
  w5_t = rotl32_S ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w5_t);
  w6_t = rotl32_S ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w6_t);
  w7_t = rotl32_S ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w7_t);
  w8_t = rotl32_S ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w8_t);
  w9_t = rotl32_S ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w9_t);
  wa_t = rotl32_S ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, wa_t);
  wb_t = rotl32_S ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, wb_t);
  wc_t = rotl32_S ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, wc_t);
  wd_t = rotl32_S ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, wd_t);
  we_t = rotl32_S ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, we_t);
  wf_t = rotl32_S ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, wf_t);

  #undef K

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
  digest[4] += e;
}

__device__ void sha1_init (sha1_ctx_t *ctx)
{
  ctx->h[0] = SHA1M_A;
  ctx->h[1] = SHA1M_B;
  ctx->h[2] = SHA1M_C;
  ctx->h[3] = SHA1M_D;
  ctx->h[4] = SHA1M_E;

  ctx->w0[0] = 0;
  ctx->w0[1] = 0;
  ctx->w0[2] = 0;
  ctx->w0[3] = 0;
  ctx->w1[0] = 0;
  ctx->w1[1] = 0;
  ctx->w1[2] = 0;
  ctx->w1[3] = 0;
  ctx->w2[0] = 0;
  ctx->w2[1] = 0;
  ctx->w2[2] = 0;
  ctx->w2[3] = 0;
  ctx->w3[0] = 0;
  ctx->w3[1] = 0;
  ctx->w3[2] = 0;
  ctx->w3[3] = 0;

  ctx->len = 0;
}

__device__ u32 hc_byte_perm_S(const u32 a, const u32 b, const u32 c)
{
	u32 r;

	asm("prmt.b32 %0, %1, %2, %3;" : "=r"(r) : "r"(a), "r"(b), "r"(c));

	return r;
}

__device__ u32 hc_bytealign_S (const u32 a, const u32 b, const u32 c)
{
  u32 r;

  #if CUDA_ARCH >= 350

  asm ("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(r) : "r"(b), "r"(a), "r"((c & 3) * 8));

  #else

  r = hc_byte_perm_S (b, a, (0x76543210 >> ((c & 3) * 4)) & 0xffff);

  #endif

  return r;
}

__device__ void switch_buffer_by_offset_be_S (u32 *w0, u32 *w1, u32 *w2, u32 *w3, const u32 offset)
{
  const int offset_switch = offset / 4;

  #if (defined IS_AMD && AMD_GCN < 3) || defined IS_GENERIC
  switch (offset_switch)
  {
    case  0:
      w3[3] = hc_bytealign_S (w3[2], w3[3], offset);
      w3[2] = hc_bytealign_S (w3[1], w3[2], offset);
      w3[1] = hc_bytealign_S (w3[0], w3[1], offset);
      w3[0] = hc_bytealign_S (w2[3], w3[0], offset);
      w2[3] = hc_bytealign_S (w2[2], w2[3], offset);
      w2[2] = hc_bytealign_S (w2[1], w2[2], offset);
      w2[1] = hc_bytealign_S (w2[0], w2[1], offset);
      w2[0] = hc_bytealign_S (w1[3], w2[0], offset);
      w1[3] = hc_bytealign_S (w1[2], w1[3], offset);
      w1[2] = hc_bytealign_S (w1[1], w1[2], offset);
      w1[1] = hc_bytealign_S (w1[0], w1[1], offset);
      w1[0] = hc_bytealign_S (w0[3], w1[0], offset);
      w0[3] = hc_bytealign_S (w0[2], w0[3], offset);
      w0[2] = hc_bytealign_S (w0[1], w0[2], offset);
      w0[1] = hc_bytealign_S (w0[0], w0[1], offset);
      w0[0] = hc_bytealign_S (    0, w0[0], offset);

      break;

    case  1:
      w3[3] = hc_bytealign_S (w3[1], w3[2], offset);
      w3[2] = hc_bytealign_S (w3[0], w3[1], offset);
      w3[1] = hc_bytealign_S (w2[3], w3[0], offset);
      w3[0] = hc_bytealign_S (w2[2], w2[3], offset);
      w2[3] = hc_bytealign_S (w2[1], w2[2], offset);
      w2[2] = hc_bytealign_S (w2[0], w2[1], offset);
      w2[1] = hc_bytealign_S (w1[3], w2[0], offset);
      w2[0] = hc_bytealign_S (w1[2], w1[3], offset);
      w1[3] = hc_bytealign_S (w1[1], w1[2], offset);
      w1[2] = hc_bytealign_S (w1[0], w1[1], offset);
      w1[1] = hc_bytealign_S (w0[3], w1[0], offset);
      w1[0] = hc_bytealign_S (w0[2], w0[3], offset);
      w0[3] = hc_bytealign_S (w0[1], w0[2], offset);
      w0[2] = hc_bytealign_S (w0[0], w0[1], offset);
      w0[1] = hc_bytealign_S (    0, w0[0], offset);
      w0[0] = 0;

      break;

    case  2:
      w3[3] = hc_bytealign_S (w3[0], w3[1], offset);
      w3[2] = hc_bytealign_S (w2[3], w3[0], offset);
      w3[1] = hc_bytealign_S (w2[2], w2[3], offset);
      w3[0] = hc_bytealign_S (w2[1], w2[2], offset);
      w2[3] = hc_bytealign_S (w2[0], w2[1], offset);
      w2[2] = hc_bytealign_S (w1[3], w2[0], offset);
      w2[1] = hc_bytealign_S (w1[2], w1[3], offset);
      w2[0] = hc_bytealign_S (w1[1], w1[2], offset);
      w1[3] = hc_bytealign_S (w1[0], w1[1], offset);
      w1[2] = hc_bytealign_S (w0[3], w1[0], offset);
      w1[1] = hc_bytealign_S (w0[2], w0[3], offset);
      w1[0] = hc_bytealign_S (w0[1], w0[2], offset);
      w0[3] = hc_bytealign_S (w0[0], w0[1], offset);
      w0[2] = hc_bytealign_S (    0, w0[0], offset);
      w0[1] = 0;
      w0[0] = 0;

      break;

    case  3:
      w3[3] = hc_bytealign_S (w2[3], w3[0], offset);
      w3[2] = hc_bytealign_S (w2[2], w2[3], offset);
      w3[1] = hc_bytealign_S (w2[1], w2[2], offset);
      w3[0] = hc_bytealign_S (w2[0], w2[1], offset);
      w2[3] = hc_bytealign_S (w1[3], w2[0], offset);
      w2[2] = hc_bytealign_S (w1[2], w1[3], offset);
      w2[1] = hc_bytealign_S (w1[1], w1[2], offset);
      w2[0] = hc_bytealign_S (w1[0], w1[1], offset);
      w1[3] = hc_bytealign_S (w0[3], w1[0], offset);
      w1[2] = hc_bytealign_S (w0[2], w0[3], offset);
      w1[1] = hc_bytealign_S (w0[1], w0[2], offset);
      w1[0] = hc_bytealign_S (w0[0], w0[1], offset);
      w0[3] = hc_bytealign_S (    0, w0[0], offset);
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case  4:
      w3[3] = hc_bytealign_S (w2[2], w2[3], offset);
      w3[2] = hc_bytealign_S (w2[1], w2[2], offset);
      w3[1] = hc_bytealign_S (w2[0], w2[1], offset);
      w3[0] = hc_bytealign_S (w1[3], w2[0], offset);
      w2[3] = hc_bytealign_S (w1[2], w1[3], offset);
      w2[2] = hc_bytealign_S (w1[1], w1[2], offset);
      w2[1] = hc_bytealign_S (w1[0], w1[1], offset);
      w2[0] = hc_bytealign_S (w0[3], w1[0], offset);
      w1[3] = hc_bytealign_S (w0[2], w0[3], offset);
      w1[2] = hc_bytealign_S (w0[1], w0[2], offset);
      w1[1] = hc_bytealign_S (w0[0], w0[1], offset);
      w1[0] = hc_bytealign_S (    0, w0[0], offset);
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case  5:
      w3[3] = hc_bytealign_S (w2[1], w2[2], offset);
      w3[2] = hc_bytealign_S (w2[0], w2[1], offset);
      w3[1] = hc_bytealign_S (w1[3], w2[0], offset);
      w3[0] = hc_bytealign_S (w1[2], w1[3], offset);
      w2[3] = hc_bytealign_S (w1[1], w1[2], offset);
      w2[2] = hc_bytealign_S (w1[0], w1[1], offset);
      w2[1] = hc_bytealign_S (w0[3], w1[0], offset);
      w2[0] = hc_bytealign_S (w0[2], w0[3], offset);
      w1[3] = hc_bytealign_S (w0[1], w0[2], offset);
      w1[2] = hc_bytealign_S (w0[0], w0[1], offset);
      w1[1] = hc_bytealign_S (    0, w0[0], offset);
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case  6:
      w3[3] = hc_bytealign_S (w2[0], w2[1], offset);
      w3[2] = hc_bytealign_S (w1[3], w2[0], offset);
      w3[1] = hc_bytealign_S (w1[2], w1[3], offset);
      w3[0] = hc_bytealign_S (w1[1], w1[2], offset);
      w2[3] = hc_bytealign_S (w1[0], w1[1], offset);
      w2[2] = hc_bytealign_S (w0[3], w1[0], offset);
      w2[1] = hc_bytealign_S (w0[2], w0[3], offset);
      w2[0] = hc_bytealign_S (w0[1], w0[2], offset);
      w1[3] = hc_bytealign_S (w0[0], w0[1], offset);
      w1[2] = hc_bytealign_S (    0, w0[0], offset);
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case  7:
      w3[3] = hc_bytealign_S (w1[3], w2[0], offset);
      w3[2] = hc_bytealign_S (w1[2], w1[3], offset);
      w3[1] = hc_bytealign_S (w1[1], w1[2], offset);
      w3[0] = hc_bytealign_S (w1[0], w1[1], offset);
      w2[3] = hc_bytealign_S (w0[3], w1[0], offset);
      w2[2] = hc_bytealign_S (w0[2], w0[3], offset);
      w2[1] = hc_bytealign_S (w0[1], w0[2], offset);
      w2[0] = hc_bytealign_S (w0[0], w0[1], offset);
      w1[3] = hc_bytealign_S (    0, w0[0], offset);
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case  8:
      w3[3] = hc_bytealign_S (w1[2], w1[3], offset);
      w3[2] = hc_bytealign_S (w1[1], w1[2], offset);
      w3[1] = hc_bytealign_S (w1[0], w1[1], offset);
      w3[0] = hc_bytealign_S (w0[3], w1[0], offset);
      w2[3] = hc_bytealign_S (w0[2], w0[3], offset);
      w2[2] = hc_bytealign_S (w0[1], w0[2], offset);
      w2[1] = hc_bytealign_S (w0[0], w0[1], offset);
      w2[0] = hc_bytealign_S (    0, w0[0], offset);
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case  9:
      w3[3] = hc_bytealign_S (w1[1], w1[2], offset);
      w3[2] = hc_bytealign_S (w1[0], w1[1], offset);
      w3[1] = hc_bytealign_S (w0[3], w1[0], offset);
      w3[0] = hc_bytealign_S (w0[2], w0[3], offset);
      w2[3] = hc_bytealign_S (w0[1], w0[2], offset);
      w2[2] = hc_bytealign_S (w0[0], w0[1], offset);
      w2[1] = hc_bytealign_S (    0, w0[0], offset);
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 10:
      w3[3] = hc_bytealign_S (w1[0], w1[1], offset);
      w3[2] = hc_bytealign_S (w0[3], w1[0], offset);
      w3[1] = hc_bytealign_S (w0[2], w0[3], offset);
      w3[0] = hc_bytealign_S (w0[1], w0[2], offset);
      w2[3] = hc_bytealign_S (w0[0], w0[1], offset);
      w2[2] = hc_bytealign_S (    0, w0[0], offset);
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 11:
      w3[3] = hc_bytealign_S (w0[3], w1[0], offset);
      w3[2] = hc_bytealign_S (w0[2], w0[3], offset);
      w3[1] = hc_bytealign_S (w0[1], w0[2], offset);
      w3[0] = hc_bytealign_S (w0[0], w0[1], offset);
      w2[3] = hc_bytealign_S (    0, w0[0], offset);
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 12:
      w3[3] = hc_bytealign_S (w0[2], w0[3], offset);
      w3[2] = hc_bytealign_S (w0[1], w0[2], offset);
      w3[1] = hc_bytealign_S (w0[0], w0[1], offset);
      w3[0] = hc_bytealign_S (    0, w0[0], offset);
      w2[3] = 0;
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 13:
      w3[3] = hc_bytealign_S (w0[1], w0[2], offset);
      w3[2] = hc_bytealign_S (w0[0], w0[1], offset);
      w3[1] = hc_bytealign_S (    0, w0[0], offset);
      w3[0] = 0;
      w2[3] = 0;
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 14:
      w3[3] = hc_bytealign_S (w0[0], w0[1], offset);
      w3[2] = hc_bytealign_S (    0, w0[0], offset);
      w3[1] = 0;
      w3[0] = 0;
      w2[3] = 0;
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 15:
      w3[3] = hc_bytealign_S (    0, w0[0], offset);
      w3[2] = 0;
      w3[1] = 0;
      w3[0] = 0;
      w2[3] = 0;
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;
  }
  #endif

  #if (defined IS_AMD && AMD_GCN >= 3) || defined IS_NV

  #if defined IS_NV
  const int selector = (0x76543210 >> ((offset & 3) * 4)) & 0xffff;
  #endif

  #if defined IS_AMD
  const int selector = 0x0706050403020100 >> ((offset & 3) * 8);
  #endif

  switch (offset_switch)
  {
    case  0:
      w3[3] = hc_byte_perm_S (w3[3], w3[2], selector);
      w3[2] = hc_byte_perm_S (w3[2], w3[1], selector);
      w3[1] = hc_byte_perm_S (w3[1], w3[0], selector);
      w3[0] = hc_byte_perm_S (w3[0], w2[3], selector);
      w2[3] = hc_byte_perm_S (w2[3], w2[2], selector);
      w2[2] = hc_byte_perm_S (w2[2], w2[1], selector);
      w2[1] = hc_byte_perm_S (w2[1], w2[0], selector);
      w2[0] = hc_byte_perm_S (w2[0], w1[3], selector);
      w1[3] = hc_byte_perm_S (w1[3], w1[2], selector);
      w1[2] = hc_byte_perm_S (w1[2], w1[1], selector);
      w1[1] = hc_byte_perm_S (w1[1], w1[0], selector);
      w1[0] = hc_byte_perm_S (w1[0], w0[3], selector);
      w0[3] = hc_byte_perm_S (w0[3], w0[2], selector);
      w0[2] = hc_byte_perm_S (w0[2], w0[1], selector);
      w0[1] = hc_byte_perm_S (w0[1], w0[0], selector);
      w0[0] = hc_byte_perm_S (w0[0],     0, selector);

      break;

    case  1:
      w3[3] = hc_byte_perm_S (w3[2], w3[1], selector);
      w3[2] = hc_byte_perm_S (w3[1], w3[0], selector);
      w3[1] = hc_byte_perm_S (w3[0], w2[3], selector);
      w3[0] = hc_byte_perm_S (w2[3], w2[2], selector);
      w2[3] = hc_byte_perm_S (w2[2], w2[1], selector);
      w2[2] = hc_byte_perm_S (w2[1], w2[0], selector);
      w2[1] = hc_byte_perm_S (w2[0], w1[3], selector);
      w2[0] = hc_byte_perm_S (w1[3], w1[2], selector);
      w1[3] = hc_byte_perm_S (w1[2], w1[1], selector);
      w1[2] = hc_byte_perm_S (w1[1], w1[0], selector);
      w1[1] = hc_byte_perm_S (w1[0], w0[3], selector);
      w1[0] = hc_byte_perm_S (w0[3], w0[2], selector);
      w0[3] = hc_byte_perm_S (w0[2], w0[1], selector);
      w0[2] = hc_byte_perm_S (w0[1], w0[0], selector);
      w0[1] = hc_byte_perm_S (w0[0],     0, selector);
      w0[0] = 0;

      break;

    case  2:
      w3[3] = hc_byte_perm_S (w3[1], w3[0], selector);
      w3[2] = hc_byte_perm_S (w3[0], w2[3], selector);
      w3[1] = hc_byte_perm_S (w2[3], w2[2], selector);
      w3[0] = hc_byte_perm_S (w2[2], w2[1], selector);
      w2[3] = hc_byte_perm_S (w2[1], w2[0], selector);
      w2[2] = hc_byte_perm_S (w2[0], w1[3], selector);
      w2[1] = hc_byte_perm_S (w1[3], w1[2], selector);
      w2[0] = hc_byte_perm_S (w1[2], w1[1], selector);
      w1[3] = hc_byte_perm_S (w1[1], w1[0], selector);
      w1[2] = hc_byte_perm_S (w1[0], w0[3], selector);
      w1[1] = hc_byte_perm_S (w0[3], w0[2], selector);
      w1[0] = hc_byte_perm_S (w0[2], w0[1], selector);
      w0[3] = hc_byte_perm_S (w0[1], w0[0], selector);
      w0[2] = hc_byte_perm_S (w0[0],     0, selector);
      w0[1] = 0;
      w0[0] = 0;

      break;

    case  3:
      w3[3] = hc_byte_perm_S (w3[0], w2[3], selector);
      w3[2] = hc_byte_perm_S (w2[3], w2[2], selector);
      w3[1] = hc_byte_perm_S (w2[2], w2[1], selector);
      w3[0] = hc_byte_perm_S (w2[1], w2[0], selector);
      w2[3] = hc_byte_perm_S (w2[0], w1[3], selector);
      w2[2] = hc_byte_perm_S (w1[3], w1[2], selector);
      w2[1] = hc_byte_perm_S (w1[2], w1[1], selector);
      w2[0] = hc_byte_perm_S (w1[1], w1[0], selector);
      w1[3] = hc_byte_perm_S (w1[0], w0[3], selector);
      w1[2] = hc_byte_perm_S (w0[3], w0[2], selector);
      w1[1] = hc_byte_perm_S (w0[2], w0[1], selector);
      w1[0] = hc_byte_perm_S (w0[1], w0[0], selector);
      w0[3] = hc_byte_perm_S (w0[0],     0, selector);
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case  4:
      w3[3] = hc_byte_perm_S (w2[3], w2[2], selector);
      w3[2] = hc_byte_perm_S (w2[2], w2[1], selector);
      w3[1] = hc_byte_perm_S (w2[1], w2[0], selector);
      w3[0] = hc_byte_perm_S (w2[0], w1[3], selector);
      w2[3] = hc_byte_perm_S (w1[3], w1[2], selector);
      w2[2] = hc_byte_perm_S (w1[2], w1[1], selector);
      w2[1] = hc_byte_perm_S (w1[1], w1[0], selector);
      w2[0] = hc_byte_perm_S (w1[0], w0[3], selector);
      w1[3] = hc_byte_perm_S (w0[3], w0[2], selector);
      w1[2] = hc_byte_perm_S (w0[2], w0[1], selector);
      w1[1] = hc_byte_perm_S (w0[1], w0[0], selector);
      w1[0] = hc_byte_perm_S (w0[0],     0, selector);
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case  5:
      w3[3] = hc_byte_perm_S (w2[2], w2[1], selector);
      w3[2] = hc_byte_perm_S (w2[1], w2[0], selector);
      w3[1] = hc_byte_perm_S (w2[0], w1[3], selector);
      w3[0] = hc_byte_perm_S (w1[3], w1[2], selector);
      w2[3] = hc_byte_perm_S (w1[2], w1[1], selector);
      w2[2] = hc_byte_perm_S (w1[1], w1[0], selector);
      w2[1] = hc_byte_perm_S (w1[0], w0[3], selector);
      w2[0] = hc_byte_perm_S (w0[3], w0[2], selector);
      w1[3] = hc_byte_perm_S (w0[2], w0[1], selector);
      w1[2] = hc_byte_perm_S (w0[1], w0[0], selector);
      w1[1] = hc_byte_perm_S (w0[0],     0, selector);
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case  6:
      w3[3] = hc_byte_perm_S (w2[1], w2[0], selector);
      w3[2] = hc_byte_perm_S (w2[0], w1[3], selector);
      w3[1] = hc_byte_perm_S (w1[3], w1[2], selector);
      w3[0] = hc_byte_perm_S (w1[2], w1[1], selector);
      w2[3] = hc_byte_perm_S (w1[1], w1[0], selector);
      w2[2] = hc_byte_perm_S (w1[0], w0[3], selector);
      w2[1] = hc_byte_perm_S (w0[3], w0[2], selector);
      w2[0] = hc_byte_perm_S (w0[2], w0[1], selector);
      w1[3] = hc_byte_perm_S (w0[1], w0[0], selector);
      w1[2] = hc_byte_perm_S (w0[0],     0, selector);
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case  7:
      w3[3] = hc_byte_perm_S (w2[0], w1[3], selector);
      w3[2] = hc_byte_perm_S (w1[3], w1[2], selector);
      w3[1] = hc_byte_perm_S (w1[2], w1[1], selector);
      w3[0] = hc_byte_perm_S (w1[1], w1[0], selector);
      w2[3] = hc_byte_perm_S (w1[0], w0[3], selector);
      w2[2] = hc_byte_perm_S (w0[3], w0[2], selector);
      w2[1] = hc_byte_perm_S (w0[2], w0[1], selector);
      w2[0] = hc_byte_perm_S (w0[1], w0[0], selector);
      w1[3] = hc_byte_perm_S (w0[0],     0, selector);
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case  8:
      w3[3] = hc_byte_perm_S (w1[3], w1[2], selector);
      w3[2] = hc_byte_perm_S (w1[2], w1[1], selector);
      w3[1] = hc_byte_perm_S (w1[1], w1[0], selector);
      w3[0] = hc_byte_perm_S (w1[0], w0[3], selector);
      w2[3] = hc_byte_perm_S (w0[3], w0[2], selector);
      w2[2] = hc_byte_perm_S (w0[2], w0[1], selector);
      w2[1] = hc_byte_perm_S (w0[1], w0[0], selector);
      w2[0] = hc_byte_perm_S (w0[0],     0, selector);
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case  9:
      w3[3] = hc_byte_perm_S (w1[2], w1[1], selector);
      w3[2] = hc_byte_perm_S (w1[1], w1[0], selector);
      w3[1] = hc_byte_perm_S (w1[0], w0[3], selector);
      w3[0] = hc_byte_perm_S (w0[3], w0[2], selector);
      w2[3] = hc_byte_perm_S (w0[2], w0[1], selector);
      w2[2] = hc_byte_perm_S (w0[1], w0[0], selector);
      w2[1] = hc_byte_perm_S (w0[0],     0, selector);
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 10:
      w3[3] = hc_byte_perm_S (w1[1], w1[0], selector);
      w3[2] = hc_byte_perm_S (w1[0], w0[3], selector);
      w3[1] = hc_byte_perm_S (w0[3], w0[2], selector);
      w3[0] = hc_byte_perm_S (w0[2], w0[1], selector);
      w2[3] = hc_byte_perm_S (w0[1], w0[0], selector);
      w2[2] = hc_byte_perm_S (w0[0],     0, selector);
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 11:
      w3[3] = hc_byte_perm_S (w1[0], w0[3], selector);
      w3[2] = hc_byte_perm_S (w0[3], w0[2], selector);
      w3[1] = hc_byte_perm_S (w0[2], w0[1], selector);
      w3[0] = hc_byte_perm_S (w0[1], w0[0], selector);
      w2[3] = hc_byte_perm_S (w0[0],     0, selector);
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 12:
      w3[3] = hc_byte_perm_S (w0[3], w0[2], selector);
      w3[2] = hc_byte_perm_S (w0[2], w0[1], selector);
      w3[1] = hc_byte_perm_S (w0[1], w0[0], selector);
      w3[0] = hc_byte_perm_S (w0[0],     0, selector);
      w2[3] = 0;
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 13:
      w3[3] = hc_byte_perm_S (w0[2], w0[1], selector);
      w3[2] = hc_byte_perm_S (w0[1], w0[0], selector);
      w3[1] = hc_byte_perm_S (w0[0],     0, selector);
      w3[0] = 0;
      w2[3] = 0;
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 14:
      w3[3] = hc_byte_perm_S (w0[1], w0[0], selector);
      w3[2] = hc_byte_perm_S (w0[0],     0, selector);
      w3[1] = 0;
      w3[0] = 0;
      w2[3] = 0;
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 15:
      w3[3] = hc_byte_perm_S (w0[0],     0, selector);
      w3[2] = 0;
      w3[1] = 0;
      w3[0] = 0;
      w2[3] = 0;
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;
  }
  #endif
}

__device__ void switch_buffer_by_offset_carry_be_S (u32 *w0, u32 *w1, u32 *w2, u32 *w3, u32 *c0, u32 *c1, u32 *c2, u32 *c3, const u32 offset)
{
  const int offset_switch = offset / 4;

  #if (defined IS_AMD && AMD_GCN < 3) || defined IS_GENERIC
  switch (offset_switch)
  {
    case  0:
      c0[0] = hc_bytealign_S (w3[3],     0, offset);
      w3[3] = hc_bytealign_S (w3[2], w3[3], offset);
      w3[2] = hc_bytealign_S (w3[1], w3[2], offset);
      w3[1] = hc_bytealign_S (w3[0], w3[1], offset);
      w3[0] = hc_bytealign_S (w2[3], w3[0], offset);
      w2[3] = hc_bytealign_S (w2[2], w2[3], offset);
      w2[2] = hc_bytealign_S (w2[1], w2[2], offset);
      w2[1] = hc_bytealign_S (w2[0], w2[1], offset);
      w2[0] = hc_bytealign_S (w1[3], w2[0], offset);
      w1[3] = hc_bytealign_S (w1[2], w1[3], offset);
      w1[2] = hc_bytealign_S (w1[1], w1[2], offset);
      w1[1] = hc_bytealign_S (w1[0], w1[1], offset);
      w1[0] = hc_bytealign_S (w0[3], w1[0], offset);
      w0[3] = hc_bytealign_S (w0[2], w0[3], offset);
      w0[2] = hc_bytealign_S (w0[1], w0[2], offset);
      w0[1] = hc_bytealign_S (w0[0], w0[1], offset);
      w0[0] = hc_bytealign_S (    0, w0[0], offset);

      break;

    case  1:
      c0[1] = hc_bytealign_S (w3[3],     0, offset);
      c0[0] = hc_bytealign_S (w3[2], w3[3], offset);
      w3[3] = hc_bytealign_S (w3[1], w3[2], offset);
      w3[2] = hc_bytealign_S (w3[0], w3[1], offset);
      w3[1] = hc_bytealign_S (w2[3], w3[0], offset);
      w3[0] = hc_bytealign_S (w2[2], w2[3], offset);
      w2[3] = hc_bytealign_S (w2[1], w2[2], offset);
      w2[2] = hc_bytealign_S (w2[0], w2[1], offset);
      w2[1] = hc_bytealign_S (w1[3], w2[0], offset);
      w2[0] = hc_bytealign_S (w1[2], w1[3], offset);
      w1[3] = hc_bytealign_S (w1[1], w1[2], offset);
      w1[2] = hc_bytealign_S (w1[0], w1[1], offset);
      w1[1] = hc_bytealign_S (w0[3], w1[0], offset);
      w1[0] = hc_bytealign_S (w0[2], w0[3], offset);
      w0[3] = hc_bytealign_S (w0[1], w0[2], offset);
      w0[2] = hc_bytealign_S (w0[0], w0[1], offset);
      w0[1] = hc_bytealign_S (    0, w0[0], offset);
      w0[0] = 0;

      break;

    case  2:
      c0[2] = hc_bytealign_S (w3[3],     0, offset);
      c0[1] = hc_bytealign_S (w3[2], w3[3], offset);
      c0[0] = hc_bytealign_S (w3[1], w3[2], offset);
      w3[3] = hc_bytealign_S (w3[0], w3[1], offset);
      w3[2] = hc_bytealign_S (w2[3], w3[0], offset);
      w3[1] = hc_bytealign_S (w2[2], w2[3], offset);
      w3[0] = hc_bytealign_S (w2[1], w2[2], offset);
      w2[3] = hc_bytealign_S (w2[0], w2[1], offset);
      w2[2] = hc_bytealign_S (w1[3], w2[0], offset);
      w2[1] = hc_bytealign_S (w1[2], w1[3], offset);
      w2[0] = hc_bytealign_S (w1[1], w1[2], offset);
      w1[3] = hc_bytealign_S (w1[0], w1[1], offset);
      w1[2] = hc_bytealign_S (w0[3], w1[0], offset);
      w1[1] = hc_bytealign_S (w0[2], w0[3], offset);
      w1[0] = hc_bytealign_S (w0[1], w0[2], offset);
      w0[3] = hc_bytealign_S (w0[0], w0[1], offset);
      w0[2] = hc_bytealign_S (    0, w0[0], offset);
      w0[1] = 0;
      w0[0] = 0;

      break;

    case  3:
      c0[3] = hc_bytealign_S (w3[3],     0, offset);
      c0[2] = hc_bytealign_S (w3[2], w3[3], offset);
      c0[1] = hc_bytealign_S (w3[1], w3[2], offset);
      c0[0] = hc_bytealign_S (w3[0], w3[1], offset);
      w3[3] = hc_bytealign_S (w2[3], w3[0], offset);
      w3[2] = hc_bytealign_S (w2[2], w2[3], offset);
      w3[1] = hc_bytealign_S (w2[1], w2[2], offset);
      w3[0] = hc_bytealign_S (w2[0], w2[1], offset);
      w2[3] = hc_bytealign_S (w1[3], w2[0], offset);
      w2[2] = hc_bytealign_S (w1[2], w1[3], offset);
      w2[1] = hc_bytealign_S (w1[1], w1[2], offset);
      w2[0] = hc_bytealign_S (w1[0], w1[1], offset);
      w1[3] = hc_bytealign_S (w0[3], w1[0], offset);
      w1[2] = hc_bytealign_S (w0[2], w0[3], offset);
      w1[1] = hc_bytealign_S (w0[1], w0[2], offset);
      w1[0] = hc_bytealign_S (w0[0], w0[1], offset);
      w0[3] = hc_bytealign_S (    0, w0[0], offset);
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case  4:
      c1[0] = hc_bytealign_S (w3[3],     0, offset);
      c0[3] = hc_bytealign_S (w3[2], w3[3], offset);
      c0[2] = hc_bytealign_S (w3[1], w3[2], offset);
      c0[1] = hc_bytealign_S (w3[0], w3[1], offset);
      c0[0] = hc_bytealign_S (w2[3], w3[0], offset);
      w3[3] = hc_bytealign_S (w2[2], w2[3], offset);
      w3[2] = hc_bytealign_S (w2[1], w2[2], offset);
      w3[1] = hc_bytealign_S (w2[0], w2[1], offset);
      w3[0] = hc_bytealign_S (w1[3], w2[0], offset);
      w2[3] = hc_bytealign_S (w1[2], w1[3], offset);
      w2[2] = hc_bytealign_S (w1[1], w1[2], offset);
      w2[1] = hc_bytealign_S (w1[0], w1[1], offset);
      w2[0] = hc_bytealign_S (w0[3], w1[0], offset);
      w1[3] = hc_bytealign_S (w0[2], w0[3], offset);
      w1[2] = hc_bytealign_S (w0[1], w0[2], offset);
      w1[1] = hc_bytealign_S (w0[0], w0[1], offset);
      w1[0] = hc_bytealign_S (    0, w0[0], offset);
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case  5:
      c1[1] = hc_bytealign_S (w3[3],     0, offset);
      c1[0] = hc_bytealign_S (w3[2], w3[3], offset);
      c0[3] = hc_bytealign_S (w3[1], w3[2], offset);
      c0[2] = hc_bytealign_S (w3[0], w3[1], offset);
      c0[1] = hc_bytealign_S (w2[3], w3[0], offset);
      c0[0] = hc_bytealign_S (w2[2], w2[3], offset);
      w3[3] = hc_bytealign_S (w2[1], w2[2], offset);
      w3[2] = hc_bytealign_S (w2[0], w2[1], offset);
      w3[1] = hc_bytealign_S (w1[3], w2[0], offset);
      w3[0] = hc_bytealign_S (w1[2], w1[3], offset);
      w2[3] = hc_bytealign_S (w1[1], w1[2], offset);
      w2[2] = hc_bytealign_S (w1[0], w1[1], offset);
      w2[1] = hc_bytealign_S (w0[3], w1[0], offset);
      w2[0] = hc_bytealign_S (w0[2], w0[3], offset);
      w1[3] = hc_bytealign_S (w0[1], w0[2], offset);
      w1[2] = hc_bytealign_S (w0[0], w0[1], offset);
      w1[1] = hc_bytealign_S (    0, w0[0], offset);
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case  6:
      c1[2] = hc_bytealign_S (w3[3],     0, offset);
      c1[1] = hc_bytealign_S (w3[2], w3[3], offset);
      c1[0] = hc_bytealign_S (w3[1], w3[2], offset);
      c0[3] = hc_bytealign_S (w3[0], w3[1], offset);
      c0[2] = hc_bytealign_S (w2[3], w3[0], offset);
      c0[1] = hc_bytealign_S (w2[2], w2[3], offset);
      c0[0] = hc_bytealign_S (w2[1], w2[2], offset);
      w3[3] = hc_bytealign_S (w2[0], w2[1], offset);
      w3[2] = hc_bytealign_S (w1[3], w2[0], offset);
      w3[1] = hc_bytealign_S (w1[2], w1[3], offset);
      w3[0] = hc_bytealign_S (w1[1], w1[2], offset);
      w2[3] = hc_bytealign_S (w1[0], w1[1], offset);
      w2[2] = hc_bytealign_S (w0[3], w1[0], offset);
      w2[1] = hc_bytealign_S (w0[2], w0[3], offset);
      w2[0] = hc_bytealign_S (w0[1], w0[2], offset);
      w1[3] = hc_bytealign_S (w0[0], w0[1], offset);
      w1[2] = hc_bytealign_S (    0, w0[0], offset);
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case  7:
      c1[3] = hc_bytealign_S (w3[3],     0, offset);
      c1[2] = hc_bytealign_S (w3[2], w3[3], offset);
      c1[1] = hc_bytealign_S (w3[1], w3[2], offset);
      c1[0] = hc_bytealign_S (w3[0], w3[1], offset);
      c0[3] = hc_bytealign_S (w2[3], w3[0], offset);
      c0[2] = hc_bytealign_S (w2[2], w2[3], offset);
      c0[1] = hc_bytealign_S (w2[1], w2[2], offset);
      c0[0] = hc_bytealign_S (w2[0], w2[1], offset);
      w3[3] = hc_bytealign_S (w1[3], w2[0], offset);
      w3[2] = hc_bytealign_S (w1[2], w1[3], offset);
      w3[1] = hc_bytealign_S (w1[1], w1[2], offset);
      w3[0] = hc_bytealign_S (w1[0], w1[1], offset);
      w2[3] = hc_bytealign_S (w0[3], w1[0], offset);
      w2[2] = hc_bytealign_S (w0[2], w0[3], offset);
      w2[1] = hc_bytealign_S (w0[1], w0[2], offset);
      w2[0] = hc_bytealign_S (w0[0], w0[1], offset);
      w1[3] = hc_bytealign_S (    0, w0[0], offset);
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case  8:
      c2[0] = hc_bytealign_S (w3[3],     0, offset);
      c1[3] = hc_bytealign_S (w3[2], w3[3], offset);
      c1[2] = hc_bytealign_S (w3[1], w3[2], offset);
      c1[1] = hc_bytealign_S (w3[0], w3[1], offset);
      c1[0] = hc_bytealign_S (w2[3], w3[0], offset);
      c0[3] = hc_bytealign_S (w2[2], w2[3], offset);
      c0[2] = hc_bytealign_S (w2[1], w2[2], offset);
      c0[1] = hc_bytealign_S (w2[0], w2[1], offset);
      c0[0] = hc_bytealign_S (w1[3], w2[0], offset);
      w3[3] = hc_bytealign_S (w1[2], w1[3], offset);
      w3[2] = hc_bytealign_S (w1[1], w1[2], offset);
      w3[1] = hc_bytealign_S (w1[0], w1[1], offset);
      w3[0] = hc_bytealign_S (w0[3], w1[0], offset);
      w2[3] = hc_bytealign_S (w0[2], w0[3], offset);
      w2[2] = hc_bytealign_S (w0[1], w0[2], offset);
      w2[1] = hc_bytealign_S (w0[0], w0[1], offset);
      w2[0] = hc_bytealign_S (    0, w0[0], offset);
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case  9:
      c2[1] = hc_bytealign_S (w3[3],     0, offset);
      c2[0] = hc_bytealign_S (w3[2], w3[3], offset);
      c1[3] = hc_bytealign_S (w3[1], w3[2], offset);
      c1[2] = hc_bytealign_S (w3[0], w3[1], offset);
      c1[1] = hc_bytealign_S (w2[3], w3[0], offset);
      c1[0] = hc_bytealign_S (w2[2], w2[3], offset);
      c0[3] = hc_bytealign_S (w2[1], w2[2], offset);
      c0[2] = hc_bytealign_S (w2[0], w2[1], offset);
      c0[1] = hc_bytealign_S (w1[3], w2[0], offset);
      c0[0] = hc_bytealign_S (w1[2], w1[3], offset);
      w3[3] = hc_bytealign_S (w1[1], w1[2], offset);
      w3[2] = hc_bytealign_S (w1[0], w1[1], offset);
      w3[1] = hc_bytealign_S (w0[3], w1[0], offset);
      w3[0] = hc_bytealign_S (w0[2], w0[3], offset);
      w2[3] = hc_bytealign_S (w0[1], w0[2], offset);
      w2[2] = hc_bytealign_S (w0[0], w0[1], offset);
      w2[1] = hc_bytealign_S (    0, w0[0], offset);
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 10:
      c2[2] = hc_bytealign_S (w3[3],     0, offset);
      c2[1] = hc_bytealign_S (w3[2], w3[3], offset);
      c2[0] = hc_bytealign_S (w3[1], w3[2], offset);
      c1[3] = hc_bytealign_S (w3[0], w3[1], offset);
      c1[2] = hc_bytealign_S (w2[3], w3[0], offset);
      c1[1] = hc_bytealign_S (w2[2], w2[3], offset);
      c1[0] = hc_bytealign_S (w2[1], w2[2], offset);
      c0[3] = hc_bytealign_S (w2[0], w2[1], offset);
      c0[2] = hc_bytealign_S (w1[3], w2[0], offset);
      c0[1] = hc_bytealign_S (w1[2], w1[3], offset);
      c0[0] = hc_bytealign_S (w1[1], w1[2], offset);
      w3[3] = hc_bytealign_S (w1[0], w1[1], offset);
      w3[2] = hc_bytealign_S (w0[3], w1[0], offset);
      w3[1] = hc_bytealign_S (w0[2], w0[3], offset);
      w3[0] = hc_bytealign_S (w0[1], w0[2], offset);
      w2[3] = hc_bytealign_S (w0[0], w0[1], offset);
      w2[2] = hc_bytealign_S (    0, w0[0], offset);
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 11:
      c2[3] = hc_bytealign_S (w3[3],     0, offset);
      c2[2] = hc_bytealign_S (w3[2], w3[3], offset);
      c2[1] = hc_bytealign_S (w3[1], w3[2], offset);
      c2[0] = hc_bytealign_S (w3[0], w3[1], offset);
      c1[3] = hc_bytealign_S (w2[3], w3[0], offset);
      c1[2] = hc_bytealign_S (w2[2], w2[3], offset);
      c1[1] = hc_bytealign_S (w2[1], w2[2], offset);
      c1[0] = hc_bytealign_S (w2[0], w2[1], offset);
      c0[3] = hc_bytealign_S (w1[3], w2[0], offset);
      c0[2] = hc_bytealign_S (w1[2], w1[3], offset);
      c0[1] = hc_bytealign_S (w1[1], w1[2], offset);
      c0[0] = hc_bytealign_S (w1[0], w1[1], offset);
      w3[3] = hc_bytealign_S (w0[3], w1[0], offset);
      w3[2] = hc_bytealign_S (w0[2], w0[3], offset);
      w3[1] = hc_bytealign_S (w0[1], w0[2], offset);
      w3[0] = hc_bytealign_S (w0[0], w0[1], offset);
      w2[3] = hc_bytealign_S (    0, w0[0], offset);
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 12:
      c3[0] = hc_bytealign_S (w3[3],     0, offset);
      c2[3] = hc_bytealign_S (w3[2], w3[3], offset);
      c2[2] = hc_bytealign_S (w3[1], w3[2], offset);
      c2[1] = hc_bytealign_S (w3[0], w3[1], offset);
      c2[0] = hc_bytealign_S (w2[3], w3[0], offset);
      c1[3] = hc_bytealign_S (w2[2], w2[3], offset);
      c1[2] = hc_bytealign_S (w2[1], w2[2], offset);
      c1[1] = hc_bytealign_S (w2[0], w2[1], offset);
      c1[0] = hc_bytealign_S (w1[3], w2[0], offset);
      c0[3] = hc_bytealign_S (w1[2], w1[3], offset);
      c0[2] = hc_bytealign_S (w1[1], w1[2], offset);
      c0[1] = hc_bytealign_S (w1[0], w1[1], offset);
      c0[0] = hc_bytealign_S (w0[3], w1[0], offset);
      w3[3] = hc_bytealign_S (w0[2], w0[3], offset);
      w3[2] = hc_bytealign_S (w0[1], w0[2], offset);
      w3[1] = hc_bytealign_S (w0[0], w0[1], offset);
      w3[0] = hc_bytealign_S (    0, w0[0], offset);
      w2[3] = 0;
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 13:
      c3[1] = hc_bytealign_S (w3[3],     0, offset);
      c3[0] = hc_bytealign_S (w3[2], w3[3], offset);
      c2[3] = hc_bytealign_S (w3[1], w3[2], offset);
      c2[2] = hc_bytealign_S (w3[0], w3[1], offset);
      c2[1] = hc_bytealign_S (w2[3], w3[0], offset);
      c2[0] = hc_bytealign_S (w2[2], w2[3], offset);
      c1[3] = hc_bytealign_S (w2[1], w2[2], offset);
      c1[2] = hc_bytealign_S (w2[0], w2[1], offset);
      c1[1] = hc_bytealign_S (w1[3], w2[0], offset);
      c1[0] = hc_bytealign_S (w1[2], w1[3], offset);
      c0[3] = hc_bytealign_S (w1[1], w1[2], offset);
      c0[2] = hc_bytealign_S (w1[0], w1[1], offset);
      c0[1] = hc_bytealign_S (w0[3], w1[0], offset);
      c0[0] = hc_bytealign_S (w0[2], w0[3], offset);
      w3[3] = hc_bytealign_S (w0[1], w0[2], offset);
      w3[2] = hc_bytealign_S (w0[0], w0[1], offset);
      w3[1] = hc_bytealign_S (    0, w0[0], offset);
      w3[0] = 0;
      w2[3] = 0;
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 14:
      c3[2] = hc_bytealign_S (w3[3],     0, offset);
      c3[1] = hc_bytealign_S (w3[2], w3[3], offset);
      c3[0] = hc_bytealign_S (w3[1], w3[2], offset);
      c2[3] = hc_bytealign_S (w3[0], w3[1], offset);
      c2[2] = hc_bytealign_S (w2[3], w3[0], offset);
      c2[1] = hc_bytealign_S (w2[2], w2[3], offset);
      c2[0] = hc_bytealign_S (w2[1], w2[2], offset);
      c1[3] = hc_bytealign_S (w2[0], w2[1], offset);
      c1[2] = hc_bytealign_S (w1[3], w2[0], offset);
      c1[1] = hc_bytealign_S (w1[2], w1[3], offset);
      c1[0] = hc_bytealign_S (w1[1], w1[2], offset);
      c0[3] = hc_bytealign_S (w1[0], w1[1], offset);
      c0[2] = hc_bytealign_S (w0[3], w1[0], offset);
      c0[1] = hc_bytealign_S (w0[2], w0[3], offset);
      c0[0] = hc_bytealign_S (w0[1], w0[2], offset);
      w3[3] = hc_bytealign_S (w0[0], w0[1], offset);
      w3[2] = hc_bytealign_S (    0, w0[0], offset);
      w3[1] = 0;
      w3[0] = 0;
      w2[3] = 0;
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 15:
      c3[3] = hc_bytealign_S (w3[3],     0, offset);
      c3[2] = hc_bytealign_S (w3[2], w3[3], offset);
      c3[1] = hc_bytealign_S (w3[1], w3[2], offset);
      c3[0] = hc_bytealign_S (w3[0], w3[1], offset);
      c2[3] = hc_bytealign_S (w2[3], w3[0], offset);
      c2[2] = hc_bytealign_S (w2[2], w2[3], offset);
      c2[1] = hc_bytealign_S (w2[1], w2[2], offset);
      c2[0] = hc_bytealign_S (w2[0], w2[1], offset);
      c1[3] = hc_bytealign_S (w1[3], w2[0], offset);
      c1[2] = hc_bytealign_S (w1[2], w1[3], offset);
      c1[1] = hc_bytealign_S (w1[1], w1[2], offset);
      c1[0] = hc_bytealign_S (w1[0], w1[1], offset);
      c0[3] = hc_bytealign_S (w0[3], w1[0], offset);
      c0[2] = hc_bytealign_S (w0[2], w0[3], offset);
      c0[1] = hc_bytealign_S (w0[1], w0[2], offset);
      c0[0] = hc_bytealign_S (w0[0], w0[1], offset);
      w3[3] = hc_bytealign_S (    0, w0[0], offset);
      w3[2] = 0;
      w3[1] = 0;
      w3[0] = 0;
      w2[3] = 0;
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;
  }
  #endif

  #if (defined IS_AMD && AMD_GCN >= 3) || defined IS_NV

  #if defined IS_NV
  const int selector = (0x76543210 >> ((offset & 3) * 4)) & 0xffff;
  #endif

  #if defined IS_AMD
  const int selector = 0x0706050403020100 >> ((offset & 3) * 8);
  #endif

  switch (offset_switch)
  {
    case  0:
      c0[0] = hc_byte_perm_S (    0, w3[3], selector);
      w3[3] = hc_byte_perm_S (w3[3], w3[2], selector);
      w3[2] = hc_byte_perm_S (w3[2], w3[1], selector);
      w3[1] = hc_byte_perm_S (w3[1], w3[0], selector);
      w3[0] = hc_byte_perm_S (w3[0], w2[3], selector);
      w2[3] = hc_byte_perm_S (w2[3], w2[2], selector);
      w2[2] = hc_byte_perm_S (w2[2], w2[1], selector);
      w2[1] = hc_byte_perm_S (w2[1], w2[0], selector);
      w2[0] = hc_byte_perm_S (w2[0], w1[3], selector);
      w1[3] = hc_byte_perm_S (w1[3], w1[2], selector);
      w1[2] = hc_byte_perm_S (w1[2], w1[1], selector);
      w1[1] = hc_byte_perm_S (w1[1], w1[0], selector);
      w1[0] = hc_byte_perm_S (w1[0], w0[3], selector);
      w0[3] = hc_byte_perm_S (w0[3], w0[2], selector);
      w0[2] = hc_byte_perm_S (w0[2], w0[1], selector);
      w0[1] = hc_byte_perm_S (w0[1], w0[0], selector);
      w0[0] = hc_byte_perm_S (w0[0],     0, selector);

      break;

    case  1:
      c0[1] = hc_byte_perm_S (    0, w3[3], selector);
      c0[0] = hc_byte_perm_S (w3[3], w3[2], selector);
      w3[3] = hc_byte_perm_S (w3[2], w3[1], selector);
      w3[2] = hc_byte_perm_S (w3[1], w3[0], selector);
      w3[1] = hc_byte_perm_S (w3[0], w2[3], selector);
      w3[0] = hc_byte_perm_S (w2[3], w2[2], selector);
      w2[3] = hc_byte_perm_S (w2[2], w2[1], selector);
      w2[2] = hc_byte_perm_S (w2[1], w2[0], selector);
      w2[1] = hc_byte_perm_S (w2[0], w1[3], selector);
      w2[0] = hc_byte_perm_S (w1[3], w1[2], selector);
      w1[3] = hc_byte_perm_S (w1[2], w1[1], selector);
      w1[2] = hc_byte_perm_S (w1[1], w1[0], selector);
      w1[1] = hc_byte_perm_S (w1[0], w0[3], selector);
      w1[0] = hc_byte_perm_S (w0[3], w0[2], selector);
      w0[3] = hc_byte_perm_S (w0[2], w0[1], selector);
      w0[2] = hc_byte_perm_S (w0[1], w0[0], selector);
      w0[1] = hc_byte_perm_S (w0[0],     0, selector);
      w0[0] = 0;

      break;

    case  2:
      c0[2] = hc_byte_perm_S (    0, w3[3], selector);
      c0[1] = hc_byte_perm_S (w3[3], w3[2], selector);
      c0[0] = hc_byte_perm_S (w3[2], w3[1], selector);
      w3[3] = hc_byte_perm_S (w3[1], w3[0], selector);
      w3[2] = hc_byte_perm_S (w3[0], w2[3], selector);
      w3[1] = hc_byte_perm_S (w2[3], w2[2], selector);
      w3[0] = hc_byte_perm_S (w2[2], w2[1], selector);
      w2[3] = hc_byte_perm_S (w2[1], w2[0], selector);
      w2[2] = hc_byte_perm_S (w2[0], w1[3], selector);
      w2[1] = hc_byte_perm_S (w1[3], w1[2], selector);
      w2[0] = hc_byte_perm_S (w1[2], w1[1], selector);
      w1[3] = hc_byte_perm_S (w1[1], w1[0], selector);
      w1[2] = hc_byte_perm_S (w1[0], w0[3], selector);
      w1[1] = hc_byte_perm_S (w0[3], w0[2], selector);
      w1[0] = hc_byte_perm_S (w0[2], w0[1], selector);
      w0[3] = hc_byte_perm_S (w0[1], w0[0], selector);
      w0[2] = hc_byte_perm_S (w0[0],     0, selector);
      w0[1] = 0;
      w0[0] = 0;

      break;

    case  3:
      c0[3] = hc_byte_perm_S (    0, w3[3], selector);
      c0[2] = hc_byte_perm_S (w3[3], w3[2], selector);
      c0[1] = hc_byte_perm_S (w3[2], w3[1], selector);
      c0[0] = hc_byte_perm_S (w3[1], w3[0], selector);
      w3[3] = hc_byte_perm_S (w3[0], w2[3], selector);
      w3[2] = hc_byte_perm_S (w2[3], w2[2], selector);
      w3[1] = hc_byte_perm_S (w2[2], w2[1], selector);
      w3[0] = hc_byte_perm_S (w2[1], w2[0], selector);
      w2[3] = hc_byte_perm_S (w2[0], w1[3], selector);
      w2[2] = hc_byte_perm_S (w1[3], w1[2], selector);
      w2[1] = hc_byte_perm_S (w1[2], w1[1], selector);
      w2[0] = hc_byte_perm_S (w1[1], w1[0], selector);
      w1[3] = hc_byte_perm_S (w1[0], w0[3], selector);
      w1[2] = hc_byte_perm_S (w0[3], w0[2], selector);
      w1[1] = hc_byte_perm_S (w0[2], w0[1], selector);
      w1[0] = hc_byte_perm_S (w0[1], w0[0], selector);
      w0[3] = hc_byte_perm_S (w0[0],     0, selector);
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case  4:
      c1[0] = hc_byte_perm_S (    0, w3[3], selector);
      c0[3] = hc_byte_perm_S (w3[3], w3[2], selector);
      c0[2] = hc_byte_perm_S (w3[2], w3[1], selector);
      c0[1] = hc_byte_perm_S (w3[1], w3[0], selector);
      c0[0] = hc_byte_perm_S (w3[0], w2[3], selector);
      w3[3] = hc_byte_perm_S (w2[3], w2[2], selector);
      w3[2] = hc_byte_perm_S (w2[2], w2[1], selector);
      w3[1] = hc_byte_perm_S (w2[1], w2[0], selector);
      w3[0] = hc_byte_perm_S (w2[0], w1[3], selector);
      w2[3] = hc_byte_perm_S (w1[3], w1[2], selector);
      w2[2] = hc_byte_perm_S (w1[2], w1[1], selector);
      w2[1] = hc_byte_perm_S (w1[1], w1[0], selector);
      w2[0] = hc_byte_perm_S (w1[0], w0[3], selector);
      w1[3] = hc_byte_perm_S (w0[3], w0[2], selector);
      w1[2] = hc_byte_perm_S (w0[2], w0[1], selector);
      w1[1] = hc_byte_perm_S (w0[1], w0[0], selector);
      w1[0] = hc_byte_perm_S (w0[0],     0, selector);
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case  5:
      c1[1] = hc_byte_perm_S (    0, w3[3], selector);
      c1[0] = hc_byte_perm_S (w3[3], w3[2], selector);
      c0[3] = hc_byte_perm_S (w3[2], w3[1], selector);
      c0[2] = hc_byte_perm_S (w3[1], w3[0], selector);
      c0[1] = hc_byte_perm_S (w3[0], w2[3], selector);
      c0[0] = hc_byte_perm_S (w2[3], w2[2], selector);
      w3[3] = hc_byte_perm_S (w2[2], w2[1], selector);
      w3[2] = hc_byte_perm_S (w2[1], w2[0], selector);
      w3[1] = hc_byte_perm_S (w2[0], w1[3], selector);
      w3[0] = hc_byte_perm_S (w1[3], w1[2], selector);
      w2[3] = hc_byte_perm_S (w1[2], w1[1], selector);
      w2[2] = hc_byte_perm_S (w1[1], w1[0], selector);
      w2[1] = hc_byte_perm_S (w1[0], w0[3], selector);
      w2[0] = hc_byte_perm_S (w0[3], w0[2], selector);
      w1[3] = hc_byte_perm_S (w0[2], w0[1], selector);
      w1[2] = hc_byte_perm_S (w0[1], w0[0], selector);
      w1[1] = hc_byte_perm_S (w0[0],     0, selector);
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case  6:
      c1[2] = hc_byte_perm_S (    0, w3[3], selector);
      c1[1] = hc_byte_perm_S (w3[3], w3[2], selector);
      c1[0] = hc_byte_perm_S (w3[2], w3[1], selector);
      c0[3] = hc_byte_perm_S (w3[1], w3[0], selector);
      c0[2] = hc_byte_perm_S (w3[0], w2[3], selector);
      c0[1] = hc_byte_perm_S (w2[3], w2[2], selector);
      c0[0] = hc_byte_perm_S (w2[2], w2[1], selector);
      w3[3] = hc_byte_perm_S (w2[1], w2[0], selector);
      w3[2] = hc_byte_perm_S (w2[0], w1[3], selector);
      w3[1] = hc_byte_perm_S (w1[3], w1[2], selector);
      w3[0] = hc_byte_perm_S (w1[2], w1[1], selector);
      w2[3] = hc_byte_perm_S (w1[1], w1[0], selector);
      w2[2] = hc_byte_perm_S (w1[0], w0[3], selector);
      w2[1] = hc_byte_perm_S (w0[3], w0[2], selector);
      w2[0] = hc_byte_perm_S (w0[2], w0[1], selector);
      w1[3] = hc_byte_perm_S (w0[1], w0[0], selector);
      w1[2] = hc_byte_perm_S (w0[0],     0, selector);
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case  7:
      c1[3] = hc_byte_perm_S (    0, w3[3], selector);
      c1[2] = hc_byte_perm_S (w3[3], w3[2], selector);
      c1[1] = hc_byte_perm_S (w3[2], w3[1], selector);
      c1[0] = hc_byte_perm_S (w3[1], w3[0], selector);
      c0[3] = hc_byte_perm_S (w3[0], w2[3], selector);
      c0[2] = hc_byte_perm_S (w2[3], w2[2], selector);
      c0[1] = hc_byte_perm_S (w2[2], w2[1], selector);
      c0[0] = hc_byte_perm_S (w2[1], w2[0], selector);
      w3[3] = hc_byte_perm_S (w2[0], w1[3], selector);
      w3[2] = hc_byte_perm_S (w1[3], w1[2], selector);
      w3[1] = hc_byte_perm_S (w1[2], w1[1], selector);
      w3[0] = hc_byte_perm_S (w1[1], w1[0], selector);
      w2[3] = hc_byte_perm_S (w1[0], w0[3], selector);
      w2[2] = hc_byte_perm_S (w0[3], w0[2], selector);
      w2[1] = hc_byte_perm_S (w0[2], w0[1], selector);
      w2[0] = hc_byte_perm_S (w0[1], w0[0], selector);
      w1[3] = hc_byte_perm_S (w0[0],     0, selector);
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case  8:
      c2[0] = hc_byte_perm_S (    0, w3[3], selector);
      c1[3] = hc_byte_perm_S (w3[3], w3[2], selector);
      c1[2] = hc_byte_perm_S (w3[2], w3[1], selector);
      c1[1] = hc_byte_perm_S (w3[1], w3[0], selector);
      c1[0] = hc_byte_perm_S (w3[0], w2[3], selector);
      c0[3] = hc_byte_perm_S (w2[3], w2[2], selector);
      c0[2] = hc_byte_perm_S (w2[2], w2[1], selector);
      c0[1] = hc_byte_perm_S (w2[1], w2[0], selector);
      c0[0] = hc_byte_perm_S (w2[0], w1[3], selector);
      w3[3] = hc_byte_perm_S (w1[3], w1[2], selector);
      w3[2] = hc_byte_perm_S (w1[2], w1[1], selector);
      w3[1] = hc_byte_perm_S (w1[1], w1[0], selector);
      w3[0] = hc_byte_perm_S (w1[0], w0[3], selector);
      w2[3] = hc_byte_perm_S (w0[3], w0[2], selector);
      w2[2] = hc_byte_perm_S (w0[2], w0[1], selector);
      w2[1] = hc_byte_perm_S (w0[1], w0[0], selector);
      w2[0] = hc_byte_perm_S (w0[0],     0, selector);
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case  9:
      c2[1] = hc_byte_perm_S (    0, w3[3], selector);
      c2[0] = hc_byte_perm_S (w3[3], w3[2], selector);
      c1[3] = hc_byte_perm_S (w3[2], w3[1], selector);
      c1[2] = hc_byte_perm_S (w3[1], w3[0], selector);
      c1[1] = hc_byte_perm_S (w3[0], w2[3], selector);
      c1[0] = hc_byte_perm_S (w2[3], w2[2], selector);
      c0[3] = hc_byte_perm_S (w2[2], w2[1], selector);
      c0[2] = hc_byte_perm_S (w2[1], w2[0], selector);
      c0[1] = hc_byte_perm_S (w2[0], w1[3], selector);
      c0[0] = hc_byte_perm_S (w1[3], w1[2], selector);
      w3[3] = hc_byte_perm_S (w1[2], w1[1], selector);
      w3[2] = hc_byte_perm_S (w1[1], w1[0], selector);
      w3[1] = hc_byte_perm_S (w1[0], w0[3], selector);
      w3[0] = hc_byte_perm_S (w0[3], w0[2], selector);
      w2[3] = hc_byte_perm_S (w0[2], w0[1], selector);
      w2[2] = hc_byte_perm_S (w0[1], w0[0], selector);
      w2[1] = hc_byte_perm_S (w0[0],     0, selector);
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 10:
      c2[2] = hc_byte_perm_S (    0, w3[3], selector);
      c2[1] = hc_byte_perm_S (w3[3], w3[2], selector);
      c2[0] = hc_byte_perm_S (w3[2], w3[1], selector);
      c1[3] = hc_byte_perm_S (w3[1], w3[0], selector);
      c1[2] = hc_byte_perm_S (w3[0], w2[3], selector);
      c1[1] = hc_byte_perm_S (w2[3], w2[2], selector);
      c1[0] = hc_byte_perm_S (w2[2], w2[1], selector);
      c0[3] = hc_byte_perm_S (w2[1], w2[0], selector);
      c0[2] = hc_byte_perm_S (w2[0], w1[3], selector);
      c0[1] = hc_byte_perm_S (w1[3], w1[2], selector);
      c0[0] = hc_byte_perm_S (w1[2], w1[1], selector);
      w3[3] = hc_byte_perm_S (w1[1], w1[0], selector);
      w3[2] = hc_byte_perm_S (w1[0], w0[3], selector);
      w3[1] = hc_byte_perm_S (w0[3], w0[2], selector);
      w3[0] = hc_byte_perm_S (w0[2], w0[1], selector);
      w2[3] = hc_byte_perm_S (w0[1], w0[0], selector);
      w2[2] = hc_byte_perm_S (w0[0],     0, selector);
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 11:
      c2[3] = hc_byte_perm_S (    0, w3[3], selector);
      c2[2] = hc_byte_perm_S (w3[3], w3[2], selector);
      c2[1] = hc_byte_perm_S (w3[2], w3[1], selector);
      c2[0] = hc_byte_perm_S (w3[1], w3[0], selector);
      c1[3] = hc_byte_perm_S (w3[0], w2[3], selector);
      c1[2] = hc_byte_perm_S (w2[3], w2[2], selector);
      c1[1] = hc_byte_perm_S (w2[2], w2[1], selector);
      c1[0] = hc_byte_perm_S (w2[1], w2[0], selector);
      c0[3] = hc_byte_perm_S (w2[0], w1[3], selector);
      c0[2] = hc_byte_perm_S (w1[3], w1[2], selector);
      c0[1] = hc_byte_perm_S (w1[2], w1[1], selector);
      c0[0] = hc_byte_perm_S (w1[1], w1[0], selector);
      w3[3] = hc_byte_perm_S (w1[0], w0[3], selector);
      w3[2] = hc_byte_perm_S (w0[3], w0[2], selector);
      w3[1] = hc_byte_perm_S (w0[2], w0[1], selector);
      w3[0] = hc_byte_perm_S (w0[1], w0[0], selector);
      w2[3] = hc_byte_perm_S (w0[0],     0, selector);
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 12:
      c3[0] = hc_byte_perm_S (    0, w3[3], selector);
      c2[3] = hc_byte_perm_S (w3[3], w3[2], selector);
      c2[2] = hc_byte_perm_S (w3[2], w3[1], selector);
      c2[1] = hc_byte_perm_S (w3[1], w3[0], selector);
      c2[0] = hc_byte_perm_S (w3[0], w2[3], selector);
      c1[3] = hc_byte_perm_S (w2[3], w2[2], selector);
      c1[2] = hc_byte_perm_S (w2[2], w2[1], selector);
      c1[1] = hc_byte_perm_S (w2[1], w2[0], selector);
      c1[0] = hc_byte_perm_S (w2[0], w1[3], selector);
      c0[3] = hc_byte_perm_S (w1[3], w1[2], selector);
      c0[2] = hc_byte_perm_S (w1[2], w1[1], selector);
      c0[1] = hc_byte_perm_S (w1[1], w1[0], selector);
      c0[0] = hc_byte_perm_S (w1[0], w0[3], selector);
      w3[3] = hc_byte_perm_S (w0[3], w0[2], selector);
      w3[2] = hc_byte_perm_S (w0[2], w0[1], selector);
      w3[1] = hc_byte_perm_S (w0[1], w0[0], selector);
      w3[0] = hc_byte_perm_S (w0[0],     0, selector);
      w2[3] = 0;
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 13:
      c3[1] = hc_byte_perm_S (    0, w3[3], selector);
      c3[0] = hc_byte_perm_S (w3[3], w3[2], selector);
      c2[3] = hc_byte_perm_S (w3[2], w3[1], selector);
      c2[2] = hc_byte_perm_S (w3[1], w3[0], selector);
      c2[1] = hc_byte_perm_S (w3[0], w2[3], selector);
      c2[0] = hc_byte_perm_S (w2[3], w2[2], selector);
      c1[3] = hc_byte_perm_S (w2[2], w2[1], selector);
      c1[2] = hc_byte_perm_S (w2[1], w2[0], selector);
      c1[1] = hc_byte_perm_S (w2[0], w1[3], selector);
      c1[0] = hc_byte_perm_S (w1[3], w1[2], selector);
      c0[3] = hc_byte_perm_S (w1[2], w1[1], selector);
      c0[2] = hc_byte_perm_S (w1[1], w1[0], selector);
      c0[1] = hc_byte_perm_S (w1[0], w0[3], selector);
      c0[0] = hc_byte_perm_S (w0[3], w0[2], selector);
      w3[3] = hc_byte_perm_S (w0[2], w0[1], selector);
      w3[2] = hc_byte_perm_S (w0[1], w0[0], selector);
      w3[1] = hc_byte_perm_S (w0[0],     0, selector);
      w3[0] = 0;
      w2[3] = 0;
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 14:
      c3[2] = hc_byte_perm_S (    0, w3[3], selector);
      c3[1] = hc_byte_perm_S (w3[3], w3[2], selector);
      c3[0] = hc_byte_perm_S (w3[2], w3[1], selector);
      c2[3] = hc_byte_perm_S (w3[1], w3[0], selector);
      c2[2] = hc_byte_perm_S (w3[0], w2[3], selector);
      c2[1] = hc_byte_perm_S (w2[3], w2[2], selector);
      c2[0] = hc_byte_perm_S (w2[2], w2[1], selector);
      c1[3] = hc_byte_perm_S (w2[1], w2[0], selector);
      c1[2] = hc_byte_perm_S (w2[0], w1[3], selector);
      c1[1] = hc_byte_perm_S (w1[3], w1[2], selector);
      c1[0] = hc_byte_perm_S (w1[2], w1[1], selector);
      c0[3] = hc_byte_perm_S (w1[1], w1[0], selector);
      c0[2] = hc_byte_perm_S (w1[0], w0[3], selector);
      c0[1] = hc_byte_perm_S (w0[3], w0[2], selector);
      c0[0] = hc_byte_perm_S (w0[2], w0[1], selector);
      w3[3] = hc_byte_perm_S (w0[1], w0[0], selector);
      w3[2] = hc_byte_perm_S (w0[0],     0, selector);
      w3[1] = 0;
      w3[0] = 0;
      w2[3] = 0;
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 15:
      c3[3] = hc_byte_perm_S (    0, w3[3], selector);
      c3[2] = hc_byte_perm_S (w3[3], w3[2], selector);
      c3[1] = hc_byte_perm_S (w3[2], w3[1], selector);
      c3[0] = hc_byte_perm_S (w3[1], w3[0], selector);
      c2[3] = hc_byte_perm_S (w3[0], w2[3], selector);
      c2[2] = hc_byte_perm_S (w2[3], w2[2], selector);
      c2[1] = hc_byte_perm_S (w2[2], w2[1], selector);
      c2[0] = hc_byte_perm_S (w2[1], w2[0], selector);
      c1[3] = hc_byte_perm_S (w2[0], w1[3], selector);
      c1[2] = hc_byte_perm_S (w1[3], w1[2], selector);
      c1[1] = hc_byte_perm_S (w1[2], w1[1], selector);
      c1[0] = hc_byte_perm_S (w1[1], w1[0], selector);
      c0[3] = hc_byte_perm_S (w1[0], w0[3], selector);
      c0[2] = hc_byte_perm_S (w0[3], w0[2], selector);
      c0[1] = hc_byte_perm_S (w0[2], w0[1], selector);
      c0[0] = hc_byte_perm_S (w0[1], w0[0], selector);
      w3[3] = hc_byte_perm_S (w0[0],     0, selector);
      w3[2] = 0;
      w3[1] = 0;
      w3[0] = 0;
      w2[3] = 0;
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;
  }
  #endif
}

__device__ void sha1_update_64 (sha1_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len)
{
  const int pos = ctx->len & 63;

  ctx->len += len;

  if ((pos + len) < 64)
  {
    switch_buffer_by_offset_be_S (w0, w1, w2, w3, pos);

    ctx->w0[0] |= w0[0];
    ctx->w0[1] |= w0[1];
    ctx->w0[2] |= w0[2];
    ctx->w0[3] |= w0[3];
    ctx->w1[0] |= w1[0];
    ctx->w1[1] |= w1[1];
    ctx->w1[2] |= w1[2];
    ctx->w1[3] |= w1[3];
    ctx->w2[0] |= w2[0];
    ctx->w2[1] |= w2[1];
    ctx->w2[2] |= w2[2];
    ctx->w2[3] |= w2[3];
    ctx->w3[0] |= w3[0];
    ctx->w3[1] |= w3[1];
    ctx->w3[2] |= w3[2];
    ctx->w3[3] |= w3[3];
  }
  else
  {
    u32 c0[4] = { 0 };
    u32 c1[4] = { 0 };
    u32 c2[4] = { 0 };
    u32 c3[4] = { 0 };

    switch_buffer_by_offset_carry_be_S (w0, w1, w2, w3, c0, c1, c2, c3, pos);

    ctx->w0[0] |= w0[0];
    ctx->w0[1] |= w0[1];
    ctx->w0[2] |= w0[2];
    ctx->w0[3] |= w0[3];
    ctx->w1[0] |= w1[0];
    ctx->w1[1] |= w1[1];
    ctx->w1[2] |= w1[2];
    ctx->w1[3] |= w1[3];
    ctx->w2[0] |= w2[0];
    ctx->w2[1] |= w2[1];
    ctx->w2[2] |= w2[2];
    ctx->w2[3] |= w2[3];
    ctx->w3[0] |= w3[0];
    ctx->w3[1] |= w3[1];
    ctx->w3[2] |= w3[2];
    ctx->w3[3] |= w3[3];

    sha1_transform (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h);

    ctx->w0[0] = c0[0];
    ctx->w0[1] = c0[1];
    ctx->w0[2] = c0[2];
    ctx->w0[3] = c0[3];
    ctx->w1[0] = c1[0];
    ctx->w1[1] = c1[1];
    ctx->w1[2] = c1[2];
    ctx->w1[3] = c1[3];
    ctx->w2[0] = c2[0];
    ctx->w2[1] = c2[1];
    ctx->w2[2] = c2[2];
    ctx->w2[3] = c2[3];
    ctx->w3[0] = c3[0];
    ctx->w3[1] = c3[1];
    ctx->w3[2] = c3[2];
    ctx->w3[3] = c3[3];
  }
}

__device__ void sha1_update (sha1_ctx_t *ctx, const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 64; pos1 += 64, pos4 += 16)
  {
    w0[0] = w[pos4 +  0];
    w0[1] = w[pos4 +  1];
    w0[2] = w[pos4 +  2];
    w0[3] = w[pos4 +  3];
    w1[0] = w[pos4 +  4];
    w1[1] = w[pos4 +  5];
    w1[2] = w[pos4 +  6];
    w1[3] = w[pos4 +  7];
    w2[0] = w[pos4 +  8];
    w2[1] = w[pos4 +  9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];

    sha1_update_64 (ctx, w0, w1, w2, w3, 64);
  }

  w0[0] = w[pos4 +  0];
  w0[1] = w[pos4 +  1];
  w0[2] = w[pos4 +  2];
  w0[3] = w[pos4 +  3];
  w1[0] = w[pos4 +  4];
  w1[1] = w[pos4 +  5];
  w1[2] = w[pos4 +  6];
  w1[3] = w[pos4 +  7];
  w2[0] = w[pos4 +  8];
  w2[1] = w[pos4 +  9];
  w2[2] = w[pos4 + 10];
  w2[3] = w[pos4 + 11];
  w3[0] = w[pos4 + 12];
  w3[1] = w[pos4 + 13];
  w3[2] = w[pos4 + 14];
  w3[3] = w[pos4 + 15];

  sha1_update_64 (ctx, w0, w1, w2, w3, len - pos1);
}

__device__ void set_mark_1x4_S (u32 *v, const u32 offset)
{
  const u32 c = (offset & 15) / 4;
  const u32 r = 0xff << ((offset & 3) * 8);

  v[0] = (c == 0) ? r : 0;
  v[1] = (c == 1) ? r : 0;
  v[2] = (c == 2) ? r : 0;
  v[3] = (c == 3) ? r : 0;
}

__device__ void append_helper_1x4_S (u32 *r, const u32 v, const u32 *m)
{
  r[0] |= v & m[0];
  r[1] |= v & m[1];
  r[2] |= v & m[2];
  r[3] |= v & m[3];
}

__device__ void append_0x80_4x4_S (u32 *w0, u32 *w1, u32 *w2, u32 *w3, const u32 offset)
{
  u32 v[4];

  set_mark_1x4_S (v, offset);

  const u32 offset16 = offset / 16;

  append_helper_1x4_S (w0, ((offset16 == 0) ? 0x80808080 : 0), v);
  append_helper_1x4_S (w1, ((offset16 == 1) ? 0x80808080 : 0), v);
  append_helper_1x4_S (w2, ((offset16 == 2) ? 0x80808080 : 0), v);
  append_helper_1x4_S (w3, ((offset16 == 3) ? 0x80808080 : 0), v);
}

__device__ void sha1_final(sha1_ctx_t *ctx)
{
	volatile const int pos = ctx->len & 63;

	append_0x80_4x4_S(ctx->w0, ctx->w1, ctx->w2, ctx->w3, pos ^ 3);

	if (pos >= 56)
	{
		sha1_transform(ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h);

		ctx->w0[0] = 0;
		ctx->w0[1] = 0;
		ctx->w0[2] = 0;
		ctx->w0[3] = 0;
		ctx->w1[0] = 0;
		ctx->w1[1] = 0;
		ctx->w1[2] = 0;
		ctx->w1[3] = 0;
		ctx->w2[0] = 0;
		ctx->w2[1] = 0;
		ctx->w2[2] = 0;
		ctx->w2[3] = 0;
		ctx->w3[0] = 0;
		ctx->w3[1] = 0;
		ctx->w3[2] = 0;
		ctx->w3[3] = 0;
	}

	ctx->w3[2] = 0;
	ctx->w3[3] = ctx->len * 8;

	sha1_transform(ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h);
}

__device__ void SHA1(
	char hash_out[20],
	const char *str,
	int len)
{
	sha1_ctx_t ctx;
	unsigned int ii;

	sha1_init(&ctx);
	u32 input_b[] = { 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u };

	for (ii = 0; ii < len; ii += 1) {
		input_b[0] = str[ii] << 24;
		sha1_update(&ctx, input_b, 1);

		/*
		printf("hash sha1 buffer @ %d ", ii);		
		for (int i = 0; i < 16; i++)
		{
			printf("%02x", ((ctx.w0[i >> 2] >> ((3 - (i & 3)) * 8)) & 255));
		}
		for (int i = 0; i < 16; i++)
		{
			printf("%02x", ((ctx.w1[i >> 2] >> ((3 - (i & 3)) * 8)) & 255));
		}
		for (int i = 0; i < 16; i++)
		{
			printf("%02x", ((ctx.w2[i >> 2] >> ((3 - (i & 3)) * 8)) & 255));
		}
		for (int i = 0; i < 16; i++)
		{
			printf("%02x", ((ctx.w3[i >> 2] >> ((3 - (i & 3)) * 8)) & 255));
		}
		printf("\n");
		printf("hash sha1 state @ %d ", ii);
		for (int i = 0; i < 20; i++)
		{
			printf("%02x", (unsigned char)
				((ctx.h[i >> 2] >> ((3 - (i & 3)) * 8)) & 255));
		}
		printf("\n");
		*/
	}
	sha1_final(&ctx);
	for (int i = 0; i < 20; i++)
	{
		hash_out[i] = (unsigned char)
			((ctx.h[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
	}
}