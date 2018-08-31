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
#ifndef F5CRYPT_H
#define F5CRYPT_H

void F5gen_rand_series(char *seed, int seed_len,  char *byte_array, int byte_count );
void F5permutation(char *rand_series, int *shuffled, int size);
int  F5extract(short *coeff, int coeff_len, int* shuffled, char* rand_series, int rand_series_len, int max_msg_length, char *message, int *message_len, int mode);

void F5crypt_internal_check();
int  F5cic_comp(char*a , char* b);
#endif
