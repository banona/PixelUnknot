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
#include<stdio.h>
#include<stdlib.h>
#include<assert.h>
#include<string.h>

#include "global.h"
#include "err.h"
#include "sha1.h"

#include "F5crypt.h"

char deZigZag[] = {  0,  1,  5,  6, 14, 15, 27, 28,
                     2,  4,  7, 13, 16, 26, 29, 42,
                     3,  8, 12, 17, 25, 30, 41, 43,
                     9, 11, 18, 24, 31, 40, 44, 53,
                    10, 19, 23, 32, 39, 45, 52, 54,
                    20, 22, 33, 38, 46, 51, 55, 60,
                    21, 34, 37, 47, 50, 56, 59, 61,
                    35, 36, 48, 49, 57, 58, 62, 63};

char pk_sentinal[] = "----* PK v 1.0 REQUIRES PASSWORD ----*";

void F5gen_rand_series(char *seed, int seed_len, char *byte_array, int byte_count )
{                                                /*  Modifies  */
    // implement the SHA1PRNG from java,
    // generate an array of bytes as would be done by the F5 algo,

    char state[20];    // The java code uses BYTEs,
    int last, v, zf;
    uint8_t t;

    assert( byte_count % 20 == 0 );   //integer array must be padded to the next multiple of 20bytes (hash size of SHA 160bits)

    // Set initial state
    SHA1(state, seed, seed_len);

    // Generate in blocks of 5 ints
    for(int i = 0; i < byte_count; i+=20)
    {
        // From SecureRandom.getEngineNextBytes
        // Conviently, the 20 state bytes get assembled in little endin order into 5 integers
        char* output = byte_array + i;

        SHA1(output, state, 20);

        // From SecureRandom.updateState
        last = 1;
        v = 0;
        t = 0;
        zf = 0;  //using as bool

        for(int j = 0; j < 20; j++)
        {
            v = (int)state[j] + (int)output[j] + last;
            t = (uint8_t)v;   //lower 8 bits only
            zf = zf | (state[j] != t);
            state[j] = t;
            last = v >> 8;
        }

        if( !zf ) state[0]++;  // make sure at least one bit changes
    }

    #ifdef DEBUG
    FILE *debug_dump;
    debug_dump = fopen("rand_series_dump.dat", "wb");
    if(debug_dump) fwrite(byte_array, 1, byte_count, debug_dump);
    fclose(debug_dump);
    #endif

}

void F5permutation(char *rand_series, int *shuffled, int size)
{                                     /*modifies*/
    // finishes what F5Random does
    // then builds the permutation table

    int retVal;
    int random_index;
    int tmp;
    int max_random;


    assert( shuffled ); assert( rand_series );

    max_random = size;
    for(int i = 0; i < size; i++)
    {
        // F5Random.getNextValue
        retVal =  (int)(rand_series[i*4]) | (int)(rand_series[i*4+1]) << 8 | (int)(rand_series[i*4+2]) << 16 | (int)(rand_series[i*4+3]) << 24;
        retVal %= max_random;

        //retVal = *((int*)rand_series + i*4);  //CPU says No.
        retVal %= max_random;

        if( retVal < 0 ) retVal += max_random;
        max_random--;

        //Permutation
        random_index = retVal;

        tmp = shuffled[random_index];
        shuffled[random_index] = shuffled[max_random];
        shuffled[max_random] = tmp;
    }

    #ifdef DEBUG
    FILE *debug_dump;
    debug_dump = fopen("permutation_dump.dat", "wb");
    if(debug_dump) fwrite(shuffled, 4, size, debug_dump);
    fclose(debug_dump);
    #endif
}


int F5extract(short *coeff, int coeff_len, int* shuffled, char* rand_series, int rand_series_len, int max_msg_length, char *message, int *message_len, int mode)
{                                                                                                                     /*         modifies          */
    int rand_pos = coeff_len * sizeof(int); //previous bytes were for the permutation
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
    for(i = 0; availableExtractedBits < 32; i++)
    {
        shuffledIndex = shuffled[i];
        if( shuffledIndex % 64 == 0 ) continue; //Skip DCs
        shuffledIndex = shuffledIndex - (shuffledIndex % 64) + deZigZag[shuffledIndex % 64];
        if( coeff[shuffledIndex] == 0 ) continue; //Skip zeros
        if( coeff[shuffledIndex] > 0 )
            extractedBit = coeff[shuffledIndex] & 1;        // if coefficent is greater than 0 then take LSB literally
        else
            extractedBit = 1 - (coeff[shuffledIndex] & 1);  // else, take the INVERSE of the LSB
        extractedFileLength |= extractedBit << availableExtractedBits++;
    }

    // remove pad
    extractedFileLength ^= rand_series[rand_pos++];
    extractedFileLength ^= rand_series[rand_pos++] << 8;
    extractedFileLength ^= rand_series[rand_pos++] << 16;
    extractedFileLength ^= rand_series[rand_pos++] << 24;
    int k = (extractedFileLength >> 24);
    k %= 32;
    int n = (1 << k) - 1;
    extractedFileLength &= 0x007fffff;

    // quick retun of message length is beyond  max reasonable size
    if( extractedFileLength > max_msg_length )
        return 0;

    // Proceed with decode
    availableExtractedBits = 0;
    if( n > 0 )
    {
        int startOfN = i;
        int hash;

        while(1)
        {
            // read places and calculate bits
            hash = 0;
            int code = 1;
            for( i = 0; code <= n; i++ )
            {
                if( startOfN + i >= coeff_len) return 0;
                shuffledIndex = shuffled[startOfN + i];
                if( shuffledIndex % 64 == 0 ) continue; //skip DCs
                shuffledIndex = shuffledIndex - (shuffledIndex%64) + deZigZag[shuffledIndex%64];
                if( coeff[shuffledIndex] == 0 ) continue; //skip zeros
                if( coeff[shuffledIndex] > 0 )
                    extractedBit = coeff[shuffledIndex] & 1;
                else
                    extractedBit = (1 - coeff[shuffledIndex]) & 1;
                if( extractedBit == 1 ) hash ^= code;
                code++;
            }
            startOfN += i;

            // write k bits bytewise
            for( i = 0; i < k; i++ )
            {
                extractedByte |= ((hash>>i) & 1) << availableExtractedBits++;
                if( availableExtractedBits == 8 )
                {
                    // remove pad and save byte
                    extractedByte ^= rand_series[rand_pos++];
                    message[msg_pos++] = extractedByte;
                    extractedByte = 0;
                    availableExtractedBits = 0;
                    nBytesExtracted++;

                    // PixelKnow specific check
                    if( (mode == 1) & (nBytesExtracted < 30) )
                        if( message[msg_pos-1] != pk_sentinal[msg_pos-1] )
                            return 0;
                }
                // check for pending end of embedded data
                if( nBytesExtracted == extractedFileLength )
                {
                    *message_len = msg_pos;
                    return 1; //woohoo!
                }
            }
        }
    }
    else  //Default code used
    {
        for(/*see above*/; i < coeff_len; i++)
        {
            shuffledIndex = shuffled[i];
            if( shuffledIndex % 64 == 0) continue; //skip DCs
            shuffledIndex = shuffledIndex - (shuffledIndex % 64)+ deZigZag[shuffledIndex % 64];
            if( coeff[shuffledIndex] == 0 ) continue; //skip zeros
            if( coeff[shuffledIndex] > 0 )
                extractedBit = coeff[shuffledIndex] & 1;
            else
                extractedBit = 1 - (coeff[shuffledIndex] & 1);
            extractedByte |= extractedBit << availableExtractedBits++;
            if (availableExtractedBits == 8)
            {
                // remove pseudo random pad
                extractedByte ^= rand_series[rand_pos++];
                message[msg_pos++] = extractedByte;
                extractedByte = 0;
                availableExtractedBits = 0;
                nBytesExtracted++;
                if(nBytesExtracted == extractedFileLength)
                {
                    *message_len = msg_pos;
                    return 1;
                }
            }
        }
    }

    if( nBytesExtracted < extractedFileLength )
            return 0;

    return 0;  //shouldn't ever get to here
}


void F5crypt_internal_check()
{
    char sha_null_out[] = {0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55,
                           0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09};
    char sha_test_out[] = {0xa9, 0x4a, 0x8f, 0xe5, 0xcc, 0xb1, 0x9b, 0xa6, 0x1c, 0x4c,
                           0x08, 0x73, 0xd3, 0x91, 0xe9, 0x87, 0x98, 0x2f, 0xbb, 0xd3};
    char gen_rand_out[] = {0x68, 0x90, 0x33, 0xed, 0x17, 0x55, 0x0d, 0x23, 0x8a, 0x56,
                           0x61, 0x75, 0x85, 0xa6, 0xec, 0xa7, 0x27, 0x9a, 0xeb, 0x24};
    char perm_algo_out[]= {0x6d, 0x50, 0x10, 0x8d, 0x16, 0x27, 0xdb, 0x81, 0xb5, 0xc9,
                           0xbb, 0x90, 0xf0, 0x40, 0xaa, 0xee, 0x59, 0xd9, 0xc4, 0xae};

    char output[20];
    char* rand_series;
    int*  perm_series;
    int fail = 0;

    // Test the SHA hash function
    SHA1(output, "", 0);
    if( F5cic_comp(output, sha_null_out) )
        fail = 1;

    SHA1(output, "test", 4);
    if( F5cic_comp(output, sha_test_out) )
        fail = 1;

    if(fail)
    {
        printf("SHA1 failed internal test.\n");
        exit(1);
    }

    // Test the PRNG based on java's SecureRandom SHA1PRNG
    rand_series = malloc(1000000);
    malcheck(rand_series, "F5 PRNG");
    F5gen_rand_series("seed", 4, rand_series, 1000000);
    SHA1(output, rand_series, 1000000);
    if( F5cic_comp(output, gen_rand_out) )
    {
        printf("Rand Series Generator failed internal test.\n");
        exit(1);
    }

    // Test permutation algo
    perm_series = malloc(1000000);
    malcheck(perm_series, "F5 permutation");
    for(int i = 0; i < 250000; i++)
        perm_series[i] = i;
    F5permutation(rand_series, perm_series, 250000);
    SHA1(output, (char*)perm_series, 1000000);
    if( F5cic_comp(output, perm_algo_out) )
    {
        printf("Permutation failed internal test.\n");
        exit(1);
    }

    free(rand_series);
    free(perm_series);
}

int F5cic_comp(char* a, char* b)
{
    for(int i = 0; i < 20; i++)
        if(a[i] != b[i])
            return 1;

    return 0;
}
