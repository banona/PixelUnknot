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
#include<strings.h>
//#include <jpeglib.h>
#include "global.h"
#include "err.h"

#include "image.h"



//ZigZag, conversoin between the natural-order output from jpeglib
// and the zig-zag orderning expected by the F5 algorithum
int zigzag[] = { 0,  1,  8, 16,  9,  2,  3, 10,
                 17, 24, 32, 25, 18, 11,  4,  5,
                 12, 19, 26, 33, 40, 48, 41, 34,
                 27, 20, 13,  6,  7, 14, 21, 28,
                 35, 42, 49, 56, 57, 50, 43, 36,
                 29, 22, 15, 23, 30, 37, 44, 51,
                 58, 59, 52, 45, 38, 31, 39, 46,
                 53, 60, 61, 54, 47, 55, 62, 63 };


int load_coeff(char* filename, short** coeffptr, int* coeff_len, int *max_msg_len)
{
    // TODO: Either figure out why the jpeglib approach isn't working
    //       and fix it or port the Java code over line by line.

    FILE *fp;
    short *coeff = 0;

    fp = fopen(filename, "rb");
    if( !fp )
    {
        fputs("File not found\n", stderr);
        return 1;
    }
    fseek(fp, 0, SEEK_END);
    *coeff_len = ftell(fp)/2;
    rewind(fp);

    printf("File: %s   %i bytes.\n", filename, *coeff_len * 2);

    coeff = malloc(*coeff_len * sizeof(short));
    malcheck(coeff, "file buffer");
    *coeffptr = coeff; //export the pointer


    if( fread(coeff, 2, *coeff_len, fp) != *coeff_len )
    {
        fputs("File error\n", stderr);
        return 1;
    }

    *max_msg_len = 0;
    for(int i = 0; i < *coeff_len; i++)
        if( (i%64 != 0) & (coeff[i] != 0) )
            (*max_msg_len)++;

    printf("Max theoretical message length: %i\n", *max_msg_len);
    return 0;



    /*     I cannot get this thing to output the same data as the HuffmanDecode.java class. There is very little
           documentation on the layout or format of jpeglib's internal DCT data blocks.
           So instead of getting bogged down any further I'm gonna just load the result from a java based exporter.
           I'l get back to it eventually.

    FILE *fp;
    struct jpeg_decompress_struct cinfo;
    struct jpeg_error_mgr         jerr;
    jvirt_barray_ptr             *coeff_array;

    printf("Opening: %s\n", filename);
    fp = fopen(filename, "rb");
    if( !fp )
        return 1;

    // initialize
    cinfo.err = jpeg_std_error(&jerr);
    jpeg_create_decompress(&cinfo);
    jpeg_stdio_src(&cinfo, fp);
    jpeg_read_header(&cinfo, 1);
    coeff_array = jpeg_read_coefficients(&cinfo);

    #ifdef DEBUG
    printf("Image Width: %i\n", cinfo.image_width);
    printf("Image Height: %i\n", cinfo.image_height);
    printf("Components: %i\n", cinfo.num_components);
    printf("MCU blocks per row: %i\n", cinfo.MCUs_per_row);
    printf("MCU blocks in scan: %i\n",cinfo.MCU_rows_in_scan);
    printf("VSamp: %i\n", cinfo.max_h_samp_factor);
    printf("HSamp: %i\n", cinfo.max_h_samp_factor);
    printf("Blocks in MCU: %i\n", cinfo.blocks_in_MCU);
    #endif

    *coeff_len = DCTSIZE2 * cinfo.MCUs_per_row * cinfo.MCU_rows_in_scan * cinfo.blocks_in_MCU;
    printf("Coefficents length: %i\n", *coeff_len);

    coeff = malloc(*coeff_len);
    malcheck(coeff, "DCT Coeff");

    int pos = 0; //
    for(int component = 0; component < cinfo.num_components; component++)
    {
        jpeg_component_info *component_ptr = &cinfo.comp_info[component];
        #if DEBUG
        printf("Component %i Vsamp: %i ", component, component_ptr->v_samp_factor);
        printf(" Hsamp: %i\n", component_ptr->h_samp_factor);
        #endif
        for( int MCU_y = 0; MCU_y < cinfo.MCU_rows_in_scan ; MCU_y += 1)
        {
        //                      |<---_ Function Pointer ----->||<--------------------------------- Function Arguments -------------------------------------->|
            JBLOCKARRAY strip = (cinfo.mem->access_virt_barray)((j_common_ptr)&cinfo, coeff_array[component], (JDIMENSION)MCU_y,           1,     FALSE);
        //                                                                          , ptrs to component objs,      starting row, manay rows?, writeable?

            for(int MCU_x = 0; MCU_x < cinfo.MCUs_per_row ; MCU_x += 1)
            {
                for(int i = 0; i < component_ptr->MCU_blocks ; i++)
                {
                    for(int k = 0; k < 64; k++)
                    {
                            coeff[pos] = (char)strip[0][MCU_x][ zigzag[k] + i*DCTSIZE2];
                            pos++;
                    }
                }
            }
        }
    }



    jpeg_destroy((j_common_ptr)&cinfo);
    #ifdef DEBUG
    FILE *debug_dump;
    debug_dump = fopen("coeff_dump.dat", "wb");
    if(debug_dump) fwrite(coeff, *coeff_len, 1, debug_dump);
    fclose(debug_dump);
    #endif

    return 0;
    */
}

