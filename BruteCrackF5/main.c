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
#include<signal.h>
#include<time.h>

#include "global.h"
#include "err.h"
#include "F5crypt.h"
#include "image.h"
#include "sha1.h"
#include "threads.h"


// Globals
char  *g_filename = 0;
char  *g_output_prefix = "output.dat.";
char  *g_password_file = 0;
int    g_threads = 1;
int    g_dontcontinue = 0;               // don't continue after find a match
int    g_mode = 0;
unsigned long g_skip_lines = 0;          // skip ahead before working
unsigned long g_counter = 0;             // running tally of checked passwords
short *g_coeff = 0;                      // coefficent dump from a JPEG file
int    g_coeff_len;
int    g_max_msg_len;                    // max legit message length
int   *g_unshuffled;                     // clean set of assending integers.


// Local Functions
void *worker_thread_main(void *threadID);
void get_next_password(char* password, int *password_len);
void write_result(char* password, int password_len, char* message, int message_len);
void sig_catch(int sig);


void usage()
{
    printf("--- BruthCrackF5 ---\n");
    printf("Reads a provided coefficent dump from a JPEG file (TODO: jpeglib) and tests it\n");
    printf("against a seriesof passwords provided to STDIN (default) or as a password file.\n");
    printf("Outputs any found payload to a file.\n");
    printf("\nUsage: brutecrackf5 filename [OPTION]...\n\nOptions:\n");
    printf(" --out FILENAME  Output filename prefix. Will be appended with numerals.\n");
    printf("                 Default: \"output.dat.\"\n");
    printf(" --pass FILENAME Password list. Expected to be seperated by new-line charactors.\n");
    printf("                 Default: STDIN\n");
    printf(" --stop          Stop after finding the first password canidate. The F5 algo\n");
    printf("                 doesn't include any sort of integrity check. False positives\n");
    printf("                 are liley in any sizeable search. The default is to continue.\n");
    printf(" --pk            Ignore anything missing the PixelKnot sentinal string as a\n");
    printf("                 false positive. Implies '--stop'\n");
    printf(" --skip #        Skip a number of input lines before starting.\n");

    exit(0);
}


int main(int argc, char** argv)
{
    F5crypt_internal_check();
    signal(SIGINT, sig_catch);
    signal(SIGTERM, sig_catch);

    //Parse Args
    for(int i = 1; i < argc; i++)
    {
        if( strcmp(argv[i], "--stop")==0 || strcmp(argv[i], "-s")==0 )
        {
            g_dontcontinue = 1;
            //printf("Dontstop flag set\n");
            continue;
        }
        if( strcmp(argv[i], "--out")==0 || strcmp(argv[i], "-o")==0 )
        {
            if(i+1 == argc) usage();
            g_output_prefix = argv[++i];
            //printf("Output file prefix set to \"%s\"\n", g_output_prefix);
            continue;
        }
        if( strcmp(argv[i],"--pass")==0 || strcmp(argv[i],"-p")==0 )
        {
            if(i+1 == argc) usage();
            g_password_file = argv[++i];
            //printf("Password file set to \"%s\"\n", g_password_file);
            continue;
        }
        if( strcmp(argv[i], "--pkmode")==0 || strcmp(argv[i], "-pk")==0 )
        {
            g_mode = 1;  //perform PixelKnot specific checks
            g_dontcontinue = 1;
            //printf("pk mode set\n");
            continue;
        }
        if( strcmp( argv[i], "--skip")==0 || strcmp(argv[i], "-sk")==0 )
        {
            if(i+1 == argc) usage();
            g_skip_lines = strtol(argv[++i], NULL, 10);
            if( g_skip_lines < 1) usage();
            printf("Skipping the first %lu lines\n", g_skip_lines);
            continue;
        }
        //fall through

        if( !g_filename )
        {
            g_filename = argv[i];
            //printf("Filename set to \"%s\"\n", g_filename);
            continue;
        }
        //anything else
        usage();
    }
    if( !g_filename )
        usage();


    //Timing
    float cps = 0;
    unsigned long int counter_now;
    unsigned long int counter_last;
    unsigned long int count_diff;
    int tinit = 0;

    load_coeff(g_filename, &g_coeff, &g_coeff_len, &g_max_msg_len);
	cudaMallocManaged(&g_unshuffled, g_coeff_len * sizeof(int));

	for(int i = 0; i < g_coeff_len; i++)
        g_unshuffled[i] = i;



	cudaFree(g_unshuffled);
	return 0;
}

__global__
void decode(int n, float *x, float *y) {

}

void *worker_thread_main(void *threadID)
{
    int ID = *((int*)threadID);

    char *rand_series;
    int   rand_series_len;
    int  *shuffled;
    char *message;
    int   message_len;
    char  password[MAX_PASSWORD_LENGTH];
    int   password_len = 0;
    int   ret;

    printf("== Thread #%i Starting ==\n", ID);

    // Mem allocations. Only need to do this once.
    rand_series_len = g_coeff_len * sizeof(int) + g_max_msg_len;
    if( rand_series_len % 20 != 0 ) //pad to multiple of 20
        rand_series_len = rand_series_len + 20 - rand_series_len%20;
    rand_series = malloc(rand_series_len);
    malchk(rand_series);

    shuffled = malloc(g_coeff_len * sizeof(int));
    malchk(shuffled);

    message = malloc(g_max_msg_len);
    malchk(message);

    while( get_runstate() != shutdown )
    {
        // 1. Get next password from interface.
        // Passed values will be modifiled by function.
        get_next_password(password, &password_len);
        if( password_len == 0 )
            break;

        // 2. Generate all of the random numbers we will need all in one go.
        // The rand_seris array will be filled by function
        F5gen_rand_series(password, password_len, rand_series, rand_series_len);

        // 3. Shuffle a clean series.
        // Values in 'shuffled' be be rearanged.
        memcpy(shuffled, g_unshuffled, g_coeff_len*sizeof(int));
        F5permutation(rand_series, shuffled, g_coeff_len);

        // 4. Attempt extraction
        // Return 1 on success, 0 on failure. On success message and message_len will be modified.
        ret = F5extract(g_coeff, g_coeff_len, shuffled, rand_series, rand_series_len, g_max_msg_len, message, &message_len, g_mode);
        // 5. Write results if password found
        if( ret )
        {
            printf(">>>>> Password Hit: \"%s\" <<<<<\n", password);
            write_result(password, password_len, message, message_len);
            if( g_dontcontinue )
                set_runstate(shutdown);
        }
    }

    printf("== Thread #%i Terminating. Last password checked: \"%s\" ==\n", ID, password);

    //free(rand_series);  //weird double-free errors on exit ???
    //free(shuffled);
    //free(message);
    pthread_exit(NULL);
}


void get_next_password(char* password, int *password_len)
{
    int got_length;
    size_t max_length = MAX_PASSWORD_LENGTH;
    static FILE* fp = 0;
    int throwaway;

    // not mutexing. thread-startup is spaced out enough
    if( !fp ) //if first pass, setup file pointer
    {
        if( !g_password_file )
        {
            printf("No password file provided. Reading from STDIN\n");
            fp = stdin;
        }
        else
            fp = fopen(g_password_file, "r");
    }
    if( !fp ) // still nothing..
    {
        printf("Error opening password file: %s\n", g_password_file);
        set_runstate(shutdown);
        return;
    }

    // getline is relativly threadsafe, but there will be a thread pile-up if g_skip_lines is largeish
    pthread_mutex_lock(&line_reader_lock);
        // optionally skip ahead. when done global var will be left at zero
        if(g_skip_lines)
            for( ; g_skip_lines > 0; g_skip_lines--)
                throwaway = getline(&password, &max_length, fp);

        got_length = getline(&password, &max_length, fp);
        if(got_length < 1 )
        {
            set_runstate(shutdown);
            return;
        }
        *password_len = got_length;
        g_counter++;
    pthread_mutex_unlock(&line_reader_lock);

    //strip line endings
    while(1)
        if( (password[got_length-1]=='\n') | (password[got_length-1] == '\r') )
            got_length--;
        else
            break;
    password[got_length] = '\0';
    *password_len = got_length;

    return;
}

void write_result(char* password, int password_len, char* message, int message_len)
{
    char fn[200];
    int i = 0;
    FILE *fp;

    if( strlen(g_output_prefix) > 190 )
        return;

    pthread_mutex_lock(&file_writer_lock);
        while(i < 1000)
        {
            i++;
            sprintf(fn, "%s%i", g_output_prefix, i);
            if( access(fn, F_OK) != -1 )
                continue; //already exists. try again.
            else
                break;
        }
        if( i == 1000 )
        {
            printf("Too many files with that name. Not writing output file.\n");
        }
        else
        {
            fp = fopen(fn, "wb");
            printf("Writing: %s\n", fn);
            fprintf(fp, "For filename: \"%s\"\n", g_filename);
            fprintf(fp, "Canadate password: \"%s\"\n", password);
            fprintf(fp, "Length: %i\n", message_len);
            fprintf(fp, "PayloadBegins->");
            fwrite(message, 1, message_len, fp);
            fclose(fp);
        }
    pthread_mutex_unlock(&file_writer_lock);
}

void sig_catch(int sig)
{
    static int not_first = 0;

    if(not_first) exit(1);

    printf("\nSignal Recieved.\n");
    set_runstate(shutdown);
    not_first = 1;
}

