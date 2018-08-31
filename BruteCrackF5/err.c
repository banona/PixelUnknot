#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#include "global.h"

#include "err.h"

void malchk(void* ptr)
{
    malcheck(ptr, "Unspecified");
}
void malcheck(void *ptr, char *message)
{
    if( !ptr )
    {
        dlog("Memory Allocation Failure: ");
        dlog(message);
        dlog("\n");
        fputs("Memory Allocation Failure: ", stderr);
        fputs(message, stderr);
        fputs("\n", stderr);
        exit(1);
    }
}


void dlog(char *message)
{
    static FILE *logfile = 0;
    static char first_run = 1;

    #ifndef DEBUG
    return;
    #endif

    if( first_run )
    {
        logfile = fopen("debug_log.txt", "w");
        fputs("--- Begining Debug Log File---\n", logfile);
        first_run = 0;
    }
    fputs(message, logfile);
}


