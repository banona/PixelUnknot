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

#include "err.h"

#include "threads.h"


enum rs_enum     runstate = init;

void init_thread_system(int threads_max)
{
    // build array from storing thread handles
    thread = malloc(sizeof(pthread_t) * threads_max);
    malcheck(thread, "pthreads");

    // init various locks
    pthread_mutex_init (&line_reader_lock, NULL);
    pthread_mutex_init (&file_writer_lock, NULL);
    pthread_rwlock_init(&runstate_lock,    NULL);
}

enum rs_enum get_runstate()
{
    enum rs_enum state;
    pthread_rwlock_rdlock(&runstate_lock);
        state = runstate;
    pthread_rwlock_unlock(&runstate_lock);
    return state;
}
void set_runstate(enum rs_enum state)
{
    pthread_rwlock_wrlock(&runstate_lock);
        runstate = state;
    pthread_rwlock_unlock(&runstate_lock);
}

