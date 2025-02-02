#include "multicore.h"
#include "shared_state.h"
#include "worker.h"
#include <sys/sysinfo.h>

static SharedState *shared_state = NULL;

int init_multicore_system(void) {
    shared_state = init_shared_state();
    if (!shared_state) {
        return -1;
    }
    
    shared_state->num_workers = get_nprocs();
    return spawn_worker_processes();
}

int spawn_worker_processes(void) {
    for (int i = 0; i < shared_state->num_workers; i++) {
        pid_t pid = fork();
        if (pid < 0) {
            return -1;
        }
        
        if (pid == 0) {
            worker_main_loop(i);
            exit(0);
        }
        
        shared_state->worker_pids[i] = pid;
    }
    return 0;
}

void shutdown_multicore_system(void) {
    if (shared_state) {
        for (int i = 0; i < shared_state->num_workers; i++) {
            stop_worker(i);
        }
        destroy_shared_state(shared_state);
    }
} 