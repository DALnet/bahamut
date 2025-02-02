#ifndef __SHARED_STATE_H__
#define __SHARED_STATE_H__

#include "struct.h"
#include <pthread.h>

struct SharedState {
    // Global statistics
    struct Counter Count;
    
    // Client/channel hash tables
    aClient *client_hash_table[HASHSIZE];
    aChannel *channel_hash_table[HASHSIZE]; 
    
    // Synchronization primitives
    pthread_rwlock_t client_lock;
    pthread_rwlock_t channel_lock;
    
    // Worker process info
    int num_workers;
    pid_t worker_pids[MAX_WORKERS];
};

SharedState *init_shared_state(void);
void destroy_shared_state(SharedState *state);

// Thread-safe operations
int shared_add_client(SharedState *state, aClient *client);
int shared_remove_client(SharedState *state, aClient *client);
int shared_add_channel(SharedState *state, aChannel *channel);
int shared_remove_channel(SharedState *state, aChannel *channel);

#endif 