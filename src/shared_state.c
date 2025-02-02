#include "shared_state.h"
#include <sys/shm.h>

SharedState *init_shared_state(void) {
    int shmid = shmget(IPC_PRIVATE, sizeof(SharedState), IPC_CREAT | 0600);
    if (shmid < 0) {
        return NULL;
    }
    
    SharedState *state = (SharedState *)shmat(shmid, NULL, 0);
    if (state == (void *)-1) {
        return NULL;
    }
    
    pthread_rwlock_init(&state->client_lock, NULL);
    pthread_rwlock_init(&state->channel_lock, NULL);
    
    return state;
}

int shared_add_client(SharedState *state, aClient *client) {
    pthread_rwlock_wrlock(&state->client_lock);
    // Add client to hash table
    int result = add_to_client_hash_table(client->name, client);
    pthread_rwlock_unlock(&state->client_lock);
    return result;
}

// Similar implementations for other shared state operations... 