#ifndef __MULTICORE_H__
#define __MULTICORE_H__

#include "struct.h"
#include <sys/types.h>
#include <pthread.h>

// Forward declarations
struct SharedState;
struct MessageRingBuffer;
struct WorkerBatchCollector;
struct MessageQueue;
struct SequenceTracker;
struct HealthMonitor;
struct LoadBalancer;
struct RecoverySystem;

// Main multicore functions
int init_multicore_system(void);
void shutdown_multicore_system(void);
int spawn_worker_processes(void);
void worker_main_loop(int worker_id);

// IPC message types
enum IpcMessageType {
    IPC_NEW_CONNECTION,
    IPC_CLIENT_QUIT,
    IPC_CHANNEL_JOIN,
    IPC_CHANNEL_PART,
    IPC_WORKER_DIED
};

// Core IPC functions
int send_ipc_message(pid_t dest_pid, enum IpcMessageType type, void *data);
void process_ipc_messages(void);

#endif 