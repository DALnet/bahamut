#include "worker.h"
#include "shared_state.h"
#include "multicore.h"

void worker_main_loop(int worker_id) {
    while (1) {
        // Handle events for assigned clients
        engine_read_message(delay);
        
        // Process IPC messages
        process_ipc_messages();
        
        // Update worker status
        update_worker_status(worker_id);
        
        // Handle timeouts
        if (timeofday >= nextping) {
            nextping = check_pings(timeofday);
        }
    }
}

void update_worker_status(int worker_id) {
    // Update health metrics
    // CPU usage, memory usage, client count, etc.
} 