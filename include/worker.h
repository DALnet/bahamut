#ifndef __WORKER_H__
#define __WORKER_H__

#include "struct.h"
#include <sys/types.h>

// Worker process management
int start_worker(int worker_id);
void stop_worker(int worker_id);
void worker_process_loop(int worker_id);

// Worker health monitoring
void update_worker_status(int worker_id);
int check_worker_health(int worker_id);

#endif 