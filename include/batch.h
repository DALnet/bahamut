/* include/batch.h
 *
 * IRCv3 batch helper API.
 * Provides functions to generate batch reference names and send
 * BATCH +ref / BATCH -ref to a client.
 */

#ifndef BATCH_H
#define BATCH_H

/* Generate a unique batch reference name into buf (at least 32 bytes) */
void batch_genref(char *buf, size_t size);

/* Send "BATCH +ref type [params]" to a client */
void batch_start(aClient *to, const char *ref, const char *type, const char *params);

/* Send "BATCH -ref" to a client */
void batch_end(aClient *to, const char *ref);

#endif /* BATCH_H */
