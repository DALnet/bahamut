extern int dh_init();
extern void dh_end_session(void *);
extern void *dh_start_session();
extern char *dh_get_s_secret(char *, int, void *);
extern char *dh_get_s_public(char *, int, void *);
extern char *dh_get_s_shared(char *, int, void *);
extern int dh_generate_shared(void *, char *);

extern int dh_hexstr_to_raw(char *string, unsigned char *hexout, int *hexlen);

extern void rc4_process_stream_to_buf(void *rc4_context, const unsigned char *istring,
                               unsigned char *ostring, unsigned int stringlen);
extern void rc4_process_stream(void *rc4_context, unsigned char *istring, unsigned int stringlen);
extern void *rc4_initstate(unsigned char *key, int keylen);
extern void rc4_destroystate(void *a);
