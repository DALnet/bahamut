extern int dh_init();
extern void dh_end_session(void *);
extern void *dh_start_session();
extern char *dh_get_s_secret(char *, int, void *);
extern char *dh_get_s_public(char *, int, void *);
extern char *dh_get_s_shared(char *, int, void *);
extern int dh_generate_shared(void *, char *);
