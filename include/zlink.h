extern void *zip_create_input_session();
extern void *zip_create_output_session();
extern char *zip_input(void *session, char *buffer, int *len, int *err,
		       char **nbuf, int *nlen);
/* largedata is err return */
extern char *zip_output(void *session, char *buffer, int *len,
			int forceflush, int *largedata);
extern int zip_is_data_out(void *session);
extern void zip_out_get_stats(void *session, unsigned long *insiz,
			      unsigned long *outsiz, double *ratio);
extern void zip_in_get_stats(void *session, unsigned long *insiz,
			     unsigned long *outsiz, double *ratio);
extern void zip_destroy_input_session(void *session);
extern void zip_destroy_output_session(void *session);

