//#define FDSDEBUG /* Print out stuff on stderr! */
#undef FDSDEBUG // please no!
#ifdef FDSDEBUG
#define fdfprintf(x, y...) if(isatty(2)) fprintf(x, y);
#else
#define fdfprintf(x, y...)
#endif

struct fd_callbackp {
   void (*callback)(struct fd_callbackp *);
   void *param;
   int fd;  // fd number
   int rdf; // fd is set for reading
   int wrf; // fd is set for writing
};

#define FDT_NONE      0
#define FDT_AUTH      1
#define FDT_RESOLVER  2
#define FDT_CLIENT    3
#define FDT_LISTENER  4
#define FDT_CALLBACKP 5

#define FDF_WANTREAD  0x01
#define FDF_WANTWRITE 0x02

void init_fds();

void add_fd(int fd, int type, void *value);
void del_fd(int fd);
#define add_callback_fd(fds) add_fd((fds)->fd, FDT_CALLBACKP, (fds))
#define del_callback_fd(fds) del_fd((fds)->fd)

void get_fd_info(int fd, int *type, unsigned int *flags, void **value);
void set_fd_flags(int fd, unsigned int flags);
void unset_fd_flags(int fd, unsigned int flags);

void set_fd_internal(int fd, void *ptr);
void *get_fd_internal(int fd);

void check_client_fd(aClient *cptr);

void report_fds(aClient *cptr);
