/* simple password generator by Nelson Minar (minar@reed.edu)
 * copyright 1991, all rights reserved.
 * You can use this code as long as my name stays with it.
 */

/* Must precede every system header (sys.h pulls in <stdlib.h>) so glibc
 * exposes random()/srandom(); FreeBSD declares them unconditionally. With the
 * declarations visible from <stdlib.h>, we must NOT redeclare them ourselves:
 * the old K&R `extern int srandom(unsigned)` conflicts with FreeBSD's
 * `void srandom(unsigned int)` and breaks the build under clang. */
#define _DEFAULT_SOURCE
#include "sys.h"
#include <time.h>
#include <stdlib.h>

extern char *getpass();
extern char *crypt();

int main(argc, argv)
int argc;
char *argv[];
{
  static char saltChars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";
  char salt[3];
  char * plaintext;

  if (argc < 2) {
    srandom(time(0));		/* may not be the BEST salt, but its close */
    salt[0] = saltChars[random() % 64];
    salt[1] = saltChars[random() % 64];
    salt[2] = 0;
  }
  else {
    salt[0] = argv[1][0];
    salt[1] = argv[1][1];
    salt[2] = '\0';
    if ((strchr(saltChars, salt[0]) == NULL) || (strchr(saltChars, salt[1]) == NULL))
      fprintf(stderr, "illegal salt %s\n", salt), exit(1);
  }

  plaintext = getpass("plaintext: ");

  printf("%s\n", crypt(plaintext, salt));
  return 0;
}

