#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "config.h"
#include "sys.h"

/* wait.h is in /include on solaris, likely on other SYSV machines as well
   but wait.h is normally in /include/sys on BSD boxen,
   probably we should have an #ifdef SYSV?
  -Dianora
*/
#ifdef SOL20
#include <wait.h>
#else
#include <sys/wait.h>
#endif

#ifndef lint
/* static char *rcs_version="$Id$"; */
#endif /* lint */

int main(int argc, char *argv[])
{
#ifdef LOCKFILE
	int fd;
	char s[20], *ed, *p, *filename = CONFIGFILE;

	if((p = strrchr(argv[0], '/')) == NULL)
		p = argv[0];
	else
		p++;
	if(strcmp(p, "viklines") == 0)
		filename = KLINEFILE;

	/* create exclusive lock */
	if((fd = open(LOCKFILE, O_WRONLY|O_CREAT|O_EXCL, 0666)) < 0) {
		fprintf(stderr, "ircd config file locked\n");
		exit(1);
	}
	sprintf(s, "%d\n", (int) getpid());
	write(fd, s, strlen(s));
	close(fd);

	/* ed config file */
	switch(fork()) {
	case -1:
		fprintf(stderr, "error forking, %d\n", errno);
		exit(errno);
	case 0:		/* Child */
		if((ed = getenv("EDITOR")) == NULL)
			ed = "vi";
		execlp(ed, ed, filename, NULL);
		fprintf(stderr, "error running editor, %d\n", errno);
		exit(errno);
	default:
		wait(0);
	}

	unlink(LOCKFILE);
	return 0;
#else
	printf("LOCKFILE not defined in config.h\n");
#endif
}
