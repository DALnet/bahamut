/************************************************************************
 *   IRC - Internet Relay Chat, ircd/chkconf.c
 *   Copyright (C) 1993 Darren Reed
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef lint
/*
 * static  char sccsid[] = "@(#)chkconf.c	1.7 27 Oct 1993 (C) 1993 Darren Reed";
 * static char *rcs_version = "$Id$";
 */
#endif

#define FOREVER for(;;)

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "h.h"
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef __hpux
#include "inet.h"
#endif
#ifdef PCS
#include <time.h>
#endif
#ifdef R_LINES
#include <signal.h>
#endif

#ifdef DYNIXPTX
#include <sys/types.h>
#include <time.h>
#endif

#ifndef DOUGH_MALLOC
/*#undef	free */
#define MyRealloc(x, y)    realloc(x, y)
#define MMyFree(x)       free(x)
#define	MyMalloc(x)	malloc(x)
#endif

static	void	new_class();
static  char	*ckgetfield(char *);
static	int	ckinitconf(int);
static	int	ckopenconf();
static	aClass	*get_class();

static	int	numclasses = 0, *classarr = (int *)NULL;
static	char	*configfile = CONFIGFILE;
static	char	nullfield[] = "";
static	char	maxsendq[12];

void print_confline(aConfItem *,char *);

int main(int argc,char *argv[])
{
  new_class(0);

  if (chdir(DPATH))
    {
      perror("chdir");
      exit(-1);
    }
  if (argc > 1)
    configfile = argv[1];
  (void)ckinitconf(0);
  return 0;
}

/*
 * ckopenconf
 *
 * returns -1 on any error or else the fd opened from which to read the
 * configuration file from.  This may either be th4 file direct or one end
 * of a pipe from m4.
 */
static	int	ckopenconf()
{
#ifdef	M4_PREPROC
  int	pi[2];

  if (pipe(pi) == -1)
    return -1;
  switch(fork())
    {
    case -1 :
      return -1;
    case 0 :
      (void)close(pi[0]);
      if (pi[1] != 1)
	{
	  (void)dup2(pi[1], 1);
	  (void)close(pi[1]);
	}
      (void)dup2(1,2);
      /*
       * m4 maybe anywhere, use execvp to find it.  Any error
       * goes out with report_error.  Could be dangerous,
       * two servers running with the same fd's >:-) -avalon
       */
      (void)execlp("m4", "m4", "ircd.m4", configfile, 0);
      perror("m4");
      exit(-1);
    default :
      (void)close(pi[1]);
      return pi[0];
    }
#else
  return open(configfile, O_RDONLY);
#endif
}

/*
** ckinitconf() 
**    Read configuration file.
**
**    returns -1, if file cannot be opened
**             0, if file opened
*/

static int 	ckinitconf(int opt)
{
  int	fd;
  char	line[512], *tmp, c[80], *s;
  int	ccount = 0, ncount = 0, dh;
  aConfItem conf, *aconf = &conf;

  (void)fprintf(stderr, "initconf(): ircd.conf = %s\n", configfile);
  if ((fd = ckopenconf()) == -1)
    {
#ifdef	M4_PREPROC
      (void)wait(0);
#endif
      return -1;
    }

  aconf->host = (char *)NULL;
  aconf->passwd = (char *)NULL;
  aconf->name = (char *)NULL;

  (void)dgets(-1, NULL, 0); /* make sure buffer is at empty pos */
  while ((dh = dgets(fd, line, sizeof(line) - 1)) > 0)
    {
      if (aconf->host)
	(void)MMyFree(aconf->host);
      if (aconf->passwd)
	(void)MMyFree(aconf->passwd);
      if (aconf->name)
	(void)MMyFree(aconf->name);
      aconf->host = (char *)NULL;
      aconf->passwd = (char *)NULL;
      aconf->name = (char *)NULL;
      aconf->class = (aClass *)NULL;
      if ( (tmp = (char *)index(line, '\n')) )
	*tmp = 0;
      else while(dgets(fd, c, sizeof(c) - 1))
	if ( (tmp = (char *)index(c, '\n')) )
	  {
	    *tmp = 0;
	    break;
	  }
      /*
       * Do quoting of characters and # detection.
       */
      for (tmp = line; *tmp; tmp++)
	{
	  if (*tmp == '\\')
	    {
	      switch (*(tmp+1))
		{
		case 'n' :
		  *tmp = '\n';
		  break;
		case 'r' :
		  *tmp = '\r';
		  break;
		case 't' :
		  *tmp = '\t';
		  break;
		case '0' :
		  *tmp = '\0';
		  break;
		default :
		  *tmp = *(tmp+1);
		  break;
		}
	      if (!*(tmp+1))
		break;
	      else
		for (s = tmp; (*s = *++s); )
		  ;
	      tmp++;
	    }
	  else if (*tmp == '#')
	    *tmp = '\0';
	}
      if (!*line || *line == '#' || *line == '\n' ||
	  *line == ' ' || *line == '\t')
	continue;

      /* Could we test if it's conf line at all?	-Vesa */
      if (line[1] != ':')
	{
	  (void)fprintf(stderr, "ERROR: Bad config line (%s)\n",
			line);
	  continue;
	}

      (void)printf("\n%s\n",line);
      (void)fflush(stdout);

      tmp = ckgetfield(line);
      if (!tmp)
	{
	  (void)fprintf(stderr, "\tERROR: no fields found\n");
	  continue;
	}

      aconf->status = CONF_ILLEGAL;

      switch (*tmp)
	{
	case 'A': /* Name, e-mail address of administrator */
	case 'a': /* of this server. */
	  aconf->status = CONF_ADMIN;
	  break;

	case 'C': /* Server where I should try to connect */
	case 'c': /* in case of lp failures             */
	  ccount++;
	  aconf->status = CONF_CONNECT_SERVER;
	  break;

	case 'Z':
	case 'z':
	  aconf->status = CONF_ZLINE;
	  break;

	case 'E':
	case 'e':
	  aconf->status = CONF_ELINE;
	  break;

	case 'F':
	case 'f':
	  aconf->status = CONF_FLINE;
	  break;

	case 'H': /* Hub server line */
	case 'h':
	  aconf->status = CONF_HUB;
	  break;

	case 'I': /* Just plain normal irc client trying  */
	case 'i': /* to connect me */
	  aconf->status = CONF_CLIENT;
	  break;

	case 'K': /* Kill user line on irc.conf           */
	case 'k':
	  aconf->status = CONF_KILL;
	  break;

	  /* Me. Host field is name used for this host */
	  /* and port number is the number of the port */
	case 'M':
	case 'm':
	  aconf->status = CONF_ME;
	  break;

	case 'N': /* Server where I should NOT try to     */
	case 'n': /* connect in case of lp failures     */
	  /* but which tries to connect ME        */
	  ++ncount;
	  aconf->status = CONF_NOCONNECT_SERVER;
	  break;

	  /* Operator. Line should contain at least */
	  /* password and host where connection is  */
	case 'O':
	  aconf->status = CONF_OPERATOR;
	  break;

	  /* Local Operator, (limited privs --SRB) */
	case 'o':
	  aconf->status = CONF_LOCOP;
	  break;

	case 'P': /* listen port line */
	case 'p':
	  aconf->status = CONF_LISTEN_PORT;
	  break;

#ifdef R_LINES
	case 'R': /* extended K line */
	case 'r': /* Offers more options of how to restrict */
	  aconf->status = CONF_RESTRICT;
	  break;
#endif
	case 'U': /* Uphost, ie. host where client reading */
	case 'u': /* this should connect.                  */
	  /* This is for client only, I must ignore this */
	  /* ...U-line should be removed... --msa */
	  break;

	case 'X': /* /die and /restart passwords */
	    aconf->status = CONF_DRPASS;
	    break;
	
	case 'Y':
	case 'y':
	  aconf->status = CONF_CLASS;
	  break;

	default:
	  (void)fprintf(stderr,
			"\tERROR: unknown conf line letter (%c)\n",
			*tmp);
	  break;
	}
      
      if (IsIllegal(aconf))
	continue;
      
      for (;;) /* Fake loop, that I can use break here --msa */
	{
	  if ((tmp = ckgetfield(NULL)) == NULL)
	    break;
	  DupString(aconf->host, tmp);
	  if ((tmp = ckgetfield(NULL)) == NULL)
	    break;
	  DupString(aconf->passwd, tmp);
	  if ((tmp = ckgetfield(NULL)) == NULL)
	    break;
	  DupString(aconf->name, tmp);
	  if ((tmp = ckgetfield(NULL)) == NULL)
	    break;
	  aconf->port = atoi(tmp);
	  if ((tmp = ckgetfield(NULL)) == NULL)
	    break;
	  if (!(aconf->status & CONF_CLASS))
	    aconf->class = get_class(atoi(tmp));
	  break;
	}
      if (!aconf->class && (aconf->status & (CONF_CONNECT_SERVER|
					     CONF_NOCONNECT_SERVER|
					     CONF_OPS|CONF_CLIENT)))
	{
	  (void)fprintf(stderr,
			"\tWARNING: No class.  Default 0\n");
	  aconf->class = get_class(0);
	}
      /*
      ** If conf line is a class definition, create a class entry
      ** for it and make the conf_line illegal and delete it.
      */
      if (aconf->status & CONF_CLASS)
	{
	  if (!aconf->host)
	    {
	      (void)fprintf(stderr,"\tERROR: no class #\n");
	      continue;
	    }
	  if (!tmp)
	    {
	      (void)fprintf(stderr,
			    "\tWARNING: missing sendq field\n");
	      (void)fprintf(stderr, "\t\t default: %d\n",
			    MAXSENDQLENGTH);
	      (void)sprintf(maxsendq, "%d", MAXSENDQLENGTH);
	    }
	  else
	      (void)sprintf(maxsendq, "%d", atoi(tmp));

	  new_class(atoi(aconf->host));
	  aconf->class = get_class(atoi(aconf->host));
	  print_confline(aconf,maxsendq);
	  continue;
	}
      
      if (aconf->status & CONF_LISTEN_PORT)
	{
	  aconf->class = get_class(0);
	  print_confline(aconf,maxsendq);
	  continue;
	}

      if (aconf->status & CONF_SERVER_MASK &&
	  (!aconf->host || index(aconf->host, '*') ||
	   index(aconf->host, '?')))
	{
	  (void)fprintf(stderr, "\tERROR: bad host field\n");
	  continue;
	}
      
      if (aconf->status & CONF_SERVER_MASK && BadPtr(aconf->passwd))
	{
	  (void)fprintf(stderr,
			"\tERROR: empty/no password field\n");
	  continue;
	}

      if (aconf->status & CONF_SERVER_MASK && !aconf->name)
	{
	  (void)fprintf(stderr, "\tERROR: bad name field\n");
	  continue;
	}

      if (aconf->status & (CONF_SERVER_MASK|CONF_OPS))
	if (!index(aconf->host, '@'))
	  {
	    char	*newhost;
	    int	len = 3;	/* *@\0 = 3 */
	    
	    len += strlen(aconf->host);
	    newhost = (char *)MyMalloc(len);
	    (void)sprintf(newhost, "*@%s", aconf->host);
	    (void)MMyFree(aconf->host);
	    aconf->host = newhost;
	  }

      if (!aconf->class)
	aconf->class = get_class(0);
      (void)sprintf(maxsendq, "%d", aconf->class->class);

      if (!aconf->name)
	aconf->name = nullfield;
      if (!aconf->passwd)
	aconf->passwd = nullfield;
      if (!aconf->host)
	aconf->host = nullfield;
      
      print_confline(aconf,maxsendq);
    }
  (void)close(fd);
#ifdef	M4_PREPROC
  (void)wait(0);
#endif
  return 0;
}

void print_confline(aConfItem *aconf,char *maxsendq)
{
  (void)printf("(%d) (%s) (%s) (%s) (%d) (%s)\n",
	       aconf->status, aconf->host, aconf->passwd,
	       aconf->name, aconf->port, maxsendq);
  (void)fflush(stdout);
}

static	aClass	*get_class(int cn)
{
  static	aClass	cls;
  int	i = numclasses - 1;

  cls.class = -1;
  for (; i >= 0; i--)
    if (classarr[i] == cn)
      {
	cls.class = cn;
	break;
      }
  if (i == -1)
    (void)fprintf(stderr,"\tWARNING: class %d not found\n", cn);
  return &cls;
}

static	void	new_class(int cn)
{
  numclasses++;
  if (classarr)
    classarr = (int *)MyRealloc(classarr, sizeof(int) * numclasses);
  else
    classarr = (int *)MyMalloc(sizeof(int));
  classarr[numclasses-1] = cn;
}

/*
 * field breakup for ircd.conf file.
 */
static	char	*ckgetfield(char *newline)
{
  static	char *line = NULL;
  char	*end, *field;
  
  if (newline)
    line = newline;
  if (line == NULL)
    return(NULL);

  field = line;
  if ((end = (char *)index(line,':')) == NULL)
    {
      line = NULL;
      if ((end = (char *)index(field,'\n')) == NULL)
	end = field + strlen(field);
    }
  else
    line = end + 1;
  *end = '\0';
  return(field);
}


/*
** read a string terminated by \r or \n in from a fd
**
** Created: Sat Dec 12 06:29:58 EST 1992 by avalon
** Returns:
**	0 - EOF
**	-1 - error on read
**     >0 - number of bytes returned (<=num)
** After opening a fd, it is necessary to init dgets() by calling it as
**	dgets(x,y,0);
** to mark the buffer as being empty.
*
* cleaned up by - Dianora aug 7 1997 *argh*
*/
int dgets(int fd,char *buf,int num)
{
  static char	dgbuf[8192];
  static char	*head = dgbuf, *tail = dgbuf;
  register char	*s, *t;
  register int	n, nr;

  /*
  ** Sanity checks.
  */
  if (head == tail)
    *head = '\0';

  if (!num)
    {
      head = tail = dgbuf;
      *head = '\0';
      return 0;
    }

  if (num > sizeof(dgbuf) - 1)
    num = sizeof(dgbuf) - 1;

  FOREVER
    {
      if (head > dgbuf)
	{
	  for (nr = tail - head, s = head, t = dgbuf; nr > 0; nr--)
	    *t++ = *s++;
	  tail = t;
	  head = dgbuf;
	}
      /*
      ** check input buffer for EOL and if present return string.
      */
      if (head < tail &&
	  ((s = index(head, '\n')) || (s = index(head, '\r'))) && s < tail)
	{
	  n = MIN(s - head + 1, num);	/* at least 1 byte */
	  bcopy(head, buf, n);
	  head += n;
	  if (head == tail)
	    head = tail = dgbuf;
	  return n;
	}

      if (tail - head >= num)		/* dgets buf is big enough */
	{
	  n = num;
	  bcopy(head, buf, n);
	  head += n;
	  if (head == tail)
	    head = tail = dgbuf;
	  return n;
	}

      n = sizeof(dgbuf) - (tail - dgbuf) - 1;
      nr = read(fd, tail, n);
      if (nr == -1)
	{
	  head = tail = dgbuf;
	  return -1;
	}

      if (!nr)
	{
	  if (tail > head)
	    {
	      n = MIN(tail - head, num);
	      bcopy(head, buf, n);
	      head += n;
	      if (head == tail)
		head = tail = dgbuf;
	      return n;
	    }
	  head = tail = dgbuf;
	  return 0;
	}

      tail += nr;
      *tail = '\0';

      for (t = head; (s = index(t, '\n')); )
	{
	  if ((s > head) && (s > dgbuf))
	    {
	      t = s-1;
	      for (nr = 0; *t == '\\'; nr++)
		t--;
	      if (nr & 1)
		{
		  t = s+1;
		  s--;
		  nr = tail - t;
		  while (nr--)
		    *s++ = *t++;
		  tail -= 2;
		  *tail = '\0';
		}
	      else
		s++;
	    }
	  else
	    s++;
	  t = s;
	}
      *tail = '\0';
    }
}

