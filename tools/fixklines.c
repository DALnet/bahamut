/*

fixklines - scan an ircd conf file remove any
'#' mark (comment character) found in the reason field
of a K: K-line, replace it with a ' '.

usage: 
  gcc -o fixklines fixklines.c

  fixklines < kline.conf > kline.conf.fix

  if program flags a Kline comment with a '#' in it, then...

  mv kline.conf.fix kline.conf
  rehash

-Dianora
*/

#include <stdio.h>
#include <string.h>
#define MAXBUFF 256

#define YES 1
#define NO  0

char buffer[MAXBUFF], scratch[MAXBUFF];

int main()
{
  char *p, *k_itself, *host, *reason, *user;
  int hash_found;
  int number_of_lines=0;
  int number_hash_comments=0;

  while(fgets(buffer,MAXBUFF-1,stdin)) {
      number_of_lines++;
      if((buffer[0] == 'K') && (buffer[1] == ':'))
	{
	  strncpy(scratch,buffer,MAXBUFF);
	  p = strchr(scratch,':');
	  if(p)
	    *p = '\0';
	  else {
	      fprintf(stderr,"missing K huh? %s\n",buffer);
	      fputs(buffer,stdout);
              continue;
	    }
	  k_itself = scratch;
	  p++; host = p;
	  p = strchr(host,':');
	  if(p)
	    *p = '\0';
	  else {
	      fprintf(stderr,"missing host %s\n",buffer);
	      fputs(buffer,stdout);
	      continue;
	    }
	  p++;
	  reason = p;
	  p = strchr(reason,':'); 
	  if(p)
	    *p = '\0';
	  else {
	      fprintf(stderr,"missing reason %s\n",buffer);
	      fputs(buffer,stdout);
	      continue;
	    }
	  p++;
	  user = p;
	  p = reason;
	  hash_found = NO;
	  while(*p) {
	      if(*p == '#') {
		  *p = ' ';
		  hash_found = YES;
		}
	      p++;
	    }

	  if(hash_found) {
	      fprintf(stderr,"# found in comment %s",buffer);
	      number_hash_comments++;
	    }

	  printf("K:%s:%s:%s",host,reason,user);
	}
      else
	fputs(buffer,stdout);
    }

  fprintf(stderr,"%d lines processed %d lines with hash in K line comments\n",
	  number_of_lines,number_hash_comments);
  return 0;
}

