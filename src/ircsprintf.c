
/* $Id$ */

#include <stdio.h>
#ifdef USE_STDARGS
#include <stdarg.h>
#endif

#ifndef USE_STDARGS
void
ircsprintf(
	     char *outp,
	     char *formp,
	     char *in0p, char *in1p, char *in2p, char *in3p,
	     char *in4p, char *in5p, char *in6p, char *in7p,
	     char *in8p, char *in9p, char *in10p)
{
	
   /*
    * rp for Reading, wp for Writing, fp for the Format string 
    */
	char       *inp[11];		/*
									 * 
									 * we could hack this if we know the format of
									 * * the stack 
									 */
	register char *rp, *fp, *wp;
	register char f;
	register int i = 0;
	
   inp[0] = in0p;
   inp[1] = in1p;
   inp[2] = in2p;
   inp[3] = in3p;
   inp[4] = in4p;
   inp[5] = in5p;
   inp[6] = in6p;
   inp[7] = in7p;
   inp[8] = in8p;
   inp[9] = in9p;
   inp[10] = in10p;

   fp = formp;
   wp = outp;
	
   rp = inp[i];
	/*
	 * start with the first input string 
	 */
   /*
    * just scan the format string and puke out whatever is necessary
    * along the way...
    */

   while ((f = *(fp++))) {
		
      if (f != '%')
		  *(wp++) = f;
      else
		  switch (*(fp++)) {
			  
			case 's':		/*
								 * put the most common case at the top 
								 */
			  if (rp) {
				  while (*rp)
					 *wp++ = *rp++;
				  *wp = '\0';
			  }
			  else {
				  *wp++ = '{';
				  *wp++ = 'n';
				  *wp++ = 'u';
				  *wp++ = 'l';
				  *wp++ = 'l';
				  *wp++ = '}';
				  *wp++ = '\0';
			  }
			  rp = inp[++i];	/*
									 * get the next parameter 
									 */
			  break;
			case 'd':
				 {
					 register int myint;
					 
					 myint = (int) rp;
					 
					 if (myint < 100 || myint > 999) {
						 sprintf(outp, formp, in0p, in1p, in2p, in3p,
									in4p, in5p, in6p, in7p, in8p,
									in9p, in10p);
						 return;
					 }
					 
					 *(wp++) = (char) ((myint / 100) + (int) '0');
					 myint %= 100;
					 *(wp++) = (char) ((myint / 10) + (int) '0');
					 myint %= 10;
					 *(wp++) = (char) ((myint) + (int) '0');
					 
					 rp = inp[++i];
				 }
			  break;
			case 'u':
				 {
					 register unsigned int myuint;
					 
					 myuint = (unsigned int) rp;
					 
					 if (myuint < 100 || myuint > 999) {
						 sprintf(outp, formp, in0p, in1p, in2p, in3p,
									in4p, in5p, in6p, in7p, in8p,
									in9p, in10p);
						 return;
					 }
					 
					 *(wp++) = (char) ((myuint / 100) + (unsigned int) '0');
					 myuint %= 100;
					 *(wp++) = (char) ((myuint / 10) + (unsigned int) '0');
					 myuint %= 10;
					 *(wp++) = (char) ((myuint) + (unsigned int) '0');
					 
					 rp = inp[++i];
				 }
			  break;
			case '%':
			  *(wp++) = '%';
			  break;
			default:
			  /*
				* oh shit 
				*/
			  sprintf(outp, formp, in0p, in1p, in2p, in3p,
						 in4p, in5p, in6p, in7p, in8p,
						 in9p, in10p);
			  return;
			  break;
		  }
   }
   *wp = '\0';
	
   return;
}

#else

void ircsprintf(char *outp, char *formp, ...) {
	va_list vl;
	char *f=formp, *o=outp, f, *rp;
	va_start(vl, formp);
	
   while ((f = *(fp++))) {
		if (f != '%')
		  *(wp++) = f;
      else
		  switch (*(fp++)) {
			  
			case 's':		/*
								 * put the most common case at the top 
								 */
			  rp=va_arg(vl, char *);
			  if (rp) {
				  while (*rp)
					 *wp++ = *rp++;
				  *wp = '\0';
			  }
			  else {
				  *wp++ = '{';
				  *wp++ = 'n';
				  *wp++ = 'u';
				  *wp++ = 'l';
				  *wp++ = 'l';
				  *wp++ = '}';
				  *wp++ = '\0';
			  }
			  break;
			case 'd':
				 {
					 int myint;
					 
					 myint = va_arg(vl, int);
					 
					 if (myint < 100 || myint > 999) {
						 vsprintf(outp, formp, vl);
						 return;
					 }
					 
					 *(wp++) = (char) ((myint / 100) + (int) '0');
					 myint %= 100;
					 *(wp++) = (char) ((myint / 10) + (int) '0');
					 myint %= 10;
					 *(wp++) = (char) ((myint) + (int) '0');
					 
				 }
			  break;
			case 'u':
				 {
					 unsigned int myuint;
					 
					 myuint = va_arg(vl, unsigned int);
					 
					 if (myuint < 100 || myuint > 999) {
						 vsprintf(outp, formp, vl);
						 return;
					 }
					 
					 *(wp++) = (char) ((myuint / 100) + (unsigned int) '0');
					 myuint %= 100;
					 *(wp++) = (char) ((myuint / 10) + (unsigned int) '0');
					 myuint %= 10;
					 *(wp++) = (char) ((myuint) + (unsigned int) '0');
					 
					 rp = inp[++i];
				 }
			  break;
			case '%':
			  *(wp++) = '%';
			  break;
			default:
			  /*
				* oh shit 
				*/
			  vsprintf(outp, formp, vl);
			  return;
			  break;
		  }
   }
   *wp = '\0';
	
	return;
}
#endif
