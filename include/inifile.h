#ifndef INIFILE_H
#define INIFILE_H

void *ini_open(char *);
void ini_close(void *);
int ini_save(void *);
char *ini_get_value(void *, char *, char *);

#endif
