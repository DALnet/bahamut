/************************************************************************
 *   IRC - Internet Relay Chat, src/inifile.c
 *   Copyright (C) 2003 Lucas Madar / Bahamut
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "queue.h"
#include "h.h"

struct ini_pair {
   char *name;
   char *value;

   TAILQ_ENTRY(ini_pair) lp;
};
TAILQ_HEAD(ini_pair_tailq, ini_pair);

struct ini_section {
   char *section_name;
   struct ini_pair_tailq ini_pairs;

   TAILQ_ENTRY(ini_section) lp;
};
TAILQ_HEAD(ini_section_tailq, ini_section);

struct ini_file {
   char *fn;
   struct ini_section_tailq ini_sections;
};

void ini_close(void *ini_opaque)
{
   struct ini_section *se;
   struct ini_pair *ip;
   struct ini_file *ifl = (struct ini_file *) ini_opaque;

   while(!TAILQ_EMPTY(&ifl->ini_sections))
   {
      se = TAILQ_FIRST(&ifl->ini_sections);

      while(!TAILQ_EMPTY(&se->ini_pairs))
      {
         ip = TAILQ_FIRST(&se->ini_pairs);
         TAILQ_REMOVE(&se->ini_pairs, ip, lp);

         if(ip->name != NULL)
            MyFree(ip->name);
         if(ip->value != NULL)
            MyFree(ip->value);
         MyFree(ip);
      }

      TAILQ_REMOVE(&ifl->ini_sections, se, lp);
      if(se->section_name != NULL)
         MyFree(se->section_name);
      MyFree(se);
   }
   
   if(ifl->fn != NULL)
      MyFree(ifl->fn);
   MyFree(ifl);
}

static struct ini_section *find_or_add_inisection(struct ini_section_tailq *sects, 
                                                  char *sectname, int add)
{
   struct ini_section *se;
   TAILQ_FOREACH(se, sects, lp) 
   {
      if(mycmp(se->section_name, sectname) == 0)
         return se;
   }

   if(!add) 
      return NULL;

   se = (struct ini_section *) MyMalloc(sizeof(struct ini_section));
   se->section_name = (char *) MyMalloc(strlen(sectname) + 1);
   strcpy(se->section_name, sectname);

   TAILQ_INIT(&se->ini_pairs);
   TAILQ_INSERT_TAIL(sects, se, lp);

   return se;
}

static struct ini_pair *find_or_add_inipair(struct ini_pair_tailq *pairs, char *pairname, int add)
{
   struct ini_pair *ip;
   TAILQ_FOREACH(ip, pairs, lp) 
   {
      if(mycmp(ip->name, pairname) == 0)
         return ip;
   }

   if(!add)
      return NULL;

   ip = (struct ini_pair *) MyMalloc(sizeof(struct ini_pair));
   ip->name = (char *) MyMalloc(strlen(pairname) + 1);
   strcpy(ip->name, pairname);
   ip->value = NULL;

   TAILQ_INSERT_TAIL(pairs, ip, lp);

   return ip;
}

char *ini_get_value(void *ini_opaque, char *section, char *name)
{
   struct ini_file *ifl = (struct ini_file *) ini_opaque;
   struct ini_section *se = find_or_add_inisection(&ifl->ini_sections, section, 0);
   struct ini_pair *ip = (se) ? (find_or_add_inipair(&se->ini_pairs, name, 0)) : NULL;

   return (ip) ? (ip->value) : NULL;
}

void ini_set_value(void *ini_opaque, char *section, char *name, char *newvalue)
{
   struct ini_file *ifl = (struct ini_file *) ini_opaque;
   struct ini_section *se = find_or_add_inisection(&ifl->ini_sections, section, 1);
   struct ini_pair *ip = find_or_add_inipair(&se->ini_pairs, name, 1);

   if(ip->value != NULL)
      MyFree(ip->value);

   ip->value = (char *) MyMalloc(strlen(newvalue) + 1);
   strcpy(ip->value, newvalue);
}

int ini_save(void *ini_opaque)
{
   struct ini_section *se;
   struct ini_pair *ip;
   struct ini_file *ifl = (struct ini_file *) ini_opaque;
   FILE *fp = fopen(ifl->fn, "w");

   if(!fp)
      return -1;

   TAILQ_FOREACH(se, &ifl->ini_sections, lp)
   {
      fprintf(fp, "[%s]\n", se->section_name);
      TAILQ_FOREACH(ip, &se->ini_pairs, lp)
      {
         if(ip->value != NULL)
           fprintf(fp, "%s=%s\n", ip->name, ip->value);
      }
      fprintf(fp, "\n");
   }   

   fclose(fp);
   return 0;      
}

static void ini_read(FILE *fp, void *ini_opaque)
{
   char linebuf[4096];
   char cursec[4096];
   char *x, *e, *v;
   int iidx;

   strcpy(cursec, "DEFAULT");
   while(fgets(linebuf, 8192, fp))
   {
      x = linebuf;
      while(*x == ' ')
         x++;

      /* comments! */
      if(*x == '#' || *x == ';')
         continue;

      /* do we have a section name? */
      if(*x == '[')
      {
         x++;
         e = strchr(x, ']');
         if(!e)
            continue;
         *e = '\0';

         strcpy(cursec, x);
         continue;
      }

      v = strchr(x, '=');
      if(!v)
         continue;

      *v = '\0';
      v++;
      while(*v == ' ')
         v++;

      /* chop accursed CRLF! */
      e = strchr(v, '\r');
      if(e)
         *e = '\0';
      e = strchr(v, '\n');
      if(e)
         *e = '\0';

      /* chop spaces off the end of the name and value */
      while(x[(iidx = (strlen(x) - 1))] == ' ')
         x[iidx] = '\0';
      while(v[(iidx = (strlen(v) - 1))] == ' ')
         v[iidx] = '\0';

      if(*x == '\0' || *v == '\0')
         continue;

      ini_set_value(ini_opaque, cursec, x, v);
   }
}

void *ini_open(char *fn)
{
   FILE *fp = fopen(fn, "r");
   struct ini_file *ifl;

   if(!fp)
   {
      if(errno != ENOENT)
         return NULL;
   }

   ifl = (struct ini_file *) MyMalloc(sizeof(struct ini_file));
   ifl->fn = (char *) MyMalloc(strlen(fn) + 1);
   strcpy(ifl->fn, fn);
   TAILQ_INIT(&ifl->ini_sections);

   if(fp)
   {
      ini_read(fp, ifl);
      fclose(fp);
   }

   return (void *) ifl;
}

