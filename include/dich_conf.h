/************************************************************************
 *   IRC - Internet Relay Chat, include/dich_conf.h
 *   Copyright (C) 1995 Philippe Levan
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
/*
 * The dich_conf.h and dich_conf.c were written to provide a generic
 * interface for configuration lines matching. I decided to write it
 * after I read Roy's K: line tree patch. the underlying ideas are the
 * following : . get rid of the left/right branches by using a
 * dichotomy on an ordered list . arrange patterns matching one another
 * in a tree so that if we find a possible match, all other possible
 * matches are "below" These routines are meant for fast matching.
 * There is no notion of "best" of "first" (meaning the order in which
 * the lines are read) match. Therefore, the following functions are
 * fit for K: lines matching but not I: lines matching (as sad as it
 * may be). Other kinds of configuration lines aren't as time consuming
 * or just aren't use for matching so it's irrelevant to try and use
 * these functions for anything else. However, I still made them as
 * generic as possible, just in case.
 * 
 * -Soleil (Philippe Levan)
 * 
 */

/* $Id$ */

#ifndef __dich_conf_h__
#define __dich_conf_h__

#include "struct.h"

typedef struct ConfList aConfList;
typedef struct ConfEntry aConfEntry;

struct ConfList 
{
    unsigned int length;
    aConfEntry *conf_list;
};

struct ConfEntry 
{
    char       *pattern;
    aConfItem  *conf;
    aConfEntry *next;
    aConfList  *sub;
};

extern void addto_conf_list();
extern void clear_conf_list();
extern aConfItem *find_matching_conf();
extern void l_addto_conf_list();
extern aConfItem *l_find_matching_conf();
extern char *host_field();
extern char *name_field();
extern char *rev_host_field();
extern char *rev_name_field();
extern int  sortable();
extern void reverse(char *, char *);

#endif
