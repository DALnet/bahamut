/************************************************************************
 *   IRC - Internet Relay Chat, include/find.h
 *   Copyright (C) 2000 
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

/* $Id$ */

#ifndef	__find_include__
#define __find_include__

#define find_server(a, b)       hash_find_server(a, b)
#define find_name(a, b)         hash_find_server(a, b)
#define find_client(a, b)       hash_find_client(a, b)
 
static inline aClient *find_person(char *name, aClient *cptr)
{
   aClient *acptr = find_client(name, cptr);
 
   return acptr ? (IsClient(acptr) ? acptr : cptr) : cptr;
} 

#endif /*
        * __find_include__ 
        */
