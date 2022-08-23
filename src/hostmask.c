/* Copyright (C) 1992 Darren Reed
 *
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifdef HAVE_UUID_H
#include <uuid/uuid.h>

#include "struct.h"
#include "numeric.h"
#include "h.h"


/*
 * Function is only called when user hostmasking is enabled and
 * bahamut is responsible for creating such vhosts. We can either
 * create a random hostmask or we can have it include parts of the user's 
 * real host. What value will the latter give us? -skill
 */
int user_hostmask(char *nick, char *orghost, char *orgip, char **newhost)
{
    snprintf(*newhost, HOSTLEN+1, "user/bahamut/%s", nick);
    return 1;
}