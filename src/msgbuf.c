/*
 * src/msgbuf.c - IRCv3 message-tag buffer parsing for Bahamut IRC Server
 *
 * parse_msgbuf() tokenises an @key=val;key2;key3=val3 tag block in-place,
 * filling a MsgBuf's tags[] array.  The caller must have already stripped
 * the leading '@' before passing the pointer.
 *
 * Tag format (IRCv3 spec):
 *   @tag-block SP rest
 *   tag-block = tag *( ';' tag )
 *   tag        = key [ '=' value ]
 *   key        = [ vendor '/' ] tag-name
 *   value      = *( %x01-06 / %x08-09 / %x0B-0C / %x0E-1F / %x21-3A / %x3C-FF )
 *
 * Escape sequences in values (\: → ;, \s → space, \\ → \, \r → CR, \n → LF)
 * are NOT decoded here — handlers that care must unescape themselves.
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "msgbuf.h"

#include <string.h>

/*
 * parse_msgbuf - parse the @tag block into mb.
 *
 * s   : first character after the '@' that opens the tag block.
 * mb  : output struct; tags[] and n_tags are filled.
 *
 * Returns a pointer to the first non-tag, non-space character of the
 * remainder of the line (i.e. the start of the : prefix or command).
 *
 * Tags beyond MAXMSGTAGS are silently discarded.
 */
char *
parse_msgbuf(struct MsgBuf *mb, char *s)
{
    char *p;
    int   n = 0;

    /* Walk through semicolon-separated tags until we hit a space or NUL. */
    while (*s && *s != ' ')
    {
        const char *key_start = s;
        const char *val_start = NULL;

        /* Scan to '=', ';', ' ', or end */
        for (p = s; *p && *p != '=' && *p != ';' && *p != ' '; p++)
            ;

        if (*p == '=')
        {
            /* Key ends at '='; value starts after it */
            *p = '\0';
            val_start = p + 1;
            p = p + 1;
            /* Scan to ';', ' ', or end */
            while (*p && *p != ';' && *p != ' ')
                p++;
        }

        /* Terminate key (or key+value segment) */
        int at_end = 0;
        if (*p == ';' || *p == ' ')
        {
            at_end = (*p == ' ');
            *p++ = '\0';
        }
        /* else *p == '\0' — natural end */

        /* Store tag if we have room */
        if (n < MAXMSGTAGS && *key_start)
        {
            mb->tags[n].key   = key_start;
            mb->tags[n].value = val_start;   /* NULL for boolean tags */
            n++;
        }

        s = p;
        if (at_end || !*s)
            break;
    }

    mb->n_tags = n;

    /* Skip any spaces between tag block and the rest of the line */
    while (*s == ' ')
        s++;

    return s;
}

/*
 * msgbuf_get_tag - look up a tag value by key (case-sensitive).
 *
 * Returns the value string (may be the empty string "" for boolean tags),
 * or NULL if the tag is not present.
 */
const char *
msgbuf_get_tag(const struct MsgBuf *mb, const char *key)
{
    int i;
    for (i = 0; i < mb->n_tags; i++)
    {
        if (strcmp(mb->tags[i].key, key) == 0)
            return mb->tags[i].value ? mb->tags[i].value : "";
    }
    return NULL;
}
