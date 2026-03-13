/*
 * include/msgbuf.h - IRCv3 message tag buffer for Bahamut IRC Server
 *
 * Defines MsgBuf, which carries a raw IRC line plus any parsed @key=value
 * tags that precede it.  All handlers receive a pointer to this struct as
 * their first argument.  If no tags were present, n_tags == 0.
 */

#ifndef MSGBUF_H
#define MSGBUF_H

/* Maximum number of tags we will parse per message (silently drop extras). */
#define MAXMSGTAGS 32

/*
 * MsgTag - one key/value pair from the @tag block.
 * key   always points into MsgBuf.raw.
 * value points into MsgBuf.raw, or is NULL for boolean (value-less) tags.
 */
struct MsgTag {
    const char *key;
    const char *value;
};

/*
 * MsgBuf - scratch buffer for one incoming IRC line.
 *
 * raw[]   : the input line, NUL-terminated, in-place modified by the parser.
 * n_tags  : number of parsed tags stored in tags[].
 * tags[]  : parsed tags (key/value pointers into raw[]).
 *
 * Always stack-allocated in parse(); always passed by pointer to handlers.
 * Handlers MUST NOT retain the pointer beyond the call.
 */
struct MsgBuf {
    char          raw[BUFSIZE + 1];
    int           n_tags;
    struct MsgTag tags[MAXMSGTAGS];
};

/*
 * msgbuf_get_tag - look up a tag value by key (case-sensitive).
 *
 * Returns the value string, or NULL if the tag is absent.
 * For boolean (value-less) tags the return value is the empty string "".
 */
const char *msgbuf_get_tag(const struct MsgBuf *mb, const char *key);

/*
 * parse_msgbuf - parse an @tag string into mb.
 *
 * s     : pointer to the first character AFTER the leading '@'.
 * mb    : output buffer; tags[] and n_tags are filled.
 *
 * Returns a pointer to the first non-tag, non-space character of the
 * remainder of the line (i.e. the start of the prefix or command).
 */
char *parse_msgbuf(struct MsgBuf *mb, char *s);

#endif /* MSGBUF_H */
