/*
 * include/cmds.h - Dynamic command registry for Bahamut IRC Server
 *
 * Allows modules to register and unregister IRC commands at runtime,
 * without modifying the static msgtab[] in msg.h.
 *
 * The dynamic registry is checked when the static trie lookup fails,
 * so dynamically registered commands are fully visible to parse().
 */

#ifndef CMDS_H
#define CMDS_H

struct Message;
struct mapi_cmd_av2;

/*
 * cmd_add - register a new IRC command dynamically from a mapi_cmd_av2 entry.
 *
 * @av2:  pointer to the command descriptor (cmd, reset_idle, handlers[]).
 *
 * Returns 0 on success, -1 if the command is already registered
 * (either in the static table or the dynamic registry).
 */
int cmd_add(const struct mapi_cmd_av2 *av2);

/*
 * cmd_del - unregister a dynamically-registered command.
 *
 * Only commands previously added with cmd_add() can be removed.
 * Static msgtab[] commands cannot be removed at runtime.
 */
void cmd_del(const char *cmd);

/*
 * cmd_find_dynamic - look up a command in the dynamic registry.
 *
 * Returns a pointer to the Message struct on success, NULL if not found.
 * This is used internally by parse() as a fallback after the static trie.
 */
struct Message *cmd_find_dynamic(const char *cmd);

#endif /* CMDS_H */
