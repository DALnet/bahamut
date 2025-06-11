#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h> // For malloc/free
#include <stdarg.h> // For va_list, va_start, va_end in sendto_one stub

/* --- Actual IRCd Includes --- */
// Assuming these headers are in a directory structure like project_root/include/
#include "../../include/struct.h"
#include "../../include/common.h"
#include "../../include/numeric.h"
#include "../../include/msg.h"
#include "../../include/channel.h"
#include "../../include/defs.h"      // Often included by other ircd headers for basic types
// <sys/types.h> is often included by defs.h or other low-level headers

// m_opme itself is declared in msg.h

/* --- Basic Assertion Macros --- */
#define ASSERT_TRUE(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "Assertion failed: %s (%s:%d)\n", message, __FILE__, __LINE__); \
            exit(1); \
        } else { \
            printf("Assertion passed: %s\n", message); \
        } \
    } while (0)

#define ASSERT_STRING_CONTAINS(haystack, needle, message) \
    do { \
        if (haystack == NULL || strstr(haystack, needle) == NULL) { \
            fprintf(stderr, "Assertion failed: String '%s' does not contain '%s' (%s:%d)\n", (haystack ? haystack : "NULL"), needle, message, __FILE__, __LINE__); \
            exit(1); \
        } else { \
            printf("Assertion passed: %s\n", message); \
        } \
    } while (0)

#define ASSERT_EQUALS_INT(expected, actual, message) \
     do { \
        if (expected != actual) { \
            fprintf(stderr, "Assertion failed: Expected %d but got %d for %s (%s:%d)\n", expected, actual, message, __FILE__, __LINE__); \
            exit(1); \
        } else { \
            printf("Assertion passed: %s (Expected: %d, Actual: %d)\n", message, expected, actual); \
        } \
    } while (0)

/* --- Global Stubs & Test Data --- */
aClient me;
aClient *test_admin_client_g = NULL;
aClient *test_normal_client_g = NULL;
aChannel *test_channel_g = NULL;
aChanMember *test_admin_chanmember_g = NULL;
aChanMember *test_normal_chanmember_g = NULL;

char last_sent_message[MAXBUFLEN];
char last_channel_message[MAXBUFLEN];

/* --- Stubs for Core IRCd Functions (dependencies of m_opme) --- */
// This `test_is_oper` field would ideally be part of the actual aOper struct linkage in anUser
// For simplicity in this test harness, we're assuming anUser can have this test-specific flag.
// This is a known simplification.
int IsAnOper(aClient *sptr) {
    printf("STUB: IsAnOper called for %s. Result: %d\n", sptr->name, (sptr->user && sptr->user->test_is_oper));
    return sptr->user && sptr->user->test_is_oper;
}

aChannel *find_channel(const char *name) {
    printf("STUB: find_channel called for %s\n", name);
    if (test_channel_g && strcmp(test_channel_g->chname, name) == 0) {
        return test_channel_g;
    }
    printf("STUB: find_channel: channel %s not found or does not match test_channel_g (%p)\n", name, (void*)test_channel_g);
    return NULL;
}

aChanMember *find_member_on_channel(aChannel *chptr, aClient *who) {
    printf("STUB: find_member_on_channel called for user %s on channel %s\n", who->name, chptr->chname);
    if (chptr == test_channel_g) {
        if (who == test_admin_client_g && test_admin_chanmember_g != NULL) {
             printf("STUB: find_member_on_channel: Found admin %s on channel %s\n", who->name, chptr->chname);
            return test_admin_chanmember_g;
        }
        if (who == test_normal_client_g && test_normal_chanmember_g != NULL) {
            printf("STUB: find_member_on_channel: Found normal user %s on channel %s\n", who->name, chptr->chname);
            return test_normal_chanmember_g;
        }
    }
    printf("STUB: find_member_on_channel: User %s NOT found or not associated with chanMember on channel %s\n", who->name, chptr->chname);
    return NULL;
}

void sendto_one(aClient *to, const char *pattern, ...) {
    va_list args;
    va_start(args, pattern);
    // Note: err_str often includes client name (parv[0]) which is sptr->name.
    // We need to simulate how err_str and sendto_one would combine these.
    // The real err_str returns a format string that sendto_one then processes.
    // Our stub for err_str returns a nearly complete message for simplicity.
    // So, this vsnprintf might not perfectly mimic the real sendto_one if pattern from err_str is complex.
    // However, for current err_str stubs, it should be okay.
    // For messages from err_str, they are already formatted with server name, error code, and client nick.
    // We just need to fill in the specific parameters like channel name or command name.
    // Example: err_str(ERR_NOSUCHCHANNEL) -> ":%s %d %s %s :No such channel"
    // sendto_one(sptr, actual_err_str_output, me.name, ERR_NOSUCHCHANNEL, sptr->name, channel_name)
    // The current err_str stub is too simple. Let's adjust it.

    char format_string[MAXBUFLEN];
    strncpy(format_string, pattern, MAXBUFLEN-1);

    // This part is tricky. The real sendto_one takes many specific args for some numerics.
    // Our m_opme calls sendto_one(sptr, err_str(ERR_X), me.name, sptr->name, specific_arg_if_any);
    // The err_str stub should return a format string like ":%s %d %s %s :No such channel"
    // And then sendto_one should populate it with me.name, ERR_X, sptr->name, specific_arg.
    // For simplicity, the last_sent_message will just capture the direct pattern + varargs here.
    // If pattern is from err_str, it means it's already mostly formatted.
    vsnprintf(last_sent_message, sizeof(last_sent_message), format_string, args);
    va_end(args);
    printf("STUB: sendto_one (to: %s): %s\n", to->name, last_sent_message);
}

void sendto_channel_butone(aClient *skip, aClient *from, aChannel *chptr, const char *pattern, ...) {
    va_list args;
    va_start(args, pattern);
    vsnprintf(last_channel_message, sizeof(last_channel_message), pattern, args);
    va_end(args);
    printf("STUB: sendto_channel_butone (from: %s, to_chan: %s, skip: %s): %s\n",
           from->name, chptr->chname, skip ? skip->name : "NULL" , last_channel_message);
}

// err_str returns a format string. sendto_one then fills it.
// Parameters to err_str are not standardized, it's just an int.
// The format strings returned by err_str are then used by sendto_one with specific arguments.
const char *err_str(int errnum) {
    // These are format strings that sendto_one will use.
    // e.g., sendto_one(sptr, err_str(ERR_NOSUCHCHANNEL), me.name, sptr->name, channel_name);
    // So err_str should return something like ":%s %d %s %s :No such channel" which sendto_one populates.
    switch(errnum) {
        case ERR_NOPRIVILEGES:   return ":%s %d %s :Permission Denied- You're not an IRC operator"; // args for sendto_one: me.name, sptr->name
        case ERR_NEEDMOREPARAMS: return ":%s %d %s %s :Not enough parameters"; // args for sendto_one: me.name, sptr->name, command_name
        case ERR_NOSUCHCHANNEL:  return ":%s %d %s %s :No such channel"; // args for sendto_one: me.name, sptr->name, channel_name
        case ERR_NOTONCHANNEL:   return ":%s %d %s %s :You're not on that channel"; // args for sendto_one: me.name, sptr->name, channel_name
        default: {
            static char default_err_buf[100]; // Static buffer for safety
            sprintf(default_err_buf, ":%%s %d %%s :Unknown error %d", errnum, errnum); // %%s for literal %s for server name and client name
            return default_err_buf;
            }
    }
}

/* --- Test Utility Functions --- */
aClient* test_create_client(const char* nick, const char* uname, const char* hname, int is_oper_flag) {
    aClient* client = (aClient*)calloc(1, sizeof(aClient));
    assert(client != NULL);

    strncpy(client->name, nick, NICKLEN);
    client->name[NICKLEN-1] = '\0';

    client->user = (anUser*)calloc(1, sizeof(anUser));
    assert(client->user != NULL);
    strncpy(client->user->username, uname, USERLEN);
    client->user->username[USERLEN-1] = '\0';
    strncpy(client->user->host, hname, HOSTLEN);
    client->user->host[HOSTLEN-1] = '\0';

    client->user->test_is_oper = is_oper_flag; // Test-specific flag for IsAnOper stub

    return client;
}

aChannel* test_create_channel(const char* name) {
    aChannel* channel = (aChannel*)calloc(1, sizeof(aChannel));
    assert(channel != NULL);
    strncpy(channel->chname, name, CHANNELLEN);
    channel->chname[CHANNELLEN-1] = '\0';
    return channel;
}

aChanMember* test_client_join_channel(aClient* client, aChannel* channel) {
    printf("SIM: Client %s joining channel %s\n", client->name, channel->chname);
    aChanMember* cm = (aChanMember*)calloc(1, sizeof(aChanMember));
    assert(cm != NULL);

    cm->user = client;      // Link ChanMember to client
    cm->channel = channel;  // Link ChanMember to channel
    cm->flags = 0;          // Initial flags

    if (client == test_admin_client_g) test_admin_chanmember_g = cm;
    else if (client == test_normal_client_g) test_normal_chanmember_g = cm;

    return cm;
}

void init_test_environment() {
    printf("SIM: Initializing test environment...\n");
    memset(&me, 0, sizeof(aClient));
    strncpy(me.name, "testserver.name", NICKLEN);
    me.name[NICKLEN-1] = '\0';

    // Ensure me.user is allocated if any code path might dereference it, even if not strictly used by m_opme logic directly.
    // For robust stubbing, 'me' should resemble a fully connected server client.
    me.user = (anUser*)calloc(1, sizeof(anUser));
    assert(me.user != NULL);
    strncpy(me.user->username, "server", USERLEN);
    strncpy(me.user->host, "internal.host", HOSTLEN);


    test_admin_client_g = NULL;
    test_normal_client_g = NULL;
    test_channel_g = NULL;
    test_admin_chanmember_g = NULL;
    test_normal_chanmember_g = NULL;
    last_sent_message[0] = '\0';
    last_channel_message[0] = '\0';
}

void cleanup_test_environment() {
    printf("SIM: Cleaning up test environment...\n");
    if (test_admin_chanmember_g) { free(test_admin_chanmember_g); test_admin_chanmember_g = NULL; }
    if (test_normal_chanmember_g) { free(test_normal_chanmember_g); test_normal_chanmember_g = NULL; }
    if (test_admin_client_g) { if(test_admin_client_g->user) free(test_admin_client_g->user); free(test_admin_client_g); test_admin_client_g = NULL; }
    if (test_normal_client_g) { if(test_normal_client_g->user) free(test_normal_client_g->user); free(test_normal_client_g); test_normal_client_g = NULL; }
    if (test_channel_g) { free(test_channel_g); test_channel_g = NULL; }
    if (me.user) {free(me.user); me.user = NULL;} // Clean up 'me.user'
}

void call_m_opme(aClient* client, const char* channel_param_const) {
    char* parv_non_const[MAXPARA + 1]; // m_opme expects char *parv[]
    char client_name_non_const[NICKLEN];
    char channel_param_non_const[CHANNELLEN];

    last_sent_message[0] = '\0';
    last_channel_message[0] = '\0';

    strncpy(client_name_non_const, client->name, NICKLEN);
    client_name_non_const[NICKLEN-1] = '\0';
    parv_non_const[0] = client_name_non_const;

    if (channel_param_const) {
        strncpy(channel_param_non_const, channel_param_const, CHANNELLEN);
        channel_param_non_const[CHANNELLEN-1] = '\0';
        parv_non_const[1] = channel_param_non_const;
        parv_non_const[2] = NULL;
        printf("SIM: Calling m_opme with parc=2, user=%s, channel=%s\n", client->name, parv_non_const[1]);
        m_opme(client, client, 2, parv_non_const);
    } else {
        parv_non_const[1] = NULL;
        printf("SIM: Calling m_opme with parc=1, user=%s, no channel\n", client->name);
        m_opme(client, client, 1, parv_non_const);
    }
}

/* --- Test Cases --- */
void test_admin_ops_self_successfully() {
    printf("\n--- Test: Admin Ops Self Successfully ---\n");
    init_test_environment();
    test_admin_client_g = test_create_client("AdminUser", "admin", "admin.host", 1);
    test_channel_g = test_create_channel("#testchan");
    test_admin_chanmember_g = test_client_join_channel(test_admin_client_g, test_channel_g);

    call_m_opme(test_admin_client_g, "#testchan");

    // Expected message to user: ":AdminUser MODE #testchan +o AdminUser"
    // This is sent by the second sendto_one in m_opme
    ASSERT_STRING_CONTAINS(last_sent_message, ":AdminUser MODE #testchan +o AdminUser", "Admin should receive MODE +o from self");

    // Expected message to channel: ":testserver.name MODE #testchan +o AdminUser"
    // This is sent by sendto_channel_butone
    ASSERT_STRING_CONTAINS(last_channel_message, ":testserver.name MODE #testchan +o AdminUser", "Channel should receive MODE +o from server");

    ASSERT_TRUE((test_admin_chanmember_g->flags & CHFL_CHANOP), "AdminUser should have CHFL_CHANOP flag set");

    cleanup_test_environment();
}

void test_non_admin_fails_to_op_self() {
    printf("\n--- Test: Non-Admin Fails to Op Self ---\n");
    init_test_environment();
    test_normal_client_g = test_create_client("NormalUser", "user", "user.host", 0);
    test_channel_g = test_create_channel("#testchan");
    test_normal_chanmember_g = test_client_join_channel(test_normal_client_g, test_channel_g);

    call_m_opme(test_normal_client_g, "#testchan");

    // Expected from sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, sptr->name)
    // err_str returns ":%s %d %s :Permission Denied..."
    // sendto_one fills with me.name, ERR_NOPRIVILEGES, sptr->name
    // So, ":testserver.name 481 NormalUser :Permission Denied..."
    ASSERT_STRING_CONTAINS(last_sent_message, ":testserver.name 481 NormalUser :Permission Denied", "NormalUser should receive ERR_NOPRIVILEGES (481)");

    ASSERT_TRUE(!(test_normal_chanmember_g->flags & CHFL_CHANOP), "NormalUser should NOT have CHFL_CHANOP flag set");

    cleanup_test_environment();
}

void test_admin_opme_non_existent_channel() {
    printf("\n--- Test: Admin Opme Non-Existent Channel ---\n");
    init_test_environment();
    test_admin_client_g = test_create_client("AdminUser", "admin", "admin.host", 1);

    call_m_opme(test_admin_client_g, "#nonexistent");

    // Expected: ":testserver.name 403 AdminUser #nonexistent :No such channel"
    ASSERT_STRING_CONTAINS(last_sent_message, ":testserver.name 403 AdminUser #nonexistent :No such channel", "AdminUser should receive ERR_NOSUCHCHANNEL (403)");

    cleanup_test_environment();
}

void test_admin_opme_not_on_channel() {
    printf("\n--- Test: Admin Opme Not On Channel ---\n");
    init_test_environment();
    test_admin_client_g = test_create_client("AdminUser", "admin", "admin.host", 1);
    test_channel_g = test_create_channel("#channel_exists");
    // AdminUser is not "on" the channel (test_admin_chanmember_g is NULL)

    call_m_opme(test_admin_client_g, "#channel_exists");

    // Expected: ":testserver.name 442 AdminUser #channel_exists :You're not on that channel"
    ASSERT_STRING_CONTAINS(last_sent_message, ":testserver.name 442 AdminUser #channel_exists :You're not on that channel", "AdminUser should receive ERR_NOTONCHANNEL (442)");

    cleanup_test_environment();
}

void test_opme_need_more_params() {
    printf("\n--- Test: OPME Need More Params ---\n");
    init_test_environment();
    test_admin_client_g = test_create_client("AdminUser", "admin", "admin.host", 1);

    call_m_opme(test_admin_client_g, NULL);

    // Expected: ":testserver.name 461 AdminUser OPME :Not enough parameters"
    // (The command "OPME" is passed as the parv[4] to sendto_one in m_opme)
    ASSERT_STRING_CONTAINS(last_sent_message, ":testserver.name 461 AdminUser OPME :Not enough parameters", "AdminUser should receive ERR_NEEDMOREPARAMS (461)");

    cleanup_test_environment();
}

/* --- Main Test Runner --- */
int main() {
    printf("Starting /opme command tests (calling actual m_opme)...\n");

    test_admin_ops_self_successfully();
    test_non_admin_fails_to_op_self();
    test_admin_opme_non_existent_channel();
    test_admin_opme_not_on_channel();
    test_opme_need_more_params();

    printf("\nAll /opme command tests finished successfully.\n");
    return 0;
}
