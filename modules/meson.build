# modules/meson.build
#
# Build loadable MAPI v1 modules.
# Core modules (modules/core/) are auto-loaded at startup and declare
# MAPI_CORE so they refuse MODULE UNLOAD.
# Extra modules (modules/extra/) are optional and fully unloadable.

module_cargs = ircd_cargs  # inherit compiler flags from src/

# ---------------------------------------------------------------------------
# Core modules — loaded automatically from <dpath>/modules/core/ at startup
# ---------------------------------------------------------------------------
foreach m : ['m_privmsg', 'm_away', 'm_wallops', 'm_who', 'm_gossip', 'm_gossip_eventlog', 'm_legacy_bridge']
  shared_library(m, 'core' / m + '.c',
    include_directories: inc,
    c_args: module_cargs,
    override_options: ['b_lundef=false'],
    install: true,
    install_dir: get_option('prefix') / 'modules' / 'core')
endforeach

# ---------------------------------------------------------------------------
# Extra modules — optional, fully unloadable
# ---------------------------------------------------------------------------
foreach m : ['m_webirc', 'm_rwho', 'm_watch', 'm_silence', 'm_dcc',
             'm_check', 'm_put',
             'm_away_notify', 'm_echo_message', 'm_server_time',
             'm_msgid', 'm_batch', 'm_labeled_response',
             'm_userhost_in_names', 'm_invite_notify',
             'm_setname', 'm_tagmsg',
             'm_session',
             'm_account_notify', 'm_account_tag', 'm_extended_join',
             'm_starttls', 'm_tls_tag',
             'm_chghost', 'm_bot_mode',
             'm_monitor', 'm_chathistory']
  shared_library(m, 'extra' / m + '.c',
    include_directories: inc,
    c_args: module_cargs,
    # Modules resolve symbols from the host ircd binary at dlopen() time.
    # Disable --no-undefined so the linker allows unresolved references.
    override_options: ['b_lundef=false'],
    install: true,
    install_dir: get_option('prefix') / 'modules' / 'extra')
endforeach
