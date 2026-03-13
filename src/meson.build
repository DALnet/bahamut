host_os = host_machine.system()

# ---------------------------------------------------------------------------
# Socket engine selection
# ---------------------------------------------------------------------------
engine_opt = get_option('socketengine')

if engine_opt == 'auto'
  if host_os == 'linux'
    engine_src = 'socketengine_epoll.c'
  elif host_os in ['freebsd', 'netbsd', 'openbsd', 'darwin']
    engine_src = 'socketengine_kqueue.c'
  elif host_os == 'sunos'
    engine_src = 'socketengine_devpoll.c'
  else
    engine_src = 'socketengine_poll.c'
  endif
elif engine_opt == 'epoll'
  engine_src = 'socketengine_epoll.c'
elif engine_opt == 'kqueue'
  engine_src = 'socketengine_kqueue.c'
elif engine_opt == 'devpoll'
  engine_src = 'socketengine_devpoll.c'
elif engine_opt == 'poll'
  engine_src = 'socketengine_poll.c'
elif engine_opt == 'select'
  engine_src = 'socketengine_select.c'
endif

message('Socket engine: ' + engine_src)

# ---------------------------------------------------------------------------
# Generate version.c
# ---------------------------------------------------------------------------
python = find_program('python3', required: true)

version_c = custom_target('version_c',
  output:  'version.c',
  command: [python, meson.project_source_root() / 'src/gen_version.py',
            '@OUTPUT@', meson.project_source_root()],
  build_always_stale: true)

# ---------------------------------------------------------------------------
# Compiler flags and defines
# ---------------------------------------------------------------------------
ircd_cargs = [
  '-fno-strict-aliasing',
  # TODO: audit inline functions in ircsprintf.c and channel.c and convert
  # to static inline so this GNU89-ism can be dropped.
  '-fgnu89-inline',
  '-DHAVE_ENCRYPTION_ON=1',
]

if get_option('hookmodules')
  ircd_cargs += '-DUSE_HOOKMODULES=1'
endif

ircd_cargs += '-DMAXCONNECTIONS=@0@'.format(get_option('maxconnections'))

# ---------------------------------------------------------------------------
# Source files
# ---------------------------------------------------------------------------
ircd_sources = [
  'base64.c',
  'batch.c',
  'bitncmp.c',
  'gossip_event.c',
  'gossip.c',
  'gossip_dedup.c',
  'gossip_bridge.c',
  'session.c',
  's_gopeer.c',
  'blalloc.c',
  'bsd.c',
  'cap.c',
  'channel.c',
  'clientlist.c',
  'clones.c',
  'confparse.c',
  'fdlist.c',
  'fds.c',
  'hash.c',
  'hide.c',
  'inet_addr.c',
  'inet_parse_cidr.c',
  'ircd.c',
  'ircsprintf.c',
  'klines.c',
  'libcrypto-compat.c',
  'list.c',
  'm_cap.c',
  'm_nick.c',
  'm_server.c',
  'm_services.c',
  'm_stats.c',
  'match.c',
  'memcount.c',
  'modules.c',
  'msgbuf.c',
  'packet.c',
  'parse.c',
  'pcre.c',
  'pcre_chartables.c',
  'probability.c',
  'res.c',
  's_auth.c',
  's_bsd.c',
  's_conf.c',
  's_debug.c',
  's_err.c',
  's_misc.c',
  's_numeric.c',
  's_serv.c',
  's_user.c',
  'sbuf.c',
  'scache.c',
  'send.c',
  'spamfilter.c',
  'ssl.c',
  'struct.c',
  'support.c',
  'throttle.c',
  'userban.c',
  'websocket.c',
  'whowas.c',
  'zlink.c',
  engine_src,
  version_c,
]

# ---------------------------------------------------------------------------
# Link dependencies
# ---------------------------------------------------------------------------
ircd_deps = [openssl_dep, zlib_dep]

if dl_dep.found()
  ircd_deps += dl_dep
endif
if crypt_dep.found()
  ircd_deps += crypt_dep
endif
if nsl_dep.found()
  ircd_deps += nsl_dep
endif

# ---------------------------------------------------------------------------
# ircd binary
# ---------------------------------------------------------------------------
executable('ircd',
  ircd_sources,
  include_directories: inc,
  c_args:              ircd_cargs,
  dependencies:        ircd_deps,
  link_args:           ['-Wl,-export-dynamic'],
  install:             true,
  install_dir:         get_option('prefix'))
