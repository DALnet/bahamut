project('bahamut', 'c',
  version: '3.0.0',
  license: 'GPL-2.0-or-later',
  default_options: [
    'c_std=c11',
    'warning_level=1',
  ],
  meson_version: '>=0.56.0')

cc = meson.get_compiler('c')

# Required dependencies
openssl_dep = dependency('openssl', required: true)
zlib_dep    = dependency('zlib',    required: true)

# Optional platform libraries
dl_dep    = cc.find_library('dl',    required: false)
crypt_dep = cc.find_library('crypt', required: false)
nsl_dep   = cc.find_library('nsl',   required: false)

# ---------------------------------------------------------------------------
# Feature detection — generates include/setup.h
# ---------------------------------------------------------------------------
cdata = configuration_data()

# Functions
foreach f : [
  'alarm', 'bcmp', 'bcopy', 'bzero', 'dlopen', 'dlsym',
  'dn_expand', 'dn_skipname', 'dup2',
  'gethostbyname', 'gethostname', 'getpass', 'getrusage', 'gettimeofday',
  'index', 'inet_addr', 'inet_aton', 'inet_netof', 'inet_ntoa', 'isascii',
  'lrand48', 'memmove', 'memset', 'munmap',
  'res_init', 'res_mkquery', 'setenv', 'sigaction', 'socket',
  'strcasecmp', 'strchr', 'strdup', 'strerror', 'strncasecmp',
  'strrchr', 'strtok', 'strtol', 'strtoul', 'times',
  '__dn_expand', '__dn_skipname', '__res_init', '__res_mkquery',
]
  if cc.has_function(f)
    cdata.set('HAVE_' + f.to_upper(), 1)
  endif
endforeach

# Headers
foreach h : [
  'errno.h', 'fcntl.h', 'getopt.h', 'inttypes.h', 'limits.h',
  'malloc.h', 'netdb.h', 'netinet/in.h',
  'stddef.h', 'stdint.h', 'stdio.h', 'stdlib.h',
  'string.h', 'strings.h', 'syslog.h',
  'sys/file.h', 'sys/ioctl.h', 'sys/param.h', 'sys/resource.h',
  'sys/socket.h', 'sys/stat.h', 'sys/time.h', 'sys/types.h',
  'unistd.h', 'zlib.h',
]
  if cc.has_header(h)
    cdata.set('HAVE_' + h.underscorify().to_upper(), 1)
  endif
endforeach

# Libraries
if crypt_dep.found()
  cdata.set('HAVE_LIBCRYPT', 1)
endif
if dl_dep.found()
  cdata.set('HAVE_LIBDL', 1)
endif
if nsl_dep.found()
  cdata.set('HAVE_LIBNSL', 1)
endif
if zlib_dep.found()
  cdata.set('HAVE_LIBZ', 1)
endif

# MIN/MAX macros
if cc.compiles('#include <sys/param.h>\nint x = MIN(1,2);', name: 'HAVE_MINMAX')
  cdata.set('HAVE_MINMAX', 1)
endif

# WRITEV_IOV
if cc.has_function('writev')
  cdata.set('WRITEV_IOV', 64)
endif

# Standard C headers
cdata.set('STDC_HEADERS', 1)

# OpenSSL
cdata.set('HAVE_ENCRYPTION_ON', 1)

# Loadable modules
if get_option('hookmodules')
  cdata.set('USE_HOOKMODULES', 1)
endif

# Max connections
cdata.set('MAXCONNECTIONS', get_option('maxconnections'))

configure_file(
  output: 'setup.h',
  configuration: cdata,
  install: false,
)

# Global include path (covers both the source include/ dir and the build dir
# for generated setup.h)
inc = [
  include_directories('include'),
  include_directories('.'),
]

subdir('src')
subdir('modules')
subdir('tools')
