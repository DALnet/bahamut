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

# Global include path (covers both the source include/ dir and the build dir
# for any generated headers)
inc = [
  include_directories('include'),
  include_directories('.'),
]

subdir('src')
subdir('modules')
subdir('tools')
