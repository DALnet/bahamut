executable('mkpasswd',
  'mkpasswd.c',
  include_directories: inc,
  dependencies:        [openssl_dep, crypt_dep],
  install:             true,
  install_dir:         get_option('prefix'))

# Install certificate generation helpers
install_data('make-cert.tmpl', 'make-cert.cnf',
  install_dir: get_option('prefix'))
