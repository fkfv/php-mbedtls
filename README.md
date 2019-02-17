mbedTLS for PHP
===============

The extension provides a way to interact with the mbedTLS SSL/TLS library from
PHP source code.

Enabling the extension
======================

The extension will require the mbedTLS shared library and header files be
available to the PHP build system.

To build a shared binary version of the extension, run the following:

```bash
phpize
configure --enable-mbedtls
make # nmake on windows
```

License & Contributing
======================

This project is licensed under the MIT license. The license is included in the
LICENSE file and is available online at https://opensource.org/licenses/MIT
