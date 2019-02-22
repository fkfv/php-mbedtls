/*******************************************************************************
 * Copyright (c) Matthew
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * mbedTLS extension for PHP
*******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "ext/standard/info.h"
#include "php_mbedtls.h"

#include <mbedtls/pk.h>

// cipher.c
ZEND_BEGIN_ARG_INFO_EX(arginfo_mbedtls_encrypt, 0, 0, 3)
  ZEND_ARG_INFO(0, data)
  ZEND_ARG_INFO(0, method)
  ZEND_ARG_INFO(0, key)
  ZEND_ARG_INFO(0, options)
  ZEND_ARG_INFO(0, iv)
  ZEND_ARG_INFO(1, tag)
  ZEND_ARG_INFO(0, aad)
  ZEND_ARG_INFO(0, tag_length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_mbedtls_decrypt, 0, 0, 3)
  ZEND_ARG_INFO(0, data)
  ZEND_ARG_INFO(0, method)
  ZEND_ARG_INFO(0, key)
  ZEND_ARG_INFO(0, options)
  ZEND_ARG_INFO(0, iv)
  ZEND_ARG_INFO(0, tag)
  ZEND_ARG_INFO(0, aad)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_mbedtls_ciphers, 0, 0, 0)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(arginfo_mbedtls_pkey_new, 0, 0, 0)
  ZEND_ARG_INFO(0, configargs)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_mbedtls_pkey_free, 0, 0, 1)
  ZEND_ARG_INFO(0, pkey)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_mbedtls_pkey_export, 0, 0, 2)
  ZEND_ARG_INFO(0, pkey)
  ZEND_ARG_INFO(1, out)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_mbedtls_pkey_export_to_file, 0, 0, 2)
  ZEND_ARG_INFO(0, pkey)
  ZEND_ARG_INFO(0, file)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_mbedtls_pkey_get_detials, 0, 0, 1)
  ZEND_ARG_INFO(0, pkey)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_mbedtls_pkey_get_public, 0, 0, 1)
  ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_mbedtls_pkey_get_private, 0, 0, 1)
  ZEND_ARG_INFO(0, key)
  ZEND_ARG_INFO(0, password)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_mbedtls_csr_new, 0, 0, 2)
  ZEND_ARG_INFO(0, dn)
  ZEND_ARG_INFO(0, privkey)
  ZEND_ARG_INFO(0, configargs)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_mbedtls_csr_sign, 0, 0, 4)
  ZEND_ARG_INFO(0, csr)
  ZEND_ARG_INFO(0, ca)
  ZEND_ARG_INFO(0, cakey)
  ZEND_ARG_INFO(0, days)
  ZEND_ARG_INFO(0, configargs)
  ZEND_ARG_INFO(0, serial)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_mbedtls_csr_export, 0, 0, 2)
  ZEND_ARG_INFO(0, csr)
  ZEND_ARG_INFO(1, out)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_mbedtls_csr_export_to_file, 0, 0, 2)
  ZEND_ARG_INFO(0, csr)
  ZEND_ARG_INFO(0, file)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_mbedtls_csr_get_subject, 0, 0, 1)
  ZEND_ARG_INFO(0, csr)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_mbedtls_csr_get_public_key, 0, 0, 1)
  ZEND_ARG_INFO(0, csr)
ZEND_END_ARG_INFO()

int le_pkey = 0;
int le_csr = 0;
int le_crt = 0;

PHP_MINIT_FUNCTION(mbedtls)
{
  // cipher.c
  REGISTER_LONG_CONSTANT("MBEDTLS_ZERO_PADDING", MBEDTLS_ZERO_PADDING, CONST_CS | CONST_PERSISTENT);
  REGISTER_LONG_CONSTANT("MBEDTLS_RAW_DATA"    , MBEDTLS_RAW_DATA    , CONST_CS | CONST_PERSISTENT);

  // pkey.c
  REGISTER_LONG_CONSTANT("MBEDTLS_KEYTYPE_RSA", MBEDTLS_PK_RSA  , CONST_CS | CONST_PERSISTENT);
  REGISTER_LONG_CONSTANT("MBEDTLS_KEYTYPE_EC" , MBEDTLS_PK_ECKEY, CONST_CS | CONST_PERSISTENT);

  le_pkey = zend_register_list_destructors_ex(php_mbedtls_pkey_free, NULL, MBEDTLS_PKEY_RESOURCE, module_number);

  // csr.c
  le_csr = zend_register_list_destructors_ex(php_mbedtls_csr_free, NULL, MBEDTLS_CSR_RESOURCE, module_number);

  // crt.c
  le_crt = zend_register_list_destructors_ex(php_mbedtls_crt_free, NULL, MBEDTLS_CRT_RESOURCE, module_number);

  return SUCCESS;
}

PHP_MINFO_FUNCTION(mbedtls)
{
  php_info_print_table_start();
  php_info_print_table_header(2, "mbedtls support", "enabled");
  php_info_print_table_end();
}

static const zend_function_entry mbedtls_functions[] = {
  // cipher.c
  PHP_FE(mbedtls_encrypt, arginfo_mbedtls_encrypt)
  PHP_FE(mbedtls_decrypt, arginfo_mbedtls_decrypt)
  PHP_FE(mbedtls_ciphers, arginfo_mbedtls_ciphers)

  // pkey.c
  PHP_FE(mbedtls_pkey_new           , arginfo_mbedtls_pkey_new)
  PHP_FE(mbedtls_pkey_free          , arginfo_mbedtls_pkey_free)
  PHP_FE(mbedtls_pkey_export        , arginfo_mbedtls_pkey_export)
  PHP_FE(mbedtls_pkey_export_to_file, arginfo_mbedtls_pkey_export_to_file)
  PHP_FE(mbedtls_pkey_get_details   , arginfo_mbedtls_pkey_get_detials)
  PHP_FE(mbedtls_pkey_get_public    , arginfo_mbedtls_pkey_get_public)
  PHP_FE(mbedtls_pkey_get_private   , arginfo_mbedtls_pkey_get_private)

  // csr.c
  PHP_FE(mbedtls_csr_new           , arginfo_mbedtls_csr_new)
  PHP_FE(mbedtls_csr_sign          , arginfo_mbedtls_csr_sign)
  PHP_FE(mbedtls_csr_export        , arginfo_mbedtls_csr_export)
  PHP_FE(mbedtls_csr_export_to_file, arginfo_mbedtls_csr_export_to_file)
  PHP_FE(mbedtls_csr_get_subject   , arginfo_mbedtls_csr_get_subject)
  PHP_FE(mbedtls_csr_get_public_key, arginfo_mbedtls_csr_get_public_key)
  PHP_FE_END
};

zend_module_entry mbedtls_module_entry = {
  STANDARD_MODULE_HEADER,
  "mbedtls",              /* Extension name */
  mbedtls_functions,      /* zend_function_entry */
  PHP_MINIT(mbedtls),     /* PHP_MINIT - Module initialization */
  NULL,                   /* PHP_MSHUTDOWN - Module shutdown */
  NULL,                   /* PHP_RINIT - Request initialization */
  NULL,                   /* PHP_RSHUTDOWN - Request shutdown */
  PHP_MINFO(mbedtls),     /* PHP_MINFO - Module info */
  PHP_MBEDTLS_VERSION,    /* Version */
  STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_MBEDTLS
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
#endif
ZEND_GET_MODULE(mbedtls)
#endif
