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

#ifndef PHP_MBEDTLS_H
#define PHP_MBEDTLS_H

extern zend_module_entry mbedtls_module_entry;
#define phpext_mbedtls_ptr &mbedtls_module_entry

#define PHP_MBEDTLS_VERSION "0.1.0"

#if defined(ZTS) && defined(COMPILE_DL_MBEDTLS)
ZEND_TSRMLS_CACHE_EXTERN()
#endif

/* exported functions */

// cipher.c
#define MBEDTLS_ZERO_PADDING 0x01
#define MBEDTLS_RAW_DATA     0x02

PHP_FUNCTION(mbedtls_encrypt);
PHP_FUNCTION(mbedtls_decrypt);
PHP_FUNCTION(mbedtls_ciphers);

// pkey.c
#define MBEDTLS_KEYTYPE_RSA 0x01
#define MBEDTLS_KEYTYPE_EC  0x02

#define MBEDTLS_PKEY_RESOURCE "mbedtls pk context"

extern int le_pkey;
void php_mbedtls_pkey_free(zend_resource *);

PHP_FUNCTION(mbedtls_pkey_new);
PHP_FUNCTION(mbedtls_pkey_free);
PHP_FUNCTION(mbedtls_pkey_export);
PHP_FUNCTION(mbedtls_pkey_export_to_file);
PHP_FUNCTION(mbedtls_pkey_get_details);
PHP_FUNCTION(mbedtls_pkey_get_public);
PHP_FUNCTION(mbedtls_pkey_get_private);

#endif	/* PHP_MBEDTLS_H */
