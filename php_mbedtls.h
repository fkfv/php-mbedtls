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

// aes.c
#define MBEDTLS_AES_HEX 0x01
#define MBEDTLS_AES_RAW 0x02

#define MBEDTLS_AES_CBC 0x01
#define MBEDTLS_AES_ECB 0x02
#define MBEDTLS_AES_OFB 0x03
#define MBEDTLS_AES_CTR 0x04

#define MBEDTLS_ZERO_PADDING 0x01
#define MBEDTLS_RAW_DATA     0x02

PHP_FUNCTION(mbedtls_encrypt);
PHP_FUNCTION(mbedtls_decrypt);

#endif	/* PHP_MBEDTLS_H */
