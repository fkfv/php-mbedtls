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
#include "php_mbedtls.h"

int php_mbedtls_csr_load(mbedtls_x509_csr **csr, zval *val, int *needs_free)
{
  const char *pem;
  char *filename;

  filename = NULL;
  *needs_free = 0;

  if (Z_TYPE_P(val) == IS_STRING)
  {
    *csr = (mbedtls_x509_csr *)ecalloc(1, sizeof(mbedtls_x509_csr));
    pem = Z_STRVAL_P(val);

    mbedtls_x509_csr_init(*csr);

    if (strncasecmp("file://", pem, 7) == 0)
    {
      filename = emalloc(strlen(pem) - 6);
      strncpy(filename, pem + 7, strlen(pem) - 7);

      mbedtls_x509_csr_parse_file(*csr, filename);

      efree(filename);
    }
    else
    {
      mbedtls_x509_csr_parse(*csr, pem, strlen(pem));
    }

    *needs_free = 1;
  }
  else if (Z_TYPE_P(val) == IS_RESOURCE)
  {
    *csr = (mbedtls_x509_csr *)zend_fetch_resource(Z_RES_P(val),
      MBEDTLS_CSR_RESOURCE, le_csr);

    if (*csr == NULL)
    {
      php_error_docref(NULL TSRMLS_CC, E_WARNING, "resource is not csr");

      return 0;
    }
  }
  else
  {
    return 0;
  }

  return 1;
}

int php_mbedtls_crt_load(mbedtls_x509_crt **crt, zval *val, int *needs_free)
{
  const char *pem;
  char *filename;

  filename = NULL;
  *needs_free = 0;

  if (Z_TYPE_P(val) == IS_STRING)
  {
    *crt = (mbedtls_x509_crt *)ecalloc(1, sizeof(struct mbedtls_x509_crt));
    pem = Z_STRVAL_P(val);
  
    mbedtls_x509_crt_init(*crt);

    if (strncasecmp("file://", pem, 7) == 0)
    {
      filename = emalloc(strlen(pem) - 6);
      strncpy(filename, pem + 7, strlen(pem) - 7);

      mbedtls_x509_crt_parse_file(*crt, filename);

      efree(filename);
    }
    else
    {
      mbedtls_x509_crt_parse(*crt, pem, strlen(pem) + 1);
    }

    *needs_free = 1;
  }
  else if (Z_TYPE_P(val) == IS_RESOURCE)
  {
    *crt = (mbedtls_x509_crt *)zend_fetch_resource(Z_RES_P(val),
      MBEDTLS_CRT_RESOURCE, le_crt);

    if (*crt == NULL)
    {
      php_error_docref(NULL TSRMLS_CC, E_WARNING, "resource is not cert");

      return 0;
    }
  }
  else
  {
    return 0;
  }

  return 1;
}

int php_mbedtls_pkey_load_internal(mbedtls_pk_context **pkey, const char *pem,
  const char *password)
{
  char *filename;

  *pkey = (mbedtls_pk_context *)ecalloc(1, sizeof(struct mbedtls_x509_crt));
  mbedtls_pk_init(*pkey);

  if (strncasecmp("file://", pem, 7) == 0)
  {
    filename = emalloc(strlen(pem) - 6);
    strncpy(filename, pem + 7, strlen(pem) - 7);

    mbedtls_pk_parse_keyfile(*pkey, filename, password);

    efree(filename);
  }
  else
  {
    mbedtls_pk_parse_key(*pkey, pem, strlen(pem), password,
    password == NULL ? 0 : strlen(password));
  }

  return 1;
}

int php_mbedtls_pkey_load(mbedtls_pk_context **pkey, zval *val, int *needs_free)
{
  zval *passphrase;
  zval *pem;

  *needs_free = 0;

  if (Z_TYPE_P(val) == IS_STRING)
  {
    *needs_free = 1;

    return php_mbedtls_pkey_load_internal(pkey, Z_STRVAL_P(val), NULL);
  }
  else if (Z_TYPE_P(val) == IS_RESOURCE)
  {
    *pkey = (mbedtls_pk_context *)zend_fetch_resource(Z_RES_P(val),
      MBEDTLS_PKEY_RESOURCE, le_pkey);

    if (*pkey == NULL)
    {
      php_error_docref(NULL TSRMLS_CC, E_WARNING, "resource is not pkey");

      return 0;
    }
  }
  else if (Z_TYPE_P(val) == IS_ARRAY)
  {
    *needs_free = 1;

    pem = zend_hash_index_find(Z_ARRVAL_P(val), 0);
    passphrase = zend_hash_index_find(Z_ARRVAL_P(val), 1);

    if (pem == NULL || passphrase == NULL)
    {
      php_error_docref(NULL TSRMLS_CC, E_WARNING, "expected array in form " \
        "['key', 'passphrase']");

      return 0;
    }

    return php_mbedtls_pkey_load_internal(pkey, Z_STRVAL_P(pem), Z_STRVAL_P(passphrase));
  }
  else
  {
    return 0;
  }

  return 1;
}