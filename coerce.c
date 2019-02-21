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

int php_mbedtls_csr_load(struct php_mbedtls_csr **csr, zval *val, int *needs_free)
{
  const char *pem;
  char *filename;
  char *buffer;
  long size;
  FILE *f;

  buffer = NULL;
  filename = NULL;
  *needs_free = 0;

  if (Z_TYPE_P(val) == IS_STRING)
  {
    *csr = (struct php_mbedtls_csr *)ecalloc(1, sizeof(struct php_mbedtls_csr));
    pem = Z_STRVAL_P(val);

    if (strncasecmp("file://", pem, 7) == 0)
    {
      filename = emalloc(strlen(pem) - 6);
      strncpy(filename, pem + 7, strlen(pem) - 7);

      f = fopen(filename, "rb");

      if (f == NULL)
      {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "cannot open %s", filename);

        return 0;
      }

      fseek(f, 0, SEEK_END);
      size = ftell(f);
      fseek(f, 0, SEEK_SET);

      buffer = emalloc(size + 1);
      fread(buffer, 1, size, f);
      buffer[size] = '\0';

      pem = buffer;
    }

    mbedtls_x509write_csr_init(&(*csr)->csr_write);
    mbedtls_x509_csr_init(&(*csr)->csr);

    mbedtls_x509_csr_parse(&(*csr)->csr, buffer, strlen(buffer));

    *needs_free = 1;

    efree(buffer);
    efree(filename);
  }
  else if (Z_TYPE_P(val) == IS_RESOURCE)
  {
    *csr = (struct php_mbedtls_csr *)zend_fetch_resource(Z_RES_P(val),
      MBEDTLS_CSR_RESOURCE, le_csr);

    if (*csr == NULL)
    {
      return 0;
    }
  }
  else
  {
    return 0;
  }

  return 1;
}