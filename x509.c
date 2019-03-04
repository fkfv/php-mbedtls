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
#include "ext/hash/php_hash.h"
#include "php_mbedtls.h"

#include <mbedtls/x509_crt.h>
#include <mbedtls/pem.h>
#include <mbedtls/md.h>

void php_mbedtls_crt_free(zend_resource *rsrc)
{
  mbedtls_x509_crt_free(rsrc->ptr);
  efree(rsrc->ptr);
}

PHP_FUNCTION(mbedtls_x509_free)
{
  zval *x509;

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &x509) == FAILURE)
  {
    return;
  }

  if (zend_fetch_resource(Z_RES_P(x509), MBEDTLS_CRT_RESOURCE, le_pkey) == NULL)
  {
    return;
  }

  zend_list_close(Z_RES_P(x509));
}

#define CRT_HEADER "-----BEGIN CERTIFICATE-----\n"
#define CRT_FOOTER "-----END CERTIFICATE-----\n"

PHP_FUNCTION(mbedtls_x509_export)
{
  zval *crt;
  zval *out;
  char pem[16000];
  int free;
  size_t pem_length;
  mbedtls_x509_crt *ctx_crt;

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz/", &crt, &out)
    == FAILURE)
  {
    return;
  }

  if (php_mbedtls_crt_load(&ctx_crt, crt, &free) == 0)
  {
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "invalid crt");

    return;
  }

  zval_ptr_dtor(out);
  mbedtls_pem_write_buffer(CRT_HEADER, CRT_FOOTER, ctx_crt->raw.p,
    ctx_crt->raw.len, pem, 16000, &pem_length);
  ZVAL_STRING(out, pem);

  RETVAL_TRUE;
}

PHP_FUNCTION(mbedtls_x509_export_to_file)
{
  zval *crt;
  char *file;
  char pem[16000];
  int free;
  size_t file_len;
  size_t pem_length;
  mbedtls_x509_crt *ctx_crt;
  FILE *f;

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zp", &crt, &file,
    &file_len) == FAILURE)
  {
    return;
  }

  if (php_mbedtls_crt_load(&ctx_crt, crt, &free) == 0)
  {
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "invalid crt");

    return;
  }

  mbedtls_pem_write_buffer(CRT_HEADER, CRT_FOOTER, ctx_crt->raw.p,
    ctx_crt->raw.len, pem, 16000, &pem_length);

  f = fopen(file, "wb");

  if (f == NULL)
  {
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "cannot output to file: %s",
      strerror(errno));

    RETURN_FALSE;
  }

  fwrite(pem, 1, strlen(pem), f);
  fclose(f);

  RETVAL_TRUE;
}

PHP_FUNCTION(mbedtls_x509_fingerprint)
{
  zval *crt;
  char *hash_algorithm;
  char *raw_fingerprint;
  char *fingerprint;
  size_t hash_algorithm_len;
  size_t raw_length;
  int free;
  zend_bool raw_output;
  mbedtls_x509_crt *ctx_crt;
  mbedtls_md_context_t ctx_md;
  const mbedtls_md_info_t* digest;

  hash_algorithm = "SHA1";
  raw_output = 0;

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|sb", &crt,
    &hash_algorithm, &hash_algorithm_len, &raw_output) == FAILURE)
  {
    return;
  }

  digest = mbedtls_md_info_from_string(hash_algorithm);

  if (digest == NULL)
  {
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "digest algorithm %s not" \
      " found", hash_algorithm);

    return;
  }

  if (php_mbedtls_crt_load(&ctx_crt, crt, &free) == 0)
  {
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "invalid crt");

    return;
  }

  mbedtls_md_init(&ctx_md);
  mbedtls_md_setup(&ctx_md, digest, 0);

  mbedtls_md_starts(&ctx_md);
  mbedtls_md_update(&ctx_md, ctx_crt->raw.p, ctx_crt->raw.len);

  raw_length = mbedtls_md_get_size(digest);
  raw_fingerprint = ecalloc(1, raw_length);

  mbedtls_md_finish(&ctx_md, raw_fingerprint);
  mbedtls_md_free(&ctx_md);

  if (free)
  {
    mbedtls_x509_crt_free(ctx_crt);
    efree(ctx_crt);
  }

  if (raw_output == 1)
  {
    RETURN_STRINGL(raw_fingerprint, raw_length);
  }

  fingerprint = ecalloc(1, raw_length * 2 + 1);
  php_hash_bin2hex(fingerprint, raw_fingerprint, raw_length);

  RETVAL_STRING(fingerprint);

  efree(fingerprint);
  efree(raw_fingerprint);
}

PHP_FUNCTION(mbedtls_x509_read)
{
  zval *crt;
  int free;
  mbedtls_x509_crt *ctx_crt;

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &crt) == FAILURE)
  {
    return;
  }

  if (php_mbedtls_crt_load(&ctx_crt, crt, &free) == 0)
  {
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "invalid crt");

    return;
  }

  RETURN_RES(zend_register_resource(ctx_crt, le_crt));
}
