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

#include <mbedtls/pk.h>
#include <mbedtls/md.h>
#include <mbedtls/md_internal.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#define strp(x) x, strlen(x)

void php_mbedtls_crl_free(zend_resource *rsrc)
{
  mbedtls_x509write_crl *crl;

  crl = (mbedtls_x509write_crl *)rsrc->ptr;

  mbedtls_x509write_crl_free(crl);
  efree(crl);
}

static void php_mbedtls_format_validity(char *begin, char *end, zend_long days)
{
  time_t now;
  struct tm valid_until = { 0 };
  struct tm *valid_from;

  time(&now);
  valid_from = gmtime(&now);

  memcpy(&valid_until, valid_from, sizeof(struct tm));

  valid_until.tm_mday += days;
  mktime(&valid_until);

  strftime(begin, 15, "%Y%m%d%H%M%S", valid_from);
  strftime(end, 15, "%Y%m%d%H%M%S", &valid_until);
}

static void php_mbedtls_format_date(char *date)
{
  time_t now;
  struct tm *date_now;

  time(&now);
  date_now = gmtime(&now);

  strftime(date, 15, "%Y%m%d%H%M%S", date_now);
}

PHP_FUNCTION(mbedtls_crl_new)
{
  zval *crt;
  zval *key;
  zval *configargs;
  zval *configarg;
  char subject[4096];
  char update_this[15];
  char update_next[15];
  int free_crt;
  int free_key;
  zend_long next_update;
  mbedtls_x509_crt *ctx_crt;
  mbedtls_pk_context *ctx_key;
  mbedtls_x509write_crl *ctx_crl;
  const mbedtls_md_info_t *digest;

  next_update = 365;

  digest = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  configargs = NULL;

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz|z", &crt, &key,
    &configargs) == FAILURE)
  {
    return;
  }

  if (configargs != NULL)
  {
    if (zend_hash_str_exists(Z_ARRVAL_P(configargs), strp("digest_alg")))
    {
      configarg = zend_hash_str_find(Z_ARRVAL_P(configargs), strp("digest_alg"));

      if (Z_TYPE_P(configarg) == IS_STRING)
      {
        digest = mbedtls_md_info_from_string(Z_STRVAL_P(configarg));

        if (digest == NULL)
        {
          php_error_docref(NULL TSRMLS_CC, E_WARNING, "digest algorithm %s not" \
            " found", Z_STRVAL_P(configarg));

          return;
        }
      }
    }

    if (zend_hash_str_exists(Z_ARRVAL_P(configargs), strp("next_update")))
    {
      configarg = zend_hash_str_find(Z_ARRVAL_P(configargs), strp("next_update"));

      if (Z_TYPE_P(configarg) == IS_LONG)
      {
        next_update = Z_LVAL_P(configarg);
      }
    }
  }

  if (php_mbedtls_crt_load(&ctx_crt, crt, &free_crt) == 0)
  {
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "invalid crt");

    return;
  }

  if (php_mbedtls_pkey_load(&ctx_key, key, &free_key) == 0)
  {
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "invalid key");

    if (free_crt)
    {
      mbedtls_x509_crt_free(ctx_crt);
      efree(ctx_crt);
    }

    return;
  }

  ctx_crl = (mbedtls_x509write_crl *)ecalloc(1, sizeof(mbedtls_x509write_crl));
  mbedtls_x509write_crl_init(ctx_crl);

  mbedtls_x509_dn_gets(subject, 4096, &ctx_crt->subject);
  php_mbedtls_format_validity(update_this, update_next, next_update);

  mbedtls_x509write_crl_set_version(ctx_crl, 1);
  mbedtls_x509write_crl_set_issuer_name(ctx_crl, subject);
  mbedtls_x509write_crl_set_issuer_key(ctx_crl, ctx_key);
  mbedtls_x509write_crl_set_md_alg(ctx_crl, digest->type);
  mbedtls_x509write_crl_set_authority_key_identifier(ctx_crl);
  mbedtls_x509write_crl_set_update(ctx_crl, update_this, update_next);

  RETURN_RES(zend_register_resource(ctx_crl, le_crl));
}

PHP_FUNCTION(mbedtls_crl_free)
{
  zval *key;

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &key) == FAILURE)
  {
    return;
  }

  if (zend_fetch_resource(Z_RES_P(key), MBEDTLS_CRL_RESOURCE, le_crl) == NULL)
  {
    return;
  }

  zend_list_close(Z_RES_P(key));
}

PHP_FUNCTION(mbedtls_crl_revoke)
{
  zval *crl;
  zval *crt;
  zend_long reason;
  int free;
  mbedtls_x509_crt *ctx_crt;
  mbedtls_x509write_crl *ctx_crl;
  mbedtls_x509write_crl_entry *ctx_entry;
  mbedtls_mpi serial;
  mbedtls_asn1_buf serialbuf;

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz|l", &crl, &crt,
    &reason) == FAILURE)
  {
    return;
  }

  ctx_crl = (mbedtls_x509write_crl *)zend_fetch_resource(Z_RES_P(crl),
      MBEDTLS_CRL_RESOURCE, le_crl);

  if (ctx_crl == NULL)
  {
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "invalid crl");

    return;
  }

  if (php_mbedtls_crt_load(&ctx_crt, crt, &free) == 0)
  {
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "invalid crt");

    return;
  }

  memcpy(&serialbuf, &ctx_crt->serial, sizeof(mbedtls_asn1_buf));

  mbedtls_mpi_init(&serial);
  mbedtls_mpi_read_binary(&serial, serialbuf.p, serialbuf.len);

  ctx_entry = mbedtls_x509write_crl_entry_add(ctx_crl);
  mbedtls_x509write_crl_entry_set_serial(ctx_entry, &serial);
  mbedtls_x509write_crl_entry_set_revocation_date(ctx_entry, "20190225200000");
  mbedtls_x509write_crl_entry_set_reason(ctx_entry, 1);

  if (free)
  {
    mbedtls_x509_crt_free(ctx_crt);
    efree(ctx_crt);
  }

  RETVAL_TRUE;
}

PHP_FUNCTION(mbedtls_crl_export)
{
  zval *crl;
  zval *out;
  char output[16000];
  mbedtls_x509write_crl *ctx_crl;
  mbedtls_ctr_drbg_context ctx_drbg;
  mbedtls_entropy_context ctx_entropy;

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz/", &crl, &out) == FAILURE)
  {
    return;
  }

  ctx_crl = (mbedtls_x509write_crl *)zend_fetch_resource(Z_RES_P(crl),
      MBEDTLS_CRL_RESOURCE, le_crl);

  if (ctx_crl == NULL)
  {
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "invalid crl");

    return;
  }

  mbedtls_ctr_drbg_init(&ctx_drbg);
  mbedtls_entropy_init(&ctx_entropy);

  mbedtls_ctr_drbg_seed(&ctx_drbg, mbedtls_entropy_func, &ctx_entropy,
    strp("mbedtls_crl_export"));

  mbedtls_x509write_crl_pem(ctx_crl, output, 16000, mbedtls_ctr_drbg_random,
    &ctx_drbg);

  zval_ptr_dtor(out);
  ZVAL_STRING(out, output);

  mbedtls_entropy_free(&ctx_entropy);
  mbedtls_ctr_drbg_free(&ctx_drbg);

  RETVAL_TRUE;
}

PHP_FUNCTION(mbedtls_crl_export_to_file)
{
  zval *crl;
  char *file;
  char output[16000];
  size_t file_len;
  mbedtls_x509write_crl *ctx_crl;
  mbedtls_ctr_drbg_context ctx_drbg;
  mbedtls_entropy_context ctx_entropy;
  FILE *f;

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rp", &crl, &file,
    &file_len) == FAILURE)
  {
    return;
  }

  ctx_crl = (mbedtls_x509write_crl *)zend_fetch_resource(Z_RES_P(crl),
      MBEDTLS_CRL_RESOURCE, le_crl);

  if (ctx_crl == NULL)
  {
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "invalid crl");

    return;
  }

  mbedtls_ctr_drbg_init(&ctx_drbg);
  mbedtls_entropy_init(&ctx_entropy);

  mbedtls_ctr_drbg_seed(&ctx_drbg, mbedtls_entropy_func, &ctx_entropy,
    strp("mbedtls_crl_export"));

  mbedtls_x509write_crl_pem(ctx_crl, output, 16000, mbedtls_ctr_drbg_random,
    &ctx_drbg);

  f = fopen(file, "wb");

  if (f == NULL)
  {
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "cannot output to file: %s",
      strerror(errno));

    RETURN_FALSE;
  }

  fwrite(output, 1, strlen(output), f);
  fclose(f);

  mbedtls_entropy_free(&ctx_entropy);
  mbedtls_ctr_drbg_free(&ctx_drbg);

  RETVAL_TRUE;
}
