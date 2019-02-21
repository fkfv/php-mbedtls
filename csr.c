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
#include "Zend/zend_API.h"
#include "Zend/zend_smart_str.h"
#include "php_mbedtls.h"

#include <mbedtls/x509_csr.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/md.h>
#include <mbedtls/md_internal.h>

#define strp(x) x, strlen(x)

void php_mbedtls_csr_free(zend_resource *rsrc)
{
  struct php_mbedtls_csr *csr;

  csr = (struct php_mbedtls_csr *)rsrc->ptr;

  mbedtls_x509write_csr_free(&csr->csr_write);
  mbedtls_x509_csr_free(&csr->csr);

  efree(csr->output);
}

static void php_mbedtls_create_subject(zend_string **subject, zval *arr)
{
  smart_str out = {0};
  zend_string *index;
  zval *item;
  int first = 1;

  ZEND_HASH_FOREACH_STR_KEY_VAL(Z_ARRVAL_P(arr), index, item) {
    convert_to_string_ex(item);
    
    if (!first)
    {
      smart_str_appends(&out, ", ");
    }
    else
    {
      first = 0;
    }

    smart_str_appendl(&out, ZSTR_VAL(index), ZSTR_LEN(index));
    smart_str_appends(&out, "=");
    smart_str_appendl(&out, Z_STRVAL_P(item), Z_STRLEN_P(item));
  } ZEND_HASH_FOREACH_END();

  smart_str_0(&out);
  *subject = out.s;
}

PHP_FUNCTION(mbedtls_csr_new)
{
  zval *dn;
  zval *key;
  zval *configargs;
  zval *configarg;
  zend_string *subject;
  mbedtls_pk_context *ctx_key;
  struct php_mbedtls_csr *csr;
  mbedtls_ctr_drbg_context ctx_drbg;
  mbedtls_entropy_context ctx_entropy;
  const mbedtls_md_info_t* digest;

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "aza!", &dn, &key,
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
  }

  ctx_key = (mbedtls_pk_context *)zend_fetch_resource(Z_RES_P(key),
    MBEDTLS_PKEY_RESOURCE, le_pkey);
  csr = (struct php_mbedtls_csr *)ecalloc(1, sizeof(struct php_mbedtls_csr));
  csr->output = emalloc(4096);

  if (ctx_key == NULL)
  {
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "invalid key");

    return;
  }

  php_mbedtls_create_subject(&subject, dn);

  mbedtls_x509write_csr_init(&csr->csr_write);
  mbedtls_x509_csr_init(&csr->csr);
  mbedtls_ctr_drbg_init(&ctx_drbg);
  mbedtls_entropy_init(&ctx_entropy);

  mbedtls_ctr_drbg_seed(&ctx_drbg, mbedtls_entropy_func, &ctx_entropy,
    strp("mbedtls_csr_new"));

  mbedtls_x509write_csr_set_md_alg(&csr->csr_write, digest->type);
  mbedtls_x509write_csr_set_subject_name(&csr->csr_write, ZSTR_VAL(subject));
  mbedtls_x509write_csr_set_key(&csr->csr_write, ctx_key);

  mbedtls_x509write_csr_pem(&csr->csr_write, csr->output, 4096, mbedtls_ctr_drbg_random, &ctx_drbg);
  mbedtls_x509_csr_parse(&csr->csr, strp(csr->output));

  mbedtls_ctr_drbg_free(&ctx_drbg);
  mbedtls_entropy_free(&ctx_entropy);

  RETURN_RES(zend_register_resource(csr, le_csr));
}

#define MBEDTLS_CERT_VERSION_3 2

PHP_FUNCTION(mbedtls_csr_sign)
{
  zval *csr;
  zval *ca;
  zval *cakey;
  zval *configargs;
  zval *configarg;
  zend_long days;
  zend_long serial;
  char subject[4096];
  char output[4096];
  struct php_mbedtls_csr *ctx_csr;
  mbedtls_pk_context *ctx_capriv;
  mbedtls_x509write_cert crt;
  mbedtls_x509_crt *ctx_crt;
  mbedtls_x509_crt *ctx_ca;
  mbedtls_mpi bnserial;
  mbedtls_ctr_drbg_context ctx_drbg;
  mbedtls_entropy_context ctx_entropy;
  const mbedtls_md_info_t* digest;

  serial = 0;

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz!z!lal", &csr, &ca,
    &cakey, &days, &configargs, &serial) == FAILURE)
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
  }

  ctx_csr = (struct php_mbedtls_csr *)zend_fetch_resource(Z_RES_P(csr),
    MBEDTLS_CSR_RESOURCE, le_csr);
  ctx_ca = (mbedtls_x509_crt *)zend_fetch_resource(Z_RES_P(ca),
    MBEDTLS_CRT_RESOURCE, le_crt);

  if (ctx_ca != NULL)
  {
    ctx_capriv = (mbedtls_pk_context *)zend_fetch_resource(Z_RES_P(cakey),
      MBEDTLS_PKEY_RESOURCE, le_pkey);

    if (ctx_capriv == NULL)
    {
      php_error_docref(NULL TSRMLS_CC, E_WARNING, "ca private key not provided");

      return;
    }
  }

  ctx_crt = ecalloc(sizeof(mbedtls_x509_crt), 1);

  mbedtls_x509_crt_init(ctx_crt);
  mbedtls_x509write_crt_init(&crt);
  mbedtls_ctr_drbg_init(&ctx_drbg);
  mbedtls_entropy_init(&ctx_entropy);
  mbedtls_mpi_init(&bnserial);

  mbedtls_ctr_drbg_seed(&ctx_drbg, mbedtls_entropy_func, &ctx_entropy,
    strp("mbedtls_csr_sign"));
  mbedtls_mpi_lset(&bnserial, serial);

  mbedtls_x509_dn_gets(subject, 4096, &ctx_csr->csr.subject);
  mbedtls_x509write_crt_set_subject_name(&crt, subject);

  mbedtls_x509_dn_gets(subject, 4096, &ctx_ca->subject);
  mbedtls_x509write_crt_set_issuer_name(&crt, subject);

  mbedtls_x509write_crt_set_subject_key(&crt, &ctx_csr->csr.pk);
  mbedtls_x509write_crt_set_issuer_key(&crt, ctx_capriv);

  mbedtls_x509write_crt_set_version(&crt, MBEDTLS_CERT_VERSION_3);
  mbedtls_x509write_crt_set_md_alg(&crt, digest->type);
  mbedtls_x509write_crt_set_validity(&crt, "0", "20301231235959");
  mbedtls_x509write_crt_set_basic_constraints(&crt, ctx_ca == NULL, -1);
  mbedtls_x509write_crt_set_subject_key_identifier(&crt);
  mbedtls_x509write_crt_set_authority_key_identifier(&crt);

  mbedtls_x509write_crt_pem(&crt, output, 4096, mbedtls_ctr_drbg_random,
    &ctx_drbg);
  mbedtls_x509_crt_parse(ctx_crt, strp(output));

  mbedtls_x509write_crt_free(&crt);
  mbedtls_ctr_drbg_free(&ctx_drbg);
  mbedtls_entropy_free(&ctx_entropy);
  mbedtls_mpi_free(&bnserial);

  RETURN_RES(zend_register_resource(ctx_crt, le_crt));
}

PHP_FUNCTION(mbedtls_csr_export)
{
  zval *csr;
  zval *out;
  struct php_mbedtls_csr *ctx_csr;

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz", &csr, &out)
    == FAILURE)
  {
    return;
  }

  ctx_csr = (struct php_mbedtls_csr *)zend_fetch_resource(Z_RES_P(csr),
    MBEDTLS_CSR_RESOURCE, le_csr);

  if (ctx_csr == NULL)
  {
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "invalid csr");

    return;
  }

  zval_ptr_dtor(out);
  ZVAL_STRINGL(out, ctx_csr->output, strlen(ctx_csr->output));

  RETVAL_TRUE;
}

PHP_FUNCTION(mbedtls_csr_export_to_file)
{
  zval *csr;
  char *file;
  size_t file_len;
  struct php_mbedtls_csr *ctx_csr;
  FILE *f;

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zp", &csr, &file,
    &file_len) == FAILURE)
  {
    return;
  }

  ctx_csr = (struct php_mbedtls_csr *)zend_fetch_resource(Z_RES_P(csr),
    MBEDTLS_CSR_RESOURCE, le_csr);

  if (ctx_csr == NULL)
  {
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "invalid csr");

    return;
  }

  f = fopen(file, "wb");

  if (f == NULL)
  {
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "cannot output to file: %s",
      strerror(errno));

    RETURN_FALSE;
  }

  fwrite(ctx_csr->output, 1, strlen(ctx_csr->output), f);
  fclose(f);

  RETVAL_TRUE;
}
