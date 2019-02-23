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

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/pk.h>
#include <mbedtls/md.h>

PHP_FUNCTION(mbedtls_sign)
{
  zval *signature;
  zval *priv_key;
  char *data;
  char *hash;
  char sig[MBEDTLS_MPI_MAX_SIZE];
  size_t data_len;
  size_t hash_len;
  size_t sig_len;
  int free;
  zend_long algorithm;
  const mbedtls_md_info_t *digest;
  mbedtls_pk_context *ctx_key;
  mbedtls_entropy_context ctx_entropy;
  mbedtls_ctr_drbg_context ctx_drbg;

  algorithm = MBEDTLS_MD_SHA1;

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz/z|l", &data, &data_len,
    &signature, &priv_key, &algorithm) == FAILURE)
  {
    return;
  }

  RETVAL_FALSE;

  digest = mbedtls_md_info_from_type(algorithm);

  if (digest == NULL)
  {
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "invalid digest");

    return;
  }

  if (php_mbedtls_pkey_load(&ctx_key, priv_key, &free) == 0)
  {
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "invalid key");

    return;
  }

  mbedtls_entropy_init(&ctx_entropy);
  mbedtls_ctr_drbg_init(&ctx_drbg);

  mbedtls_ctr_drbg_seed(&ctx_drbg, mbedtls_entropy_func, &ctx_entropy,
    "mbedtls_sign", strlen("mbedtls_sign"));

  hash_len = mbedtls_md_get_size(digest);
  hash = emalloc(hash_len);

  mbedtls_md(digest, data, data_len, hash);
  mbedtls_pk_sign(ctx_key, algorithm, hash, 0, sig, &sig_len,
    mbedtls_ctr_drbg_random, &ctx_drbg);

  mbedtls_ctr_drbg_free(&ctx_drbg);
  mbedtls_entropy_free(&ctx_entropy);

  if (free)
  {
    mbedtls_pk_free(ctx_key);
    efree(ctx_key);
  }

  zval_ptr_dtor(signature);
  ZVAL_STRINGL(signature, sig, sig_len);

  RETVAL_TRUE;
}

PHP_FUNCTION(mbedtls_verify)
{
  zval *signature;
  zval *pub_key;
  char *data;
  char *hash;
  size_t data_len;
  size_t hash_len;
  int free;
  zend_long algorithm;
  zend_long verification;
  const mbedtls_md_info_t *digest;
  mbedtls_pk_context *ctx_key;
  mbedtls_entropy_context ctx_entropy;
  mbedtls_ctr_drbg_context ctx_drbg;

  algorithm = MBEDTLS_MD_SHA1;

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "szz|l", &data, &data_len,
    &signature, &pub_key, &algorithm) == FAILURE)
  {
    return;
  }

  RETVAL_LONG(-1);

  digest = mbedtls_md_info_from_type(algorithm);

  if (digest == NULL)
  {
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "invalid digest");

    return;
  }

  if (php_mbedtls_pkey_load(&ctx_key, pub_key, &free) == 0)
  {
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "invalid key");

    return;
  }

  mbedtls_entropy_init(&ctx_entropy);
  mbedtls_ctr_drbg_init(&ctx_drbg);

  mbedtls_ctr_drbg_seed(&ctx_drbg, mbedtls_entropy_func, &ctx_entropy,
    "mbedtls_sign", strlen("mbedtls_sign"));

  hash_len = mbedtls_md_get_size(digest);
  hash = emalloc(hash_len);

  mbedtls_md(digest, data, data_len, hash);
  verification = mbedtls_pk_verify(ctx_key, algorithm, hash, 0, data, data_len);

  mbedtls_ctr_drbg_free(&ctx_drbg);
  mbedtls_entropy_free(&ctx_entropy);

  if (free)
  {
    mbedtls_pk_free(ctx_key);
    efree(ctx_key);
  }

  RETVAL_LONG(verification == 0);
}

PHP_FUNCTION(mbedtls_hash)
{
  char *data;
  char *method;
  char *md_digest;
  char *hash;
  size_t data_len;
  size_t method_len;
  size_t md_digest_len;
  zend_bool raw_output;
  const mbedtls_md_info_t *digest;
  mbedtls_md_context_t ctx_md;

  raw_output = 0;

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|b", &data, &data_len,
    &method, &method_len, &raw_output) == FAILURE)
  {
    return;
  }

  RETVAL_LONG(-1);

  digest = mbedtls_md_info_from_string(method);

  if (digest == NULL)
  {
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "invalid method %s", method);

    return;
  }

  mbedtls_md_init(&ctx_md);
  mbedtls_md_setup(&ctx_md, digest, 0);

  md_digest_len = mbedtls_md_get_size(digest);
  md_digest = emalloc(md_digest_len);

  mbedtls_md_starts(&ctx_md);
  mbedtls_md_update(&ctx_md, data, data_len);
  mbedtls_md_finish(&ctx_md, md_digest);

  mbedtls_md_free(&ctx_md);

  if (raw_output)
  {
    RETURN_STRINGL(md_digest, md_digest_len);
  }

  hash = ecalloc(1, md_digest_len * 2 + 1);
  php_hash_bin2hex(hash, md_digest, md_digest_len);

  RETVAL_STRING(hash);

  efree(hash);
  efree(md_digest);
}
