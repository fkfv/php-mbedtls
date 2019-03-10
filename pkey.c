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

#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/oid.h>

#define strp(x) x, strlen(x)

struct php_pkey_options {
  int type;
  int size;
  int curve_id;
};

void php_mbedtls_pkey_free(zend_resource *rsrc)
{
  mbedtls_pk_free(rsrc->ptr);
  efree(rsrc->ptr);
}

PHP_FUNCTION(mbedtls_pkey_new)
{
  zval *configargs = NULL;
  zval *configarg = NULL;
  mbedtls_mpi N;
  mbedtls_mpi P;
  mbedtls_mpi Q;
  mbedtls_mpi D;
  mbedtls_mpi E;
  mbedtls_mpi DP;
  mbedtls_mpi DQ;
  mbedtls_mpi QP;
  mbedtls_pk_context *ctx_key;
  mbedtls_ctr_drbg_context ctx_drbg;
  mbedtls_entropy_context ctx_entropy;
  const mbedtls_ecp_curve_info *curve_info;
  struct php_pkey_options options;

  configargs = NULL;

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|a!", &configargs)
    == FAILURE)
  {
    return;
  }

  options.type = MBEDTLS_PK_RSA;
  options.size = 4096;
  options.curve_id = mbedtls_ecp_curve_list()->grp_id;

  if (configargs != NULL)
  {
    if (zend_hash_str_exists(Z_ARRVAL_P(configargs), strp("private_key_type")))
    {
      configarg = zend_hash_str_find(Z_ARRVAL_P(configargs),
        strp("private_key_type"));

      if (Z_TYPE_P(configarg) == IS_LONG)
      {
        options.type = Z_LVAL_P(configarg);
      }
    }

    if (zend_hash_str_exists(Z_ARRVAL_P(configargs), strp("private_key_bits")))
    {
      configarg = zend_hash_str_find(Z_ARRVAL_P(configargs),
        strp("private_key_bits"));

      if (Z_TYPE_P(configarg) == IS_LONG)
      {
        options.size = Z_LVAL_P(configarg);
      }
    }

    if (zend_hash_str_exists(Z_ARRVAL_P(configargs), strp("curve_name")))
    {
      configarg = zend_hash_str_find(Z_ARRVAL_P(configargs), strp("curve_name"));

      if (Z_TYPE_P(configarg) == IS_STRING)
      {
        curve_info = mbedtls_ecp_curve_info_from_name(Z_STRVAL_P(configarg));

        if (curve_info == NULL)
        {
          php_error_docref(NULL TSRMLS_CC, E_WARNING, "invalid curve name %s",
            Z_STRVAL_P(configarg));

          return; 
        }

        options.curve_id = curve_info->grp_id;
      }
    }
  }

  ctx_key = ecalloc(1, sizeof(mbedtls_pk_context));

  mbedtls_mpi_init(&N);
  mbedtls_mpi_init(&P);
  mbedtls_mpi_init(&Q);
  mbedtls_mpi_init(&D);
  mbedtls_mpi_init(&E);
  mbedtls_mpi_init(&DP);
  mbedtls_mpi_init(&DQ);
  mbedtls_mpi_init(&QP);

  mbedtls_pk_init(ctx_key);
  mbedtls_ctr_drbg_init(&ctx_drbg);
  mbedtls_entropy_init(&ctx_entropy);

  mbedtls_ctr_drbg_seed(&ctx_drbg, mbedtls_entropy_func, &ctx_entropy,
    strp("mbedtls_pkey_new"));

  if (mbedtls_pk_setup(ctx_key, mbedtls_pk_info_from_type(options.type)) != 0)
  {
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&D);
    mbedtls_mpi_free(&E);
    mbedtls_mpi_free(&DP);
    mbedtls_mpi_free(&DQ);
    mbedtls_mpi_free(&QP);

    mbedtls_pk_free(ctx_key);
    mbedtls_ctr_drbg_free(&ctx_drbg);
    mbedtls_entropy_free(&ctx_entropy);

    php_error_docref(NULL TSRMLS_CC, E_WARNING, "cannot generate key");

    return;
  }

  if (options.type == MBEDTLS_PK_RSA)
  {
    mbedtls_rsa_gen_key(mbedtls_pk_rsa(*ctx_key), mbedtls_ctr_drbg_random,
      &ctx_drbg, options.size, 65537);
  }
  else if (options.type == MBEDTLS_PK_ECKEY)
  {
    mbedtls_ecp_gen_key(options.curve_id, mbedtls_pk_ec(*ctx_key),
      mbedtls_ctr_drbg_random, &ctx_drbg);
  }
  else
  {
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "invalid key type");

    mbedtls_pk_free(ctx_key);
  }

  mbedtls_mpi_free(&N);
  mbedtls_mpi_free(&P);
  mbedtls_mpi_free(&Q);
  mbedtls_mpi_free(&D);
  mbedtls_mpi_free(&E);
  mbedtls_mpi_free(&DP);
  mbedtls_mpi_free(&DQ);
  mbedtls_mpi_free(&QP);

  mbedtls_ctr_drbg_free(&ctx_drbg);
  mbedtls_entropy_free(&ctx_entropy);

  if (options.type != MBEDTLS_PK_RSA && options.type != MBEDTLS_PK_ECKEY)
  {
    return;
  }

  RETURN_RES(zend_register_resource(ctx_key, le_pkey));
}

PHP_FUNCTION(mbedtls_pkey_free)
{
  zval *key;

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &key) == FAILURE)
  {
    return;
  }

  if (zend_fetch_resource(Z_RES_P(key), MBEDTLS_PKEY_RESOURCE, le_pkey) == NULL)
  {
    return;
  }

  zend_list_close(Z_RES_P(key));
}

PHP_FUNCTION(mbedtls_pkey_export)
{
  zval *key;
  zval *out;
  char output_buf[16000];
  int free;
  mbedtls_pk_context *ctx_key;

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz/", &key, &out)
    == FAILURE)
  {
    return;
  }

  if (php_mbedtls_pkey_load(&ctx_key, key, &free) == 0)
  {
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "invalid key");

    return;
  }

  if (mbedtls_pk_get_type(ctx_key) == MBEDTLS_PK_RSA)
  {
    if (mbedtls_rsa_check_privkey(mbedtls_pk_rsa(*ctx_key)) != 0)
    {
      php_error_docref(NULL TSRMLS_CC, E_WARNING, "not a private key");

      if (free)
      {
        mbedtls_pk_free(ctx_key);
        efree(ctx_key);
      }

      return;
    }
  }
  else if (mbedtls_pk_get_type(ctx_key) == MBEDTLS_PK_ECKEY)
  {
    if (mbedtls_ecp_check_privkey(&mbedtls_pk_ec(*ctx_key)->grp,
      &mbedtls_pk_ec(*ctx_key)->d) != 0)
    {
      php_error_docref(NULL TSRMLS_CC, E_WARNING, "not a private key");

      if (free)
      {
        mbedtls_pk_free(ctx_key);
        efree(ctx_key);
      }

      return;
    }
  }

  if (out != NULL && mbedtls_pk_write_key_pem(ctx_key, output_buf, 16000) == 0)
  {
    zval_ptr_dtor(out);
    ZVAL_STRINGL(out, output_buf, strlen(output_buf));

    if (free)
    {
      mbedtls_pk_free(ctx_key);
      efree(ctx_key);
    }

    RETURN_TRUE;
  }

  if (free)
  {
    mbedtls_pk_free(ctx_key);
    efree(ctx_key);
  }

  RETVAL_FALSE;
}

PHP_FUNCTION(mbedtls_pkey_export_to_file)
{
  zval *key;
  char *file;
  char output_buf[16000];
  size_t file_len;
  int free;
  mbedtls_pk_context *ctx_key;
  FILE *f;

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zp", &key, &file,
    &file_len) == FAILURE)
  {
    return;
  }

  if (php_mbedtls_pkey_load(&ctx_key, key, &free) == 0)
  {
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "invalid key");

    return;
  }

  if (mbedtls_pk_get_type(ctx_key) == MBEDTLS_PK_RSA)
  {
    if (mbedtls_rsa_check_privkey(mbedtls_pk_rsa(*ctx_key)) != 0)
    {
      php_error_docref(NULL TSRMLS_CC, E_WARNING, "not a private key");

      if (free)
      {
        mbedtls_pk_free(ctx_key);
        efree(ctx_key);
      }

      return;
    }
  }
  else if (mbedtls_pk_get_type(ctx_key) == MBEDTLS_PK_ECKEY)
  {
    if (mbedtls_ecp_check_privkey(&mbedtls_pk_ec(*ctx_key)->grp,
      &mbedtls_pk_ec(*ctx_key)->d) != 0)
    {
      php_error_docref(NULL TSRMLS_CC, E_WARNING, "not a private key");

      if (free)
      {
        mbedtls_pk_free(ctx_key);
        efree(ctx_key);
      }

      return;
    }
  }

  if (mbedtls_pk_write_key_pem(ctx_key, output_buf, 16000) == 0)
  {
    f = fopen(file, "wb");

    if (f == NULL)
    {
      php_error_docref(NULL TSRMLS_CC, E_WARNING, "cannot output to file: %s",
        strerror(errno));

      if (free)
      {
        mbedtls_pk_free(ctx_key);
        efree(ctx_key);
      }

      RETURN_FALSE;
    }

    fwrite(output_buf, 1, strlen(output_buf), f);
    fclose(f);

    if (free)
    {
      mbedtls_pk_free(ctx_key);
      efree(ctx_key);
    }

    RETURN_TRUE;
  }

  if (free)
  {
    mbedtls_pk_free(ctx_key);
    efree(ctx_key);
  }

  RETVAL_FALSE;
}

void php_mbedtls_add_key_detail(zval *arr, const char *name, mbedtls_mpi *num)
{
  char *bignum_out;
  size_t bignum_len;
  zval vl;

  bignum_len = mbedtls_mpi_size(num);
  bignum_out = emalloc(bignum_len);
  mbedtls_mpi_write_binary(num, bignum_out, bignum_len);
  ZVAL_STRINGL(&vl, bignum_out, bignum_len);
  zend_hash_str_add(Z_ARRVAL_P(arr), strp(name), &vl);
}

void php_mbedtls_translate_grpid(mbedtls_ecp_group_id group_id, char *numeric, size_t numeric_len)
{
  char *oid;
  size_t oid_len;
  mbedtls_asn1_buf oid_buffer;

  oid = NULL;
  oid_len = 0;

  mbedtls_oid_get_oid_by_ec_grp(group_id, &oid, &oid_len);

  oid_buffer.tag = 0;
  oid_buffer.len = oid_len;
  oid_buffer.p = oid;

  mbedtls_oid_get_numeric_string(numeric, numeric_len, &oid_buffer);
}

PHP_FUNCTION(mbedtls_pkey_get_details)
{
  zval *key;
  zval vl;
  zval info;
  char output_buf[16000];
  char numeric[20];
  int free;
  mbedtls_pk_context *ctx_key;
  mbedtls_rsa_context *ctx_rsa;
  mbedtls_ecp_keypair *ctx_eckey;
  const mbedtls_ecp_curve_info *curve_info;
  mbedtls_pk_type_t type;
  mbedtls_mpi N;
  mbedtls_mpi P;
  mbedtls_mpi Q;
  mbedtls_mpi D;
  mbedtls_mpi E;
  mbedtls_mpi DP;
  mbedtls_mpi DQ;
  mbedtls_mpi QP;

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &key) == FAILURE)
  {
    return;
  }

  if (php_mbedtls_pkey_load(&ctx_key, key, &free) == 0)
  {
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "invalid key");

    return;
  }

  type = mbedtls_pk_get_type(ctx_key);
  array_init(return_value);
  array_init(&info);

  mbedtls_mpi_init(&N);
  mbedtls_mpi_init(&P);
  mbedtls_mpi_init(&Q);
  mbedtls_mpi_init(&D);
  mbedtls_mpi_init(&E);
  mbedtls_mpi_init(&DP);
  mbedtls_mpi_init(&DQ);
  mbedtls_mpi_init(&QP);

  ZVAL_LONG(&vl, mbedtls_pk_get_bitlen(ctx_key));
  zend_hash_str_add(Z_ARRVAL_P(return_value), strp("bits"), &vl);

  mbedtls_pk_write_pubkey_pem(ctx_key, output_buf, 16000);
  ZVAL_STRINGL(&vl, output_buf, strlen(output_buf));
  zend_hash_str_add(Z_ARRVAL_P(return_value), strp("key"), &vl);

  ZVAL_LONG(&vl, type);
  zend_hash_str_add(Z_ARRVAL_P(return_value), strp("type"), &vl);

  if (type == MBEDTLS_PK_RSA)
  {
    ctx_rsa = mbedtls_pk_rsa(*ctx_key);

    mbedtls_rsa_export(ctx_rsa, &N, NULL, NULL, NULL, &E);
    mbedtls_rsa_export_crt(ctx_rsa, &DP, &DQ, &QP);

    php_mbedtls_add_key_detail(&info, "n", &N);
    php_mbedtls_add_key_detail(&info, "e", &E);

    if (mbedtls_rsa_check_privkey(ctx_rsa) == 0)
    {
      mbedtls_rsa_export(ctx_rsa, NULL, &P, &Q, &D, NULL);
      mbedtls_rsa_export_crt(ctx_rsa, &DP, &DQ, &QP);

      php_mbedtls_add_key_detail(&info, "p", &P);
      php_mbedtls_add_key_detail(&info, "q", &Q);
      php_mbedtls_add_key_detail(&info, "d", &D);
      php_mbedtls_add_key_detail(&info, "dmp1", &DP);
      php_mbedtls_add_key_detail(&info, "dmq1", &DQ);
      php_mbedtls_add_key_detail(&info, "iqmp", &QP);
    }

    zend_hash_str_add(Z_ARRVAL_P(return_value), strp("rsa"), &info);
  }
  else if (type == MBEDTLS_PK_ECKEY)
  {
    ctx_eckey = mbedtls_pk_ec(*ctx_key);
    curve_info = mbedtls_ecp_curve_info_from_grp_id(ctx_eckey->grp.id);

    ZVAL_STRING(&vl, curve_info->name);
    zend_hash_str_add(Z_ARRVAL_P(return_value), strp("curve_name"), &vl);

    php_mbedtls_translate_grpid(ctx_eckey->grp.id, numeric, 20);
    ZVAL_STRING(&vl, numeric);
    zend_hash_str_add(Z_ARRVAL_P(return_value), strp("curve_oid"), &vl);

    php_mbedtls_add_key_detail(&info, "x", &ctx_eckey->Q.X);
    php_mbedtls_add_key_detail(&info, "y", &ctx_eckey->Q.Y);

    if (mbedtls_ecp_check_privkey(&ctx_eckey->grp, &ctx_eckey->d) == 0)
    {
      php_mbedtls_add_key_detail(&info, "d", &ctx_eckey->d);
    }

    zend_hash_str_add(Z_ARRVAL_P(return_value), strp("ec"), &info);
  }

  if (free)
  {
    mbedtls_pk_free(ctx_key);
    efree(ctx_key);
  }
}

PHP_FUNCTION(mbedtls_pkey_get_public)
{
  zval *key;
  char *filename;
  mbedtls_pk_context *ctx_key;
  mbedtls_x509_crt *ctx_crt;

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &key) == FAILURE)
  {
    return;
  }

  ctx_key = ecalloc(1, sizeof(mbedtls_pk_context));

  mbedtls_pk_init(ctx_key);

  if (Z_TYPE_P(key) == IS_RESOURCE)
  {
    ctx_crt = (mbedtls_x509_crt *)zend_fetch_resource(Z_RES_P(key),
      MBEDTLS_CRT_RESOURCE, le_crt);

    if (ctx_crt == NULL)
    {
      php_error_docref(NULL TSRMLS_CC, E_WARNING, "failed to parse key");
      efree(ctx_key);

      return;
    }

    memcpy(ctx_key, &ctx_crt->pk, sizeof(mbedtls_pk_context));
  }
  else if (Z_TYPE_P(key) == IS_STRING)
  {
    if (strncasecmp("file://", Z_STRVAL_P(key), 7) == 0)
    {
      filename = emalloc(Z_STRLEN_P(key) - 6);
      strncpy(filename, Z_STRVAL_P(key) + 7, Z_STRLEN_P(key) - 7);

      if (mbedtls_pk_parse_public_keyfile(ctx_key, filename) != 0)
      {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "failed to parse key");
        efree(ctx_key);
        efree(filename);

        return;
      }

      efree(filename);
    }
    else
    {
      if (mbedtls_pk_parse_public_key(ctx_key, Z_STRVAL_P(key),
        Z_STRLEN_P(key) + 1) != 0)
      {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "failed to parse key");
        efree(ctx_key);

        return;
      }
    }
  }
  else
  {
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "failed to parse key");
    efree(ctx_key);

    return;
  }

  RETURN_RES(zend_register_resource(ctx_key, le_pkey));
}

PHP_FUNCTION(mbedtls_pkey_get_private)
{
  char *key;
  char *password;
  char *filename;
  size_t key_len;
  size_t password_len;
  mbedtls_pk_context *ctx_key;

  password = NULL;
  password_len = 0;

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|s", &key, &key_len,
    &password, &password_len) == FAILURE)
  {
    return;
  }

  ctx_key = ecalloc(1, sizeof(mbedtls_pk_context));

  mbedtls_pk_init(ctx_key);

  if (password_len == 0 || (password_len == 1 && password[0] == '\0'))
  {
    password = NULL;
    password_len = 0;
  }

  if (strncasecmp("file://", key, 7) == 0)
  {
    filename = emalloc(strlen(key) - 6);
    strncpy(filename, key + 7, strlen(key) - 7);

    if (mbedtls_pk_parse_keyfile(ctx_key, filename, password) != 0)
    {
      php_error_docref(NULL TSRMLS_CC, E_WARNING, "failed to parse key");

      return;
    }
  }
  else
  {
    if (mbedtls_pk_parse_key(ctx_key, key, key_len + 1, password, password_len)
      != 0)
    {
      php_error_docref(NULL TSRMLS_CC, E_WARNING, "failed to parse key");

      return;
    }
  }

  RETURN_RES(zend_register_resource(ctx_key, le_pkey));
}