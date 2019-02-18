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
#include "ext/standard/base64.h"
#include "Zend/zend_API.h"
#include "Zend/zend_smart_str.h"
#include "php_mbedtls.h"

#include <mbedtls/cipher.h>

PHP_FUNCTION(mbedtls_encrypt)
{
  zend_long options = 0;
  zend_long tag_length = 16;
  char *data;
  char *method;
  char *key;
  char *iv = "";
  char *aad = "";
  char output[1024];
  char tag[16];
  size_t data_len;
  size_t method_len;
  size_t key_len;
  size_t iv_len;
  size_t aad_len = 0;
  size_t offset;
  size_t count;
  size_t block_length;
  size_t output_len;
  zval *ztag = NULL;
  mbedtls_cipher_context_t ctx;
  const mbedtls_cipher_info_t *cipher_info;
  smart_str return_val = {0};

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss|lsz/sl", &data,
    &data_len, &method, &method_len, &key, &key_len, &options, &iv, &iv_len,
    &ztag, &aad, &aad_len, &tag_length) == FAILURE)
  {
    return;
  }

  mbedtls_cipher_init(&ctx);
  cipher_info = mbedtls_cipher_info_from_string(method);

  if (cipher_info == NULL)
  {
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "cipher %s not found", method);

    return;
  }

  mbedtls_cipher_setup(&ctx, cipher_info);
  mbedtls_cipher_setkey(&ctx, key, cipher_info->key_bitlen, MBEDTLS_ENCRYPT);

  if ((options & MBEDTLS_ZERO_PADDING) == MBEDTLS_ZERO_PADDING)
  {
    mbedtls_cipher_set_padding_mode(&ctx, MBEDTLS_PADDING_NONE);
  }

  if (iv_len > 0)
  {
    mbedtls_cipher_set_iv(&ctx, iv, iv_len);
  }

  mbedtls_cipher_reset(&ctx);

  if (aad_len > 0)
  {
    mbedtls_cipher_update_ad(&ctx, aad, aad_len);
  }

  block_length = mbedtls_cipher_get_block_size(&ctx);

  for (offset = 0; offset < data_len; offset += block_length)
  {
    count = block_length;

    if (offset + block_length > data_len)
    {
      count = data_len - offset;
    }

    mbedtls_cipher_update(&ctx, data + offset, count, output, &output_len);
    smart_str_appendl(&return_val, output, output_len);
  }

  if (mbedtls_cipher_finish(&ctx, output, &output_len) != 0)
  {
    mbedtls_cipher_free(&ctx);

    RETURN_FALSE;
  }

  smart_str_appendl(&return_val, output, output_len);
  smart_str_0(&return_val);

  if (ztag != NULL)
  {
    mbedtls_cipher_write_tag(&ctx, tag, tag_length);
    zval_ptr_dtor(ztag);
    ZVAL_STRINGL(ztag, tag, tag_length);
  }

  mbedtls_cipher_free(&ctx);

  if ((options & MBEDTLS_RAW_DATA) != MBEDTLS_RAW_DATA)
  {
    return_val.s = php_base64_encode(ZSTR_VAL(return_val.s),
      ZSTR_LEN(return_val.s));
  }

  RETVAL_STR(return_val.s);
}

PHP_FUNCTION(mbedtls_decrypt)
{
  zend_long options = 0;
  zend_long tag_length = 16;
  char *data;
  char *method;
  char *key;
  char *iv = "";
  char *tag = "";
  char *aad = "";
  char output[1024];
  size_t data_len;
  size_t method_len;
  size_t key_len;
  size_t iv_len = 0;
  size_t tag_len = 0;
  size_t aad_len = 0;
  size_t offset;
  size_t block_length;
  size_t output_len;
  size_t count;
  mbedtls_cipher_context_t ctx;
  const mbedtls_cipher_info_t *cipher_info;
  smart_str return_val = {0};
  zend_string *decoded_data;

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss|lszsl", &data,
    &data_len, &method, &method_len, &key, &key_len, &options, &iv, &iv_len,
    &tag, &tag_len, &aad, &aad_len) == FAILURE)
  {
    return;
  }

  mbedtls_cipher_init(&ctx);
  cipher_info = mbedtls_cipher_info_from_string(method);

  if (cipher_info == NULL)
  {
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "cipher %s not found", method);

    return;
  }

  mbedtls_cipher_setup(&ctx, cipher_info);
  mbedtls_cipher_setkey(&ctx, key, cipher_info->key_bitlen, MBEDTLS_DECRYPT);

  if ((options & MBEDTLS_ZERO_PADDING) == MBEDTLS_ZERO_PADDING)
  {
    mbedtls_cipher_set_padding_mode(&ctx, MBEDTLS_PADDING_NONE);
  }

  if (iv_len > 0)
  {
    mbedtls_cipher_set_iv(&ctx, iv, iv_len);
  }

  mbedtls_cipher_reset(&ctx);

  if (aad_len > 0)
  {
    mbedtls_cipher_update_ad(&ctx, aad, aad_len);
  }

  block_length = mbedtls_cipher_get_block_size(&ctx);

  if ((options & MBEDTLS_RAW_DATA) != MBEDTLS_RAW_DATA)
  {
    decoded_data = php_base64_decode(data, data_len);
    data_len = ZSTR_LEN(decoded_data);
    data = estrndup(ZSTR_VAL(decoded_data), data_len);

    zend_string_release(decoded_data);
  }

  for (offset = 0; offset < data_len; offset += block_length)
  {
    count = block_length;

    if (offset + block_length > data_len)
    {
      count = data_len - offset;
    }

    mbedtls_cipher_update(&ctx, data + offset, count, output, &output_len);
    smart_str_appendl(&return_val, output, output_len);
  }

  if (mbedtls_cipher_finish(&ctx, output, &output_len) != 0)
  {
    mbedtls_cipher_free(&ctx);

    RETURN_FALSE;
  }

  smart_str_appendl(&return_val, output, output_len);
  smart_str_0(&return_val);

  if (tag_len > 0)
  {
    if (mbedtls_cipher_check_tag(&ctx, tag, tag_len) != 0)
    {
      php_error_docref(NULL TSRMLS_CC, E_WARNING, "tag did not match");
      mbedtls_cipher_free(&ctx);

      return;
    }
  }

  mbedtls_cipher_free(&ctx);

  RETVAL_STR(return_val.s);
}

PHP_FUNCTION(mbedtls_ciphers)
{
  const int *cipher_list;
  const mbedtls_cipher_info_t *cipher_info;

  array_init(return_value);

  cipher_list = mbedtls_cipher_list();

  while (*cipher_list)
  {
    cipher_info = mbedtls_cipher_info_from_type(*cipher_list);
    add_next_index_string(return_value, cipher_info->name);

    cipher_list++;
  }
}
