--TEST--
Check cipher encrypts & decrypts successfully
--SKIPIF--
<?php
if (!extension_loaded('mbedtls')) {
  echo 'skip';
}
?>
--FILE--
<?php
$data = '0123456701234567';
$key = str_repeat('1', 32);
$iv = str_repeat('1', 16);
$mode = 'AES-256-CBC';

$encrypted = mbedtls_encrypt($data, $mode, $key, 0, $iv);

var_dump($encrypted);

$decrypred = mbedtls_decrypt($encrypted, $mode, $key, 0, $iv);

var_dump($decrypted);
?>
--EXPECT--
string(44) "Cfh1P0GDzFbPmUVptc+IlbfCFrga7puo41+VNHA3Src="
string(16) "0123456701234567"
