--TEST--
Check if mbedtls is loaded
--SKIPIF--
<?php
if (!extension_loaded('mbedtls')) {
	echo 'skip';
}
?>
--FILE--
<?php
echo 'The extension "mbedtls" is available';
?>
--EXPECT--
The extension "mbedtls" is available
