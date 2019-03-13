<?php

echo "\n", "==== CA CERTIFICATE ====", "\n";

$ca = [
  'private_key' => null,
  'certificate' => null
];

{
  $keyResource = mbedtls_pkey_new([
    'private_key_bits' => 2048
  ]);

  $subject = ['commonName' => 'big signer'];

  if (gettype($keyResource) !== 'resource') {
    echo 'CA', 'CREATE', 'could not create new private key', "\n";
  }

  $csrResource = mbedtls_csr_new($subject, $keyResource);

  if (gettype($csrResource) !== 'resource') {
    echo 'CA', 'CREATE', 'could not create certificate request', "\n";
  }

  $certificateSerial = 1;
  $certificateResource = mbedtls_csr_sign($csrResource, null, $keyResource, 3453, [],
    $certificateSerial);

  if (gettype($certificateResource) !== 'resource') {
    echo 'CA', 'CREATE', 'could not self-sign certificate', "\n";
  }

  if (!mbedtls_pkey_export($keyResource, $keyPem)) {
    echo 'CA', 'CREATE', 'could not export private key', "\n";
  }

  $publicPem = mbedtls_pkey_get_details($keyResource)['key'];

  echo 'Public: ', "\n", $publicPem, "\n";
  echo 'Private: ', "\n", $keyPem, "\n";

  if (!mbedtls_x509_export($certificateResource, $certificatePem)) {
    echo 'CA', 'CREATE', 'could not export certificate', "\n";
  }

  $certificateFingerprint = mbedtls_x509_fingerprint($certificateResource, 'SHA1');

  echo 'Serial: ', $certificateSerial, "\n";
  echo 'Certificate: ', "\n", $certificatePem, "\n";
  echo 'Fingerprint: ', $certificateFingerprint, "\n";

  $ca['private_key'] = $keyPem;
  $ca['certificate'] = $certificatePem;
}

echo "\n", "==== FIRST CERTIFICATE ====", "\n";

$cert1 = [
  'private_key' => null,
  'certificate' => null
];

{
  $keyResource = mbedtls_pkey_new([
    'private_key_bits' => 2048
  ]);

  if (gettype($keyResource) !== 'resource') {
    echo 'CERTIFICATE', 'CREATE', 'could not create new private key', "\n";
  }

  $subject['commonName'] = 'sert 1';

  $csrResource = mbedtls_csr_new($subject, $keyResource);

  if (gettype($csrResource) !== 'resource') {
    echo 'CERTIFICATE', 'CREATE', 'could not create certificate request', "\n";
  }

  $caResource = mbedtls_x509_read($ca['certificate']);

  if (gettype($caResource) !== 'resource') {
    echo 'CERTIFICATE', 'CREATE', 'could not load certificate authority', "\n";
  }

  $caKeyResource = mbedtls_pkey_get_private($ca['private_key']);

  if (gettype($caKeyResource) !== 'resource') {
    echo 'CERTIFICATE', 'CREATE', 'could not load authority private key', "\n";
  }

  $certificateSerial = 2;
  $certificateResource = mbedtls_csr_sign($csrResource, $caResource, $caKeyResource, 3453, [],
    $certificateSerial);

  if (gettype($certificateResource) !== 'resource') {
    echo 'CERTIFICATE', 'CREATE', 'could not sign certificate', "\n";
  }

  if (!mbedtls_pkey_export($keyResource, $keyPem)) {
    echo 'CA', 'CREATE', 'could not export private key', "\n";
  }

  $publicPem = mbedtls_pkey_get_details($keyResource)['key'];

  echo 'Public: ', "\n", $publicPem, "\n";
  echo 'Private: ', "\n", $keyPem, "\n";

  if (!mbedtls_x509_export($certificateResource, $certificatePem)) {
    echo 'CA', 'CREATE', 'could not export certificate', "\n";
  }

  $certificateFingerprint = mbedtls_x509_fingerprint($certificateResource, 'SHA1');

  echo 'Serial: ', $certificateSerial, "\n";
  echo 'Certificate: ', "\n", $certificatePem, "\n";
  echo 'Fingerprint: ', $certificateFingerprint, "\n";

  $cert1['private_key'] = $keyPem;
  $cert1['certificate'] = $certificatePem;
}

echo "\n", "==== SECOND CERTIFICATE ====", "\n";

$cert1 = [
  'private_key' => null,
  'certificate' => null
];

{
  $keyResource = mbedtls_pkey_new([
    'private_key_bits' => 2048
  ]);

  if (gettype($keyResource) !== 'resource') {
    echo 'CERTIFICATE', 'CREATE', 'could not create new private key', "\n";
  }

  $subject['commonName'] = 'sert 2';

  $csrResource = mbedtls_csr_new($subject, $keyResource);

  if (gettype($csrResource) !== 'resource') {
    echo 'CERTIFICATE', 'CREATE', 'could not create certificate request', "\n";
  }

  $caResource = mbedtls_x509_read($ca['certificate']);

  if (gettype($caResource) !== 'resource') {
    echo 'CERTIFICATE', 'CREATE', 'could not load certificate authority', "\n";
  }

  $caKeyResource = mbedtls_pkey_get_private($ca['private_key']);

  if (gettype($caKeyResource) !== 'resource') {
    echo 'CERTIFICATE', 'CREATE', 'could not load authority private key', "\n";
  }

  $certificateSerial = 3;
  $certificateResource = mbedtls_csr_sign($csrResource, $caResource, $caKeyResource, 3453, [],
    $certificateSerial);

  if (gettype($certificateResource) !== 'resource') {
    echo 'CERTIFICATE', 'CREATE', 'could not sign certificate', "\n";
  }

  if (!mbedtls_pkey_export($keyResource, $keyPem)) {
    echo 'CA', 'CREATE', 'could not export private key', "\n";
  }

  $publicPem = mbedtls_pkey_get_details($keyResource)['key'];

  echo 'Public: ', "\n", $publicPem, "\n";
  echo 'Private: ', "\n", $keyPem, "\n";

  if (!mbedtls_x509_export($certificateResource, $certificatePem)) {
    echo 'CA', 'CREATE', 'could not export certificate', "\n";
  }

  $certificateFingerprint = mbedtls_x509_fingerprint($certificateResource, 'SHA1');

  echo 'Serial: ', $certificateSerial, "\n";
  echo 'Certificate: ', "\n", $certificatePem, "\n";
  echo 'Fingerprint: ', $certificateFingerprint, "\n";

  $cert2['private_key'] = $keyPem;
  $cert2['certificate'] = $certificatePem;
}

echo "\n", "==== REVOKING CERTIFICATE ====", "\n";

{
  $certRes = mbedtls_x509_read($ca['certificate']);

  $crlResource = mbedtls_crl_new($certRes, $ca['private_key'], [
    'next_update' => 10
  ]);

  if (gettype($crlResource) !== 'resource') {
    throw new \Exception('Failed to create CRL');
  }

  if (!mbedtls_crl_revoke($crlResource, $cert2['certificate'], 1)) {
    throw new \Exception('Failed to revoke certificate');
  }

  if (!mbedtls_crl_export($crlResource, $crlPem)) {
    throw new \Exception('Failed to export CRL');
  }

  echo 'latestCrl: ', "\n", $crlPem, "\n";
}

echo 'Press any key to continue'
fgetc(STDIN);