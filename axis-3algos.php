<?php
$privateKey = openssl_pkey_new(array(
    'private_key_bits' => 2048,
    'private_key_type' => OPENSSL_KEYTYPE_RSA,
));

$publicKey = openssl_pkey_get_details($privateKey)['key'];

$data = '{
    "Data": {
            "userName": "alwebuser",
            "password": "acid_qa"
        },

        "Risks": {}

}';

openssl_public_encrypt($data, $encryptedData, $publicKey, OPENSSL_PKCS1_OAEP_PADDING);

openssl_private_decrypt($encryptedData, $decryptedData, $privateKey, OPENSSL_PKCS1_OAEP_PADDING);

echo "Encrypted Data from 1st algo: " . base64_encode($encryptedData) . "\n";

$encryptionKey2 = random_bytes(32);

$iv = random_bytes(12);

$encryptedData = openssl_encrypt($data, 'aes-256-gcm', $encryptionKey2, 0, $iv, $tag);

$decryptedData = openssl_decrypt($encryptedData, 'aes-256-gcm', $encryptionKey2, 0, $iv, $tag);

echo "Encrypted Data from algo 2: " . base64_encode($encryptedData) . "\n";
	
$privateKey3 = openssl_pkey_new(array(
    'private_key_bits' => 2048,
    'private_key_type' => OPENSSL_KEYTYPE_RSA,
));

$publicKey3 = openssl_pkey_get_details($privateKey3)['key'];


// Sign data with RS256
openssl_sign($data, $signature, $privateKey3, OPENSSL_ALGO_SHA256);

// Verify signature with RS256
$isValid = openssl_verify($data, $signature, $publicKey3, OPENSSL_ALGO_SHA256);

echo "Original Data: $data\n";
echo "Signature: " . base64_encode($signature) . "\n";
echo "Signature Verification: " . ($isValid == 1 ? "Valid" : "Invalid") . "\n";
