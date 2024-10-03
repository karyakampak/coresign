<?php

$ffi = FFI::cdef("
int genCSR(const char *csrFileName, const char *privateKeyName, const char *password);
int signCSR(const char *ca_cert_file, const char *pkeyPath, const char *privateKeyPassword, const char *csr_file, const char *cert_file);
int genP12(const char *pkeyPath, const char *certpath, const char *caPath, const char *privateKeyPassword, const char *p12Password, const char *outputP12);
char* sign(const char* p12Path, const char* hashData, const char* passphrase);
", "/Users/pusopskamsinas/Documents/Pribadi/Cpp/coresign/build/lib/libcoresign.dylib");




$csrFileName = "/Users/pusopskamsinas/Documents/Pribadi/Cpp/coresign/php/csr.csr";
$privateKeyName = "/Users/pusopskamsinas/Documents/Pribadi/Cpp/coresign/php/private.key";
$passphrase = "karyakampak";
// $ffi->genCSR($csrFileName, $privateKeyName, $passphrase);

$ca_cert_file = "/Users/pusopskamsinas/Documents/Pribadi/Cpp/coresign/php/certificate/certificateCA.crt";
$pkeyPath = "/Users/pusopskamsinas/Documents/Pribadi/Cpp/coresign/php/private.key";
$privateKeyPassword = "karyakampak";
$csr_file = "/Users/pusopskamsinas/Documents/Pribadi/Cpp/coresign/php/csr.csr";
$cert_file = "/Users/pusopskamsinas/Documents/Pribadi/Cpp/coresign/php/user.crt";
// $ffi->signCSR($ca_cert_file, $pkeyPath, $privateKeyPassword, $csr_file, $cert_file);

$privateKeyName = "/Users/pusopskamsinas/Documents/Pribadi/Cpp/coresign/php/private.key";
$caPath = "/Users/pusopskamsinas/Documents/Pribadi/Cpp/coresign/php/certificate/chain.crt";
$certpath = "/Users/pusopskamsinas/Documents/Pribadi/Cpp/coresign/php/user.crt";
$passphrase = "karyakampak";
$outputP12 = "/Users/pusopskamsinas/Documents/Pribadi/Cpp/coresign/php/user.p12";
// $ffi->genP12($privateKeyName, $certpath, $caPath, $passphrase, $passphrase, outputP12);

$p12Path = "/Users/pusopskamsinas/Documents/Pribadi/Cpp/coresign/php/user.p12";
$hashData = "pZGm1Av0IEBKARczz7exkNYsZb8LzaMrV7J32a2fFG4=";
$passphrase = "karyakampak";
$signature = $ffi->sign($p12Path, $hashData, $passphrase);
$signature_string = FFI::string($signature);
echo $signature_string;

?>
