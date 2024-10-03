#ifndef ADDONS_H
#define ADDONS_H
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <cstdint> // For uint8_t
#include <unordered_map>
#include <stdexcept>
#include <cctype>
#include <regex>
#include <openssl/x509.h>
#include <openssl/x509v3.h> // Include this header for STACK_OF(X509_ATTRIBUTE)
#include <openssl/sha.h>
#include <openssl/asn1.h>
#include <openssl/cms.h>
#include <openssl/pkcs12.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

// Class declaration
class Addons {

public:
    // Constructor
    Addons();
    
    // Member function declaration
    std::string base64_encode_2(const unsigned char* input, int length);
    std::vector<uint8_t> base64_decode_2(const std::string& base64Data);
    std::string binaryToHex_2(const unsigned char* data, size_t length);
    void print_attribute_oid(const X509_ATTRIBUTE* attr);
    bool loadPKCS12_2(const std::string& pkcs12Path, const std::string& password, EVP_PKEY*& pkey, X509*& cert, STACK_OF(X509)*& ca);
    std::vector<unsigned char> readData(std::string filePath);
    std::string digest(std::vector<unsigned char> data);
    std::string vectorToStringHex_2(const std::vector<uint8_t>& vec);
    std::string asn1_string_to_hex_string(const ASN1_STRING *asn1_string);
    std::string get_digest_hex_from_signer_info(const CMS_SignerInfo* signer_info);
    void find_and_replace(std::string &str, const std::string &to_find, const std::string &replace_with);
    void handleErrors();
    X509* loadCertificate(const std::string& filename);
    EVP_PKEY* loadPrivateKey(const std::string& filename, const char *password);
    STACK_OF(X509)* loadCertificateChain(const std::string& filename);
    X509_REQ* load_csr(const char *filename);
    X509* createSignedCertificate(X509_REQ* req, X509* caCert, EVP_PKEY* caKey);
};

#endif