#include "../header/addons.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <cstdint>
#include <unordered_map>
#include <stdexcept>
#include <cctype>
#include <regex>
#include <sstream>
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
#include <iomanip>

Addons::Addons() {
    // Initialize private member variables or perform any necessary setup
}


std::string Addons::base64_encode_2(const unsigned char* input, int length) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bio = BIO_new(BIO_s_mem());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, bio);
    BIO_write(b64, input, length);
    BIO_flush(b64);

    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(b64, &bufferPtr);

    std::string base64_output(bufferPtr->data, bufferPtr->length); // Exclude null terminator

    BIO_free_all(b64);
    BIO_free_all(bio);

    return base64_output;
}


std::vector<uint8_t> Addons::base64_decode_2(const std::string& base64Data) {
    BIO *bio, *b64;
    std::vector<uint8_t> decodedData;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new_mem_buf((void*)base64Data.c_str(), base64Data.length());
    bio = BIO_push(b64, bio);

    // Allocate enough memory for decoding
    decodedData.resize(base64Data.length());

    // Perform decoding
    int len = BIO_read(bio, decodedData.data(), decodedData.size());
    if (len > 0) {
        // Resize vector to actual decoded length
        decodedData.resize(len);
    } else {
        // Handle decoding error
        std::cerr << "Error decoding Base64 data" << std::endl;
        decodedData.clear();
    }

    // Free BIOs
    BIO_free_all(bio);

    return decodedData;
}

// Function to convert binary data to hex string
std::string Addons::binaryToHex_2(const unsigned char* data, size_t length) {
    std::ostringstream oss;
    for (size_t i = 0; i < length; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return oss.str();
}

// Print the OID of the X509_ATTRIBUTE
void Addons::print_attribute_oid(const X509_ATTRIBUTE* attr) {
    const ASN1_OBJECT* obj = X509_ATTRIBUTE_get0_object(const_cast<X509_ATTRIBUTE*>(attr));
    char buffer[128];
    OBJ_obj2txt(buffer, sizeof(buffer), obj, 1);
    std::cout << "OID: " << buffer << std::endl;
}

// Function to load PKCS#12 file and extract certificate, private key, and the chain of certificates
bool Addons::loadPKCS12_2(const std::string& pkcs12Path, const std::string& password, EVP_PKEY*& pkey, X509*& cert, STACK_OF(X509)*& ca) {
    FILE* fp = fopen(pkcs12Path.c_str(), "rb");
    if (!fp) {
        std::cerr << "Unable to open PKCS#12 file" << std::endl;
        return false;
    }

    PKCS12* p12 = d2i_PKCS12_fp(fp, nullptr);
    fclose(fp);

    if (!p12) {
        std::cerr << "Unable to parse PKCS#12 file" << std::endl;
        return false;
    }

    if (!PKCS12_parse(p12, password.c_str(), &pkey, &cert, &ca)) {
        std::cerr << "Unable to parse PKCS#12 structure" << std::endl;
        PKCS12_free(p12);
        return false;
    }

    PKCS12_free(p12);
    return true;
}

void Addons::handleErrors() {
    // Print OpenSSL errors to stderr
    ERR_print_errors_fp(stderr);
    
    // Optionally, throw an exception to allow for graceful error handling
    throw std::runtime_error("An error occurred in OpenSSL. Check stderr for details.");
}

std::vector<unsigned char> Addons::readData(std::string filePath) {
    std::ifstream ifs(filePath, std::ios::binary);
    if (!ifs) {
        throw std::runtime_error("Failed to open data file.");
    }

    // Read the entire file into the vector
    std::vector<unsigned char> data((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    return data;
}

std::string Addons::digest(std::vector<unsigned char> data) {
    // Create a SHA256 hash
    unsigned char sha256_digest[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), sha256_digest);

    // Encode the hash as a base64 string
    std::string hash = base64_encode_2(sha256_digest, SHA256_DIGEST_LENGTH);

    return hash;
}

// Function to convert std::vector<uint8_t> to an octet string (hexadecimal representation)
std::string Addons::vectorToStringHex_2(const std::vector<uint8_t>& vec) {
    std::ostringstream oss;
    
    // Iterate over each byte in the vector
    for (auto byte : vec) {
        // Print each byte as two-digit hexadecimal, uppercase
        oss << std::hex << std::nouppercase << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        // Optionally add a space between bytes for readability
        // oss << ' ';
    }
    
    return oss.str();
}

// Function to convert ASN1_STRING to a hexadecimal std::string
std::string Addons::asn1_string_to_hex_string(const ASN1_STRING *asn1_string) {
    const unsigned char *data = ASN1_STRING_get0_data(asn1_string);
    int length = ASN1_STRING_length(asn1_string);

    std::ostringstream hex_stream;

    // Convert each byte to a two-digit hexadecimal value
    for (int i = 0; i < length; i++) {
        hex_stream << std::hex << std::nouppercase << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }

    return hex_stream.str();
}

// Function to convert ASN1_STRING to a hexadecimal std::string
std::string Addons::get_digest_hex_from_signer_info(const CMS_SignerInfo* signer_info) {
    // Define the NID for messageDigest attribute
    int nid_message_digest = NID_pkcs9_messageDigest;
    // Get the count of signed attributes
    int attr_count = CMS_signed_get_attr_count(signer_info);
    if (attr_count < 0) {
        fprintf(stderr, "Error getting attribute count\n");
        return "";
    }
    // Try to find the digest attribute by NID
    int attr_pos = CMS_signed_get_attr_by_NID(signer_info, nid_message_digest, -1);
    if (attr_pos < 0) {
        fprintf(stderr, "Digest attribute not found\n");
        return "";
    }
    // Get the attribute at the found position
    X509_ATTRIBUTE *attr = CMS_signed_get_attr(signer_info, attr_pos);
    if (!attr) {
        fprintf(stderr, "Error getting attribute\n");
        return "";
    }
    // Extract and print the digest data
    const ASN1_TYPE *attr_value = X509_ATTRIBUTE_get0_type(attr, 0);
    if (attr_value) {
        if (attr_value->type == V_ASN1_OCTET_STRING) {
            ASN1_STRING *datal = attr_value->value.asn1_string;
            const unsigned char *datan = ASN1_STRING_get0_data(datal);
            int length = ASN1_STRING_length(datal);
            std::ostringstream hex_stream;
            for (int i = 0; i < length; i++) {
                hex_stream << std::hex << std::nouppercase << std::setw(2) << std::setfill('0') << static_cast<int>(datan[i]);
            }
            return hex_stream.str();
        } else {
            fprintf(stderr, "Attribute value is not an ASN1_OCTET_STRING\n");
        return "";
        }
    } else {
        fprintf(stderr, "Error extracting attribute value\n");
        return "";
    }
}


void Addons::find_and_replace(std::string &str, const std::string &to_find, const std::string &replace_with) {
    std::string::size_type pos = 0;

    // Loop to find and replace all occurrences
    while ((pos = str.find(to_find, pos)) != std::string::npos) {
        str.replace(pos, to_find.length(), replace_with);
        pos += replace_with.length(); // Move past the replaced part
    }
}



// Function to load a PEM file into an X509 structure
X509* Addons::loadCertificate(const std::string& filename) {
    FILE* file = fopen(filename.c_str(), "r");
    if (!file) {
        perror("Unable to open certificate file");
        handleErrors();
    }

    X509* cert = PEM_read_X509(file, NULL, NULL, NULL);
    fclose(file);

    if (!cert) {
        std::cerr << "Error loading certificate from file" << std::endl;
        handleErrors();
    }

    return cert;
}

// Function to load a PEM file into an EVP_PKEY structure
EVP_PKEY* Addons::loadPrivateKey(const std::string& filename, const char *password) {
    FILE* file = fopen(filename.c_str(), "r");
    if (!file) {
        perror("Unable to open private key file");
        handleErrors();
    }

    EVP_PKEY* key = PEM_read_PrivateKey(file, NULL, NULL, (void *)password);
    fclose(file);

    if (!key) {
        std::cerr << "Error loading private key from file" << std::endl;
        handleErrors();
    }

    return key;
}

// Function to load a PEM file into a stack of X509 structures (certificate chain)
STACK_OF(X509)* Addons::loadCertificateChain(const std::string& filename) {
    FILE* file = fopen(filename.c_str(), "r");
    if (!file) {
        perror("Unable to open certificate chain file");
        handleErrors();
    }

    STACK_OF(X509)* chain = sk_X509_new_null();
    if (!chain) {
        std::cerr << "Error creating certificate chain stack" << std::endl;
        handleErrors();
    }

    X509* cert;
    while ((cert = PEM_read_X509(file, NULL, NULL, NULL)) != NULL) {
        if (sk_X509_push(chain, cert) == 0) {
            std::cerr << "Error adding certificate to chain" << std::endl;
            handleErrors();
        }
    }

    fclose(file);

    if (sk_X509_num(chain) == 0) {
        std::cerr << "No certificates found in chain file" << std::endl;
        handleErrors();
    }

    return chain;
}

// Function to load a CSR from a PEM file
X509_REQ* Addons::load_csr(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("fopen");
        handleErrors();
    }

    X509_REQ *req = PEM_read_X509_REQ(file, NULL, NULL, NULL);
    fclose(file);

    if (!req) {
        handleErrors();
    }

    return req;
}

X509* Addons::createSignedCertificate(X509_REQ* req, X509* caCert, EVP_PKEY* caKey) {
    // Create a new X509 certificate
    X509* cert = X509_new();
    if (cert == NULL) {
        handleErrors();
    }

    // Copy the CSR information to the certificate
    X509_set_version(cert, 2); // X509 version 3
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1); // Set the serial number
    X509_gmtime_adj(X509_get_notBefore(cert), 0); // Valid from now
    X509_gmtime_adj(X509_get_notAfter(cert), 365*24*60*60); // Valid for 365 days

    // Set the CA certificate's issuer as the certificate's issuer
    X509_set_issuer_name(cert, X509_get_subject_name(caCert));

    // Set the CSR's subject as the certificate's subject
    X509_set_subject_name(cert, X509_REQ_get_subject_name(req));

    // Set the public key from the CSR
    EVP_PKEY* pkey = X509_REQ_get_pubkey(req);
    X509_set_pubkey(cert, pkey);
    EVP_PKEY_free(pkey);

    // Sign the certificate with the CA's private key
    if (X509_sign(cert, caKey, EVP_sha256()) == 0) {
        handleErrors();
    }

    return cert;
}