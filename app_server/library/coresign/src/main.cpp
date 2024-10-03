#include "../header/addons.h"
#include <iostream>
#include <vector>
#include <cstdint>
#include <string>
#include <cstring>
#include <openssl/pkcs12.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/cms.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>

extern "C" {


void handleErrors(const char* msg) {
    std::cerr << msg << std::endl;
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

// Function to load an X509 certificate from a file
void load_certificate(const char* filename, X509** cert) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        perror("Error opening certificate file");
        exit(EXIT_FAILURE);
    }

    // Try loading as PEM
    *cert = PEM_read_X509(file, NULL, NULL, NULL);
    if (*cert == NULL) {
        // Try loading as DER if PEM fails
        fseek(file, 0, SEEK_SET); // Reset file pointer
        unsigned char* der_data = NULL;
        long der_len = fread(der_data, 1, 1024, file); // Adjust size as needed
        if (der_len < 0) {
            perror("Error reading DER data");
            exit(EXIT_FAILURE);
        }
        if (der_len > 0) {
            *cert = d2i_X509(NULL, (const unsigned char**)&der_data, der_len);
            free(der_data);
        }
    }

    fclose(file);
    if (!*cert) {
        fprintf(stderr, "Error reading certificate from file %s\n", filename);
        exit(EXIT_FAILURE);
    }
}

int genCSR(const char *csrFileName, const char *privateKeyName, const char *password) {
    Addons adns;
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // 1. Generate a new RSA key pair using EVP API
    EVP_PKEY_CTX* pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pkey_ctx) {
        adns.handleErrors();
    }
    
    if (EVP_PKEY_keygen_init(pkey_ctx) <= 0) {
        adns.handleErrors();
    }
    
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, 2048) <= 0) {
        adns.handleErrors();
    }
    
    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen(pkey_ctx, &pkey) <= 0) {
        adns.handleErrors();
    }

    FILE *file = fopen(privateKeyName, "wb");
    if (!file) {
        perror("fopen");
        adns.handleErrors();
    }

    // Write the private key to the file with password encryption
    if (PEM_write_PrivateKey(file, pkey, EVP_aes_256_cbc(), NULL, 0, 
                             NULL, (void *)password) <= 0) {
        ERR_print_errors_fp(stderr);
        fclose(file);
        adns.handleErrors();
    }

    fclose(file);
    
    EVP_PKEY_CTX_free(pkey_ctx);

    // 2. Create a new X509_REQ object
    X509_REQ* req = X509_REQ_new();
    if (req == NULL) {
        adns.handleErrors();
    }
    
    // 3. Set the public key for the CSR
    if (X509_REQ_set_pubkey(req, pkey) != 1) {
        adns.handleErrors();
    }

    // 4. Set the subject name (Distinguished Name) for the CSR
    X509_NAME* name = X509_REQ_get_subject_name(req);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (const unsigned char*)"California", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (const unsigned char*)"San Francisco", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)"My Company", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"www.example.com", -1, -1, 0);

    // 5. Sign the CSR with the private key
    if (X509_REQ_sign(req, pkey, EVP_sha256()) <= 0) {
        adns.handleErrors();
    }

    // 6. Write the CSR to a file
    FILE* fp = fopen(csrFileName, "w");
    if (fp == NULL) {
        perror("Unable to open CSR file for writing");
        adns.handleErrors();
    }

    if (PEM_write_X509_REQ(fp, req) != 1) {
        adns.handleErrors();
    }

    fclose(fp);

    // Clean up
    X509_REQ_free(req);
    EVP_PKEY_free(pkey);
    ERR_free_strings();
    EVP_cleanup();

    std::cout << "CSR has been generated and saved to request.csr" << std::endl;

    return 0;
}

int signCSR(const char *ca_cert_file, const char *pkeyPath, const char *privateKeyPassword, const char *csr_file, const char *cert_file) {
    Addons adns;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Load CSR
    X509_REQ *csr = adns.load_csr(csr_file);
    EVP_PKEY* ca_key = adns.loadPrivateKey(pkeyPath, privateKeyPassword);
    X509* ca_cert = adns.loadCertificate(ca_cert_file);

    // // Sign the CSR and generate a certificate
    X509* userCert = adns.createSignedCertificate(csr, ca_cert, ca_key);

    // Write the signed certificate to file
    FILE *file = fopen(cert_file, "wb");
    if (!file) {
        perror("fopen");
        adns.handleErrors();
    }

    if (!PEM_write_X509(file, userCert)) {
        adns.handleErrors();
    }

    fclose(file);

    // // Clean up
    X509_free(ca_cert);
    X509_free(userCert);
    EVP_PKEY_free(ca_key);
    X509_REQ_free(csr);
    EVP_cleanup();
    ERR_free_strings();

    printf("CSR successfully signed and certificate saved to %s\n", cert_file);

    return 0;
}

int genP12(const char *pkeyPath, const char *certpath, const char *caPath, const char *privateKeyPassword, const char *p12Password, const char *outputP12) {
    Addons adns;
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    try {
        // Load private key, certificate, and chain
        EVP_PKEY* pkey = adns.loadPrivateKey(pkeyPath, privateKeyPassword);
        X509* cert = adns.loadCertificate(certpath);
        STACK_OF(X509)* chain = adns.loadCertificateChain(caPath);


        // Create PKCS#12 structure
        PKCS12 *p12 = PKCS12_create(p12Password, NULL, pkey, cert, chain,
                                    0, 0, 0, 0, 0);

        if (!p12) {
            std::cerr << "Error creating PKCS#12 structure" << std::endl;
            adns.handleErrors();
        }

        // Write the PKCS#12 structure to a file
        FILE* p12File = fopen(outputP12, "wb");
        if (!p12File) {
            perror("Unable to open PKCS#12 file");
            adns.handleErrors();
        }

        if (!i2d_PKCS12_fp(p12File, p12)) {
            std::cerr << "Error writing PKCS#12 file" << std::endl;
            adns.handleErrors();
        }

        fclose(p12File);
        PKCS12_free(p12);
        sk_X509_pop_free(chain, X509_free);
        EVP_PKEY_free(pkey);
        X509_free(cert);

        std::cout << "PKCS#12 file created successfully" << std::endl;
    } catch (...) {
        std::cerr << "Exception caught" << std::endl;
        ERR_print_errors_fp(stderr);
        return 1;
    }

    ERR_free_strings();
    EVP_cleanup();

    return 0;
}

STACK_OF(X509)* create_certificate_stack(const char* ca_cert_file, const char* root_ca_cert_file) {
    STACK_OF(X509)* stack = sk_X509_new_null();
    if (!stack) {
        fprintf(stderr, "Error creating STACK_OF(X509)\n");
        exit(EXIT_FAILURE);
    }

    X509* ca_cert = NULL;
    X509* root_ca_cert = NULL;

    // Load certificates
    load_certificate(ca_cert_file, &ca_cert);
    load_certificate(root_ca_cert_file, &root_ca_cert);

    // Push certificates onto the stack
    if (!sk_X509_push(stack, ca_cert)) {
        fprintf(stderr, "Error pushing CA certificate onto stack\n");
        exit(EXIT_FAILURE);
    }
    if (!sk_X509_push(stack, root_ca_cert)) {
        fprintf(stderr, "Error pushing Root CA certificate onto stack\n");
        exit(EXIT_FAILURE);
    }

    // Clean up
    X509_free(ca_cert);
    X509_free(root_ca_cert);

    return stack;
}

char* sign(const char* p12Path, const char* hashData, const char* passphrase) {
    try {
        Addons adns;

        EVP_PKEY* privateKey = nullptr;
        X509* cert = nullptr;
        STACK_OF(X509)* ca = nullptr;

        std::string data(hashData);
        std::string p12(p12Path);
        std::string password(passphrase);

        if (!adns.loadPKCS12_2(p12, password, privateKey, cert, ca)) {
            std::cerr << "Failed to load PKCS#12 file" << std::endl;
            return nullptr;
        }

        CMS_ContentInfo* cms = CMS_ContentInfo_new();
        if (!cms) {
            std::cerr << "Failed to create CMS_ContentInfo structure" << std::endl;
            EVP_PKEY_free(privateKey);
            X509_free(cert);
            sk_X509_free(ca);
            return nullptr;
        }

        CMS_SignerInfo* signer_info = CMS_add1_signer(cms, cert, privateKey, EVP_sha256(), CMS_DETACHED | CMS_BINARY | CMS_CADES);
        if (!signer_info) {
            std::cerr << "Failed to add signer to CMS" << std::endl;
            CMS_ContentInfo_free(cms);
            EVP_PKEY_free(privateKey);
            X509_free(cert);
            sk_X509_free(ca);
            return nullptr;
        }

        for (int i = 0; i < sk_X509_num(ca); ++i) {
            X509* x509 = sk_X509_value(ca, i);
            if (!CMS_add1_cert(cms, x509)) {
                std::cerr << "Failed to add certificate to CMS" << std::endl;
                CMS_ContentInfo_free(cms);
                EVP_PKEY_free(privateKey);
                X509_free(cert);
                sk_X509_free(ca);
                return nullptr;
            }
        }

        std::vector<uint8_t> data_vec = adns.base64_decode_2(data);
        std::string data_string = std::string(data_vec.begin(), data_vec.end());
        const unsigned char* data_ptr = reinterpret_cast<const unsigned char*>(data_string.c_str());

        if (!CMS_final_digest(cms, data_ptr, 32, nullptr, CMS_DETACHED | CMS_BINARY | CMS_CADES)) {
            std::cerr << "Error finalizing CMS structure" << std::endl;
            adns.handleErrors();
            CMS_ContentInfo_free(cms);
            EVP_PKEY_free(privateKey);
            X509_free(cert);
            sk_X509_free(ca);
            return nullptr;
        }

        BIO* mem = BIO_new(BIO_s_mem());
        if (!i2d_CMS_bio_stream(mem, cms, nullptr, CMS_DETACHED | CMS_BINARY | CMS_CADES)) {
            std::cerr << "Unable to write CMS to memory BIO" << std::endl;
            BIO_free(mem);
            CMS_ContentInfo_free(cms);
            EVP_PKEY_free(privateKey);
            X509_free(cert);
            sk_X509_free(ca);
            return nullptr;
        }

        BUF_MEM* bptr;
        BIO_get_mem_ptr(mem, &bptr);

        std::string hexStr = adns.binaryToHex_2(reinterpret_cast<const unsigned char*>(bptr->data), bptr->length);
        char* cstr = new char[hexStr.size() + 1];
        std::strcpy(cstr, hexStr.c_str());

        BIO_free(mem);
        CMS_ContentInfo_free(cms);
        EVP_PKEY_free(privateKey);
        X509_free(cert);
        sk_X509_free(ca);

        return cstr;

    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return nullptr;
    }
}

} // extern "C"

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <p12Path> <hashData> <passphrase>" << std::endl;
        return 1;
    }

    const char* p12Path = argv[1];
    const char* hashData = argv[2];
    const char* passphrase = argv[3];

    try {
        char* signature = sign(p12Path, hashData, passphrase);

        if (signature) {
            std::cout << "Signature: " << signature << std::endl;
            delete[] signature;  // Free the allocated memory
        } else {
            std::cerr << "Failed to get signature" << std::endl;
            return 1;
        }
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}