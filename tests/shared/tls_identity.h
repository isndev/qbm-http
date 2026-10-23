/**
 * @file tls_identity.h
 * @brief Local self-signed identities for HTTP certificate-rotation tests.
 */
#pragma once

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <qb/io/tcp/ssl/context.h>

namespace qb::http::test {

// Memory BIOs avoid passing a Windows CRT FILE* into OpenSSL. No dependency on qb's
// private test tree: a module checkout has everything this fixture needs.
class tls_identity {
    std::filesystem::path _cert;
    std::filesystem::path _key;
    bool                  _ok{false};

    static bool
    write_pem(BIO *bio, std::filesystem::path const &path) {
        char      *bytes = nullptr;
        const auto size  = BIO_get_mem_data(bio, &bytes);
        if (size <= 0)
            return false;
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        out.write(bytes, static_cast<std::streamsize>(size));
        return static_cast<bool>(out);
    }

public:
    explicit tls_identity(std::string const &name) {
        const auto stamp    = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        const auto base     = std::filesystem::temp_directory_path() / ("qbm-tls-" + name + "-" + stamp);
        _cert               = base.string() + ".crt";
        _key                = base.string() + ".key";
        EVP_PKEY  *key      = EVP_EC_gen("P-256");
        X509      *cert     = X509_new();
        X509_NAME *subject  = X509_NAME_new();
        BIO       *cert_bio = BIO_new(BIO_s_mem());
        BIO       *key_bio  = BIO_new(BIO_s_mem());
        _ok                 = key && cert && subject && cert_bio && key_bio;
        if (_ok) {
            _ok = X509_set_version(cert, 2) == 1 && ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) == 1
                  && X509_gmtime_adj(X509_getm_notBefore(cert), -3600) && X509_gmtime_adj(X509_getm_notAfter(cert), 3600)
                  && X509_set_pubkey(cert, key) == 1
                  && X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, reinterpret_cast<unsigned char const *>(name.c_str()), -1, -1, 0)
                         == 1
                  && X509_set_subject_name(cert, subject) == 1 && X509_set_issuer_name(cert, subject) == 1
                  && X509_sign(cert, key, EVP_sha256()) > 0 && PEM_write_bio_X509(cert_bio, cert) == 1
                  && PEM_write_bio_PrivateKey(key_bio, key, nullptr, nullptr, 0, nullptr, nullptr) == 1 && write_pem(cert_bio, _cert)
                  && write_pem(key_bio, _key);
        }
        BIO_free(cert_bio);
        BIO_free(key_bio);
        X509_NAME_free(subject);
        X509_free(cert);
        EVP_PKEY_free(key);
    }
    tls_identity(tls_identity const &)            = delete;
    tls_identity &operator=(tls_identity const &) = delete;
    ~tls_identity() {
        std::error_code ignored;
        std::filesystem::remove(_cert, ignored);
        std::filesystem::remove(_key, ignored);
    }
    bool
    ok() const {
        return _ok;
    }
    std::filesystem::path const &
    cert() const {
        return _cert;
    }
    std::filesystem::path const &
    key() const {
        return _key;
    }
    qb::io::ssl::Context
    context() const {
        return qb::io::ssl::Context::server(_cert, _key);
    }
};

} // namespace qb::http::test
