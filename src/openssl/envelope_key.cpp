#include "epollbook/openssl/envelope_key.hpp"
#include "epollbook/openssl/openssl_exception.hpp"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <cstdio>
#include <cstring>
#include <string>

namespace openssl {
EnvelopeKey& EnvelopeKey::operator=(const EnvelopeKey& other) {
    if(&other == this) {
        return *this;
    }
    key.reset(other.key.get());
    EVP_PKEY_up_ref(key.get());
    return *this;
}

EnvelopeKey& EnvelopeKey::operator=(EnvelopeKey&& other) {
    key = std::move(other.key);
    return *this;
}

bool operator==(EnvelopeKey& lhs, EnvelopeKey& rhs) {
    return EVP_PKEY_eq(lhs, rhs) == 1;
}

int EnvelopeKey::get_max_size() {
    return EVP_PKEY_size(key.get());
}

std::string EnvelopeKey::to_pem_public() const {
    // Serialize the key to PEM format in memory
    std::unique_ptr<BIO, DeleterFor<BIO>> memory_bio(BIO_new(BIO_s_mem()));
    if(PEM_write_bio_PUBKEY(memory_bio.get(), key.get()) != 1) {
        throw openssl_error(ERR_get_error(), "Write public key to memory");
    }
    // Copy the PEM string from the memory BIO to a C++ string
    //(It would be nice if we could just make OpenSSL write directly into the C++ string)
    char* memory_bio_data;
    long data_size = BIO_get_mem_data(memory_bio.get(), &memory_bio_data);
    std::string pem_string;
    pem_string.resize(data_size);
    memcpy(pem_string.data(), memory_bio_data, data_size);
    return pem_string;
}

void EnvelopeKey::to_pem_public(const std::string& pem_file_name) const {
    FILE* pem_file = fopen(pem_file_name.c_str(), "w");
    if(pem_file == NULL) {
        switch(errno) {
            case EACCES:
            case EPERM:
                throw permission_denied(errno, pem_file_name);
            case ENOENT:
                throw file_not_found(errno, pem_file_name);
            default:
                throw file_error(errno, pem_file_name);
        }
    }
    if(PEM_write_PUBKEY(pem_file, key.get()) != 1) {
        fclose(pem_file);
        throw openssl_error(ERR_get_error(), "Write public key to file");
    }
    fclose(pem_file);
}

EnvelopeKey EnvelopeKey::from_pem_private(const std::string& pem_file_name) {
    FILE* pem_file = fopen(pem_file_name.c_str(), "r");
    if(pem_file == NULL) {
        switch(errno) {
            case EACCES:
            case EPERM:
                throw permission_denied(errno, pem_file_name);
            case ENOENT:
                throw file_not_found(errno, pem_file_name);
            default:
                throw file_error(errno, pem_file_name);
        }
    }
    EnvelopeKey private_key(PEM_read_PrivateKey(pem_file, NULL, NULL, NULL));
    fclose(pem_file);
    if(!private_key) {
        throw openssl_error(ERR_get_error(), "Load private key");
    }
    return private_key;
}
EnvelopeKey EnvelopeKey::from_pem_private(const void* byte_buffer, std::size_t buffer_size) {
    std::unique_ptr<BIO, DeleterFor<BIO>> buffer_bio(BIO_new_mem_buf(byte_buffer, buffer_size));
    EnvelopeKey private_key(PEM_read_bio_PrivateKey(buffer_bio.get(), NULL, NULL, NULL));
    if(!private_key) {
        throw openssl_error(ERR_get_error(), "Load private key");
    }
    return private_key;
}

EnvelopeKey EnvelopeKey::from_pem_public(const std::string& pem_file_name) {
    FILE* pem_file = fopen(pem_file_name.c_str(), "r");
    if(pem_file == NULL) {
        switch(errno) {
            case EACCES:
            case EPERM:
                throw permission_denied(errno, pem_file_name);
            case ENOENT:
                throw file_not_found(errno, pem_file_name);
            default:
                throw file_error(errno, pem_file_name);
        }
    }
    EnvelopeKey public_key(PEM_read_PUBKEY(pem_file, NULL, NULL, NULL));
    fclose(pem_file);
    if(!public_key) {
        throw openssl_error(ERR_get_error(), "Load public key");
    }
    return public_key;
}

EnvelopeKey EnvelopeKey::from_pem_public(const void* byte_buffer, std::size_t buffer_size) {
    std::unique_ptr<BIO, DeleterFor<BIO>> buffer_bio(BIO_new_mem_buf(byte_buffer, buffer_size));
    EnvelopeKey public_key(PEM_read_bio_PUBKEY(buffer_bio.get(), NULL, NULL, NULL));
    if(!public_key) {
        throw openssl_error(ERR_get_error(), "Load public key");
    }
    return public_key;
}

}  // namespace openssl
