#include "epollbook/openssl/envelope_encryption.hpp"
#include "epollbook/openssl/openssl_exception.hpp"

#include <openssl/evp.h>
#include <cassert>

namespace openssl {

const EVP_CIPHER* get_cipher_type_ptr(CipherAlgorithm algorithm_type) {
    switch(algorithm_type) {
        case CipherAlgorithm::AES128_CBC:
            return EVP_aes_128_cbc();
        case CipherAlgorithm::AES128_CFB:
            return EVP_aes_128_cfb();
        case CipherAlgorithm::AES128_CTR:
            return EVP_aes_128_ctr();
        case CipherAlgorithm::AES128_CCM:
            return EVP_aes_128_ccm();
        case CipherAlgorithm::AES128_GCM:
            return EVP_aes_128_gcm();
        case CipherAlgorithm::AES256_CBC:
            return EVP_aes_256_cbc();
        case CipherAlgorithm::AES256_CFB:
            return EVP_aes_256_cfb();
        case CipherAlgorithm::AES256_CTR:
            return EVP_aes_256_ctr();
        case CipherAlgorithm::AES256_CCM:
            return EVP_aes_256_ccm();
        case CipherAlgorithm::AES256_GCM:
            return EVP_aes_256_gcm();
        default:
            return EVP_aes_256_cbc();
    }
}

EnvelopeEncryptor::EnvelopeEncryptor(const EnvelopeKey& target_public_key, CipherAlgorithm algorithm_type)
    : public_key(target_public_key),
      cipher_type(algorithm_type),
      cipher_context(EVP_CIPHER_CTX_new()) {}

int EnvelopeEncryptor::get_IV_size() {
    return EVP_CIPHER_get_iv_length(get_cipher_type_ptr(cipher_type));
}

int EnvelopeEncryptor::get_encrypted_key_size() {
    return public_key.get_max_size();
}

int EnvelopeEncryptor::get_cipher_block_size() {
    return EVP_CIPHER_get_block_size(get_cipher_type_ptr(cipher_type));
}

std::size_t EnvelopeEncryptor::compute_output_buffer_size(std::size_t input_buffer_size) {
    std::size_t block_size = get_cipher_block_size();
    // Round down to the nearest multiple of block size, then add 1 more block
    return (input_buffer_size / block_size) * block_size + block_size;
}

void EnvelopeEncryptor::init(unsigned char* encrypted_key_buffer, unsigned char* iv_buffer) {
    if(EVP_CIPHER_CTX_reset(cipher_context.get()) != 1) {
        throw openssl_error(ERR_get_error(), "EVP_CIPHER_CTX_reset");
    }
    unsigned char** singleton_ek_array = &encrypted_key_buffer;
    EVP_PKEY* pkey = public_key;
    EVP_PKEY** singleton_pkey_array = &pkey;
    int encrypted_key_length = 0;
    if(EVP_SealInit(cipher_context.get(), get_cipher_type_ptr(cipher_type),
                    singleton_ek_array, &encrypted_key_length, iv_buffer,
                    singleton_pkey_array, 1) == 0) {
        throw openssl_error(ERR_get_error(), "EVP_SealInit");
    }
    assert(encrypted_key_length == get_encrypted_key_size());
}

std::size_t EnvelopeEncryptor::encrypt_bytes(const unsigned char* input_buffer, std::size_t input_size, unsigned char* output_buffer) {
    int output_length = 0;
    if(EVP_SealUpdate(cipher_context.get(), output_buffer, &output_length, input_buffer, input_size) != 1) {
        throw openssl_error(ERR_get_error(), "EVP_SealUpdate");
    }
    return output_length;
}

std::size_t EnvelopeEncryptor::finalize(unsigned char* output_buffer) {
    int output_length = 0;
    if(EVP_SealFinal(cipher_context.get(), output_buffer, &output_length) != 1) {
        throw openssl_error(ERR_get_error(), "EVP_SealFinal");
    }
    return output_length;
}

std::vector<unsigned char> EnvelopeEncryptor::make_encrypted_message(const unsigned char* input_bytes, std::size_t input_size) {
    std::size_t total_output_size = get_encrypted_key_size() + get_IV_size() + compute_output_buffer_size(input_size);
    std::vector<unsigned char> output_buffer(total_output_size);
    // Place the encrypted key in the buffer first, followed by the IV
    init(output_buffer.data(), output_buffer.data() + get_encrypted_key_size());
    std::size_t bytes_written = get_IV_size() + get_encrypted_key_size();
    bytes_written += encrypt_bytes(input_bytes, input_size, output_buffer.data() + bytes_written);
    bytes_written += finalize(output_buffer.data() + bytes_written);
    assert(bytes_written == total_output_size);
    return output_buffer;
}

EnvelopeDecryptor::EnvelopeDecryptor(const EnvelopeKey& private_key, CipherAlgorithm algorithm_type)
    : private_key(private_key),
      cipher_type(algorithm_type),
      cipher_context(EVP_CIPHER_CTX_new()) {}

int EnvelopeDecryptor::get_IV_size() {
    return EVP_CIPHER_get_iv_length(get_cipher_type_ptr(cipher_type));
}

int EnvelopeDecryptor::get_encrypted_key_size() {
    return private_key.get_max_size();
}

void EnvelopeDecryptor::init(const unsigned char* encrypted_key_buffer, const unsigned char* iv_buffer) {
    if(EVP_CIPHER_CTX_reset(cipher_context.get()) != 1) {
        throw openssl_error(ERR_get_error(), "EVP_CIPHER_CTX_reset");
    }
    int encrypted_key_length = get_encrypted_key_size();
    if(EVP_OpenInit(cipher_context.get(), get_cipher_type_ptr(cipher_type),
                    encrypted_key_buffer, encrypted_key_length, iv_buffer,
                    private_key) == 0) {
        throw openssl_error(ERR_get_error(), "EVP_SealInit");
    }
}

std::size_t EnvelopeDecryptor::decrypt_bytes(const unsigned char* input_buffer, std::size_t input_size, unsigned char* output_buffer) {
    int output_length = 0;
    if(EVP_OpenUpdate(cipher_context.get(), output_buffer, &output_length, input_buffer, input_size) != 1) {
        throw openssl_error(ERR_get_error(), "EVP_OpenUpdate");
    }
    return output_length;
}

std::size_t EnvelopeDecryptor::finalize(unsigned char* output_buffer) {
    int output_length = 0;
    if(EVP_OpenFinal(cipher_context.get(), output_buffer, &output_length) != 1) {
        throw openssl_error(ERR_get_error(), "EVP_OpenFinal");
    }
    return output_length;
}

}  // namespace openssl