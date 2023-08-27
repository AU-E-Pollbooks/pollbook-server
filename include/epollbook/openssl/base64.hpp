#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <string>
#include <cstring>
#include <vector>


#ifndef BASE64_H
#define BASE64_H
class Base64 {
public:
    static std::string encode(const uint8_t* input, size_t length) {
        BIO *bio, *b64;
        BUF_MEM *buffer_ptr;

        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new(BIO_s_mem());
        bio = BIO_push(b64, bio);

        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
        BIO_write(bio, input, length);
        BIO_flush(bio);

        BIO_get_mem_ptr(bio, &buffer_ptr);
        std::string output(buffer_ptr->data, buffer_ptr->length);

        BIO_free_all(bio);

        return output;
    }

    static std::vector<uint8_t> decode(const std::string& input) {
        BIO *bio, *b64;
        size_t decoded_length;

        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new_mem_buf(input.c_str(), input.length());
        bio = BIO_push(b64, bio);

        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

        std::vector<uint8_t> output(input.length());
        decoded_length = BIO_read(bio, output.data(), input.length());
        output.resize(decoded_length);

        BIO_free_all(bio);

        return output;
    }
};

#endif
