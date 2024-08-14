#include "epollbook/openssl/base64.hpp"
/* #ifndef BASE64_H */
/* #define BASE64_H */

// Define thread-local variables
BIO* Base64::bio_enc = nullptr;
BIO* Base64::bio_dec = nullptr;

std::string Base64::encode(const uint8_t* input, size_t length) {
    Base64::ensureBioInitialized();
    BUF_MEM *buffer_ptr;

    Base64::BIO_set_reset(Base64::bio_enc);
    BIO_write(Base64::bio_enc, input, length);
    BIO_flush(Base64::bio_enc);
    BIO_get_mem_ptr(Base64::bio_enc, &buffer_ptr);

    std::string output(buffer_ptr->data, buffer_ptr->length);
    Base64::BIO_set_reset(Base64::bio_dec);
    return output;
}

/* std::vector<uint8_t> Base64::decode(const std::string& input) { */
/*     BIO *bio, *b64; */
/*     size_t decoded_length; */

/*     b64 = BIO_new(BIO_f_base64()); */
/*     bio = BIO_new_mem_buf(input.c_str(), input.length()); */
/*     bio = BIO_push(b64, bio); */

/*     BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); */

/*     std::vector<uint8_t> output(input.length()); */
/*     decoded_length = BIO_read(bio, output.data(), input.length()); */
/*     output.resize(decoded_length); */

/*     BIO_free_all(bio); */

/*     return output; */
/* } */
std::vector<uint8_t> Base64::decode(const std::string& input) {
    std::cout << "seg fault here: 3" << std::endl;
    Base64::ensureBioInitialized();
    size_t decoded_length;

    BIO* mem = BIO_pop(Base64::bio_dec);
    BIO_reset(mem);
    BIO_write(mem, input.c_str(), input.length());
    BIO_push(Base64::bio_dec, mem);
    std::cout << "seg fault here: 4" << std::endl;

    Base64::BIO_set_reset(Base64::bio_dec);

    std::vector<uint8_t> output(input.length());
    decoded_length = BIO_read(Base64::bio_dec, output.data(), output.size());
    output.resize(decoded_length);
    BIO_free(mem);
    std::cout << "seg fault here: 5" << std::endl;
    /* Base64::BIO_set_reset(Base64::bio_dec); */

    return output;
}

void Base64::ensureBioInitialized(bool isDecoding) {
    // Initialize BIO for encoding if it has not been initialized
    if (isDecoding && !Base64::bio_enc) {
        bio_enc = BIO_new(BIO_f_base64());
        BIO_set_flags(bio_enc, BIO_FLAGS_BASE64_NO_NL);
        BIO *mem_enc = BIO_new(BIO_s_mem());
        bio_enc = BIO_push(bio_enc, mem_enc);
        // do things stuff
        /* BIO *b64_enc = BIO_new(BIO_f_base64()); */
        /* BIO *mem_enc = BIO_new(BIO_s_mem()); */
        /* Base64::bio_enc = BIO_push(b64_enc, mem_enc); */
        /* BIO_set_flags(Base64::bio_enc, BIO_FLAGS_BASE64_NO_NL); // Do not use newlines to flush buffer */
    }

    // Initialize BIO for decoding if it has not been initialized
    if (!isDecoding && !Base64::bio_dec) {
        bio_dec = BIO_new(BIO_f_base64());
        BIO_set_flags(bio_dec, BIO_FLAGS_BASE64_NO_NL);
        BIO *mem_dec = BIO_new(BIO_s_mem());
        bio_dec = BIO_push(bio_dec, mem_dec);
        // experimental 
        /* BIO *b64_dec = BIO_new(BIO_f_base64()); */
        /* BIO *mem_dec = BIO_new(BIO_s_mem()); */
        /* Base64::bio_dec = BIO_push(b64_dec, mem_dec); */
        /* BIO_set_flags(Base64::bio_dec, BIO_FLAGS_BASE64_NO_NL); // Do not use newlines to flush buffer */
    }
}

/* void Base64::BIO_set_reset(BIO* &bio, bool isDecoding) { */
/*     // First, free the existing BIO to clear its state. This is safe even if the BIO is null. */
/*     if (bio != nullptr) { */
/*         BIO_free_all(bio); */
/*         bio = nullptr; // Ensure the pointer is null after freeing to avoid dangling pointer issues. */
/*     } */

/*     // Then, reinitialize the BIOs. This approach ensures that the BIOs are in a clean state. */
/*     ensureBioInitialized(isDecoding); // This will check and reinitialize both bio_enc and bio_dec as needed. */
/* } */

/* void Base64::BIO_set_reset(BIO* bio) { */
/*     std::cout << "seg fault here: 6" << std::endl; */
/*     if (bio != nullptr) { */
/*         BIO_free_all(bio); */
/*         bio = nullptr; // Ensure the pointer is null after freeing to avoid dangling pointer issues. */
/*     } */
/*     std::cout << "seg fault here: 7" << std::endl; */
/*     ensureBioInitialized(false); // This will check and reinitialize both bio_enc and bio_dec as needed. */
    
/* } */

void Base64::BIO_set_reset(BIO* bio) {
    std::cout << "seg fault here: 6" << std::endl;
    BIO_reset(bio);
    BUF_MEM *bptr = nullptr;
    BIO_get_mem_ptr(bio, &bptr);
    BIO_set_mem_eof_return(bio, 0); // Reset the BIO to empty without freeing and reallocating it
    std::cout << "seg fault here: 7" << std::endl;
}


/* #endif */

