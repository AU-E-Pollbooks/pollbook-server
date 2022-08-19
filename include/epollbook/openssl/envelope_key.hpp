#pragma once

#include "pointers.hpp"

#include <openssl/evp.h>
#include <string>

namespace openssl {
/**
 * A class that wraps the EVP_PKEY object used to represent public and private
 * keys in OpenSSL EVP_* functions.
 */
class EnvelopeKey {
    std::unique_ptr<EVP_PKEY, DeleterFor<EVP_PKEY>> key;

public:
    /**
     * Constructs a new EnvelopeKey that wraps an EVP_PKEY pointer returned by
     * some OpenSSL function.
     */
    EnvelopeKey(EVP_PKEY* pkey) : key(pkey){};
    /**
     * Copy constructor: "Copies" the wrapped EVP_PKEY by incrementing its
     * internal reference count and creating a new unique_ptr to it. After a
     * call to EVP_PKEY_up_ref, the first destructor-triggered call to
     * EVP_PKEY_free will actually decrement the reference count rather than
     * free the object.
     */
    EnvelopeKey(const EnvelopeKey& other) : key(other.key.get()) {
        EVP_PKEY_up_ref(key.get());
    }
    /**
     * Move constructor: Takes ownership of the wrapped EVP_PKEY from the other
     * EnvelopeKey, leaving it in an "empty" state.
     */
    EnvelopeKey(EnvelopeKey&& other) : key(std::move(other.key)) {}

    /**
     * Implicit converter to EVP_PKEY* so that this class can be used in OpenSSL
     * functions that expect an EVP_PKEY*; simply gets the wrapped raw pointer.
     */
    operator EVP_PKEY*() {
        return key.get();
    }
    /**
     * Const version of the implicit converter to EVP_PKEY*; gets the wrapped raw pointer.
     */
    operator const EVP_PKEY*() const {
        return key.get();
    }
    /**
     * Implicit bool conversion that matches std::unique_ptr's, so this object
     * can be tested for emptiness in the same way.
     * @return false if the wrapped EVP_PKEY pointer is empty, true if it is not.
     */
    operator bool() {
        return key.operator bool();
    }
    /**
     * Copy assignment operator. Just like the copy constructor, this actually
     * updates the internal reference count of the wrapped EVP_PKEY and then
     * copies the raw pointer.
     */
    EnvelopeKey& operator=(const EnvelopeKey& other);
    /**
     * Move assignment operator.
     */
    EnvelopeKey& operator=(EnvelopeKey&& other);
    /**
     * @return the "maximum output size" (in bytes) reported by this key. For
     * RSA private keys, this is the exact size of every signature and can be
     * used as the size of signature buffers.
     */
    int get_max_size();
    /**
     * Writes the public-key component of this EnvelopeKey (i.e. the entire key
     * if this EnvelopeKey is a public key) out to a PEM file on disk.
     * @param pem_file_name The name (or path) of the PEM file to create
     */
    void to_pem_public(const std::string& pem_file_name);
     /**
     * Serializes the public-key component of this EnvelopeKey into PEM format,
     * then returns the resulting PEM "file" in a string. This avoids the
     * overhead of disk I/O if you need to send the file over the network.
     * @return A string containing the PEM representation of this EnvelopeKey's
     * public component.
     */
    std::string to_pem_public();
    /**
     * Factory function that constructs an EnvelopeKey by loading a public key
     * from a PEM file on disk.
     * @param pem_file_name The name (or path) of the PEM file to read from
     */
    static EnvelopeKey from_pem_public(const std::string& pem_file_name);
    /**
     * Factory function that constructs an EnvelopeKey by loading a public key
     * from a PEM file stored in a byte buffer in memory.
     * @param byte_buffer An array of bytes containing a public key in PEM
     * format
     * @param buffer_size The size of the byte array
     */
    static EnvelopeKey from_pem_public(const void* byte_buffer, std::size_t buffer_size);
    /**
     * Factory function that constructs an EnvelopeKey by loading a private key
     * from a PEM file on disk.
     * @param pem_file_name The name (or path) of the PEM file to read from
     */
    static EnvelopeKey from_pem_private(const std::string& pem_file_name);
    /**
     * Factory function that constructs an EnvelopeKey by loading a private key
     * from a PEM file stored in a byte buffer in memory.
     * @param byte_buffer An array of bytes containing a public key in PEM
     * format
     * @param buffer_size The size of the byte array
     */
    static EnvelopeKey from_pem_private(const void* byte_buffer, std::size_t buffer_size);
};
}