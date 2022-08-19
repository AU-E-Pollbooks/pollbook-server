/**
 * @file signature.hpp
 *
 * Classes and functions that wrap the "EVP_DigestSign" and "EVP_DigestVerify"
 * features of OpenSSL.
 */

#pragma once
#include "envelope_key.hpp"
#include "hash.hpp"
#include "openssl_exception.hpp"
#include "pointers.hpp"

#include <openssl/evp.h>
#include <vector>

namespace openssl {

/**
 * A class that wraps the EVP_DigestSign* functions for signing a byte array
 * given a private key. Each function will throw exceptions if the underlying
 * library calls return errors, rather than returning an error code.
 */
class Signer {
    EnvelopeKey private_key;
    const DigestAlgorithm digest_type;
    std::unique_ptr<EVP_MD_CTX, DeleterFor<EVP_MD_CTX>> digest_context;

public:
    /**
     * Constructs a Signer that will use the given private key to sign messages,
     * using the specified digest algorithm to digest (hash) its input.
     */
    Signer(const EnvelopeKey& private_key, DigestAlgorithm digest_type);
    /**
     * @return the "maximum signature size" (in bytes) reported by the private
     * key associated with this Signer. For RSA private keys, this is the exact
     * size of every signature and can be used as the size of signature buffers.
     */
    int get_max_signature_size();
    /**
     * Initializes the Signer to start signing a new message. Must be called
     * before add_bytes or finalize.
     */
    void init();
    /**
     * Adds a byte buffer to the message (sequence of bytes) that this Signer
     * will hash and sign.
     * @param buffer A pointer to a byte array
     * @param buffer_size The length of the byte array
     */
    void add_bytes(const void* buffer, const std::size_t buffer_size);
    /**
     * Signs all of the bytes that have been added with add_bytes (since the
     * last call to init) and places the signature in the provided buffer, which
     * must be the correct length. Only use this if the caller knows the length
     * of the signature and has already allocated a buffer of the right size.
     * @param signature_buffer A pointer to a byte array in which the signature
     * will be written by this function.
     */
    void finalize(uint8_t* signature_buffer);
    /**
     * Signs all of the bytes that have been added with add_bytes (since the
     * last call to init) and returns a byte array containing the signature.
     * @return An array of bytes containing the signature.
     */
    std::vector<uint8_t> finalize();
    /**
     * A convenience method that signs a single byte buffer in one shot and
     * places the signature in a byte buffer assumed to be the correct size.
     * This will internally re-initialize and then finalize the Signer.
     * @param buffer The byte buffer to sign
     * @param buffer_size The length of the byte buffer
     * @param signature_buffer The byte buffer in which the signature will be
     * placed; must be the correct size for this signature.
     */
    void sign_bytes(const void* buffer, std::size_t buffer_size, uint8_t* signature_buffer);
};

class Verifier {
    EnvelopeKey public_key;
    const DigestAlgorithm digest_type;
    std::unique_ptr<EVP_MD_CTX, DeleterFor<EVP_MD_CTX>> digest_context;

public:
    Verifier(const EnvelopeKey& public_key, DigestAlgorithm digest_type);
    /**
     * @return the "maximum signature size" (in bytes) reported by the public
     * key associated with this Signer. For RSA public keys, this is the exact
     * size of every signature and can be used as the size of signature buffers.
     */
    int get_max_signature_size();
    /**
     * Initializes the Verifier to start verifying a new message. Must be
     * called before add_bytes or finalize.
     */
    void init();
    /**
     * Adds a byte buffer to the message (sequence of bytes) that this Verifier
     * will hash and verify.
     * @param buffer A pointer to a byte array
     * @param buffer_size The length of the byte array
     */
    void add_bytes(const void* buffer, std::size_t buffer_size);
    /**
     * Signs all of the bytes that have been added with add_bytes (since the
     * last call to init) and compares them to the provided signature. Returns
     * true if the verification succeeds, false if it fails.
     * @param signature_buffer The byte buffer containing the signature to
     * compare against.
     * @param signature_length The length of the signature buffer
     * @return True if verification succeeds, false if it fails.
     */
    bool finalize(const uint8_t* signature_buffer, std::size_t signature_length);
    /**
     * Signs all of the bytes that have been added with add_bytes (since the
     * last call to init) and compares them to the provided signature. Returns
     * true if the verification succeeds, false if it fails. This version of
     * finalize accepts a modern C++ byte array instead of a plain-C buffer.
     * @param signature A byte array containing the signature to compare
     * against.
     */
    bool finalize(const std::vector<uint8_t>& signature);
    /**
     * A convenience method that verifies a single byte buffer in one shot,
     * given a signature buffer to compare against.
     * @param buffer The byte buffer to verify
     * @param buffer_size The length of the buffer
     * @param signature The signature to compare against
     * @param signature_size The length of the signature in bytes
     * @return True if verification succeeds, false if it fails.
     */
    bool verify_bytes(const void* buffer, std::size_t buffer_size, const uint8_t* signature, std::size_t signature_size);
};

}  // namespace openssl
