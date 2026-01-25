#include "signature.h"

#include <sodium.h>
#include <stdexcept>

namespace crypto {

Signature sign(std::span<const uint8_t> message, const Keypair& keypair) {
    if (!init()) {
        throw std::runtime_error("Failed to initialize libsodium");
    }

    Signature sig;
    unsigned long long sig_len;

    crypto_sign_detached(
        sig.data(),
        &sig_len,
        message.data(),
        message.size(),
        keypair.secret_key().data()
    );

    return sig;
}

bool verify(std::span<const uint8_t> message,
            const Signature& signature,
            const PublicKey& public_key) {
    if (!init()) {
        return false;
    }

    return crypto_sign_verify_detached(
        signature.data(),
        message.data(),
        message.size(),
        public_key.data()
    ) == 0;
}

bool verify(std::span<const uint8_t> message,
            std::span<const uint8_t> signature,
            std::span<const uint8_t> public_key) {
    if (!init()) {
        return false;
    }

    if (signature.size() != SIGNATURE_SIZE || public_key.size() != PUBLIC_KEY_SIZE) {
        return false;
    }

    return crypto_sign_verify_detached(
        signature.data(),
        message.data(),
        message.size(),
        public_key.data()
    ) == 0;
}

} // namespace crypto
