#include "keypair.h"

#include <sodium.h>
#include <stdexcept>

namespace crypto {

bool init() {
    static bool initialized = false;
    if (!initialized) {
        if (sodium_init() < 0) {
            return false;
        }
        initialized = true;
    }
    return true;
}

Keypair::Keypair(PublicKey public_key, SecretKey secret_key)
    : public_key_(public_key), secret_key_(secret_key) {}

Keypair Keypair::generate() {
    if (!init()) {
        throw std::runtime_error("Failed to initialize libsodium");
    }

    PublicKey pk;
    SecretKey sk;

    crypto_sign_keypair(pk.data(), sk.data());

    return Keypair(pk, sk);
}

Keypair Keypair::from_seed(const Seed& seed) {
    if (!init()) {
        throw std::runtime_error("Failed to initialize libsodium");
    }

    PublicKey pk;
    SecretKey sk;

    crypto_sign_seed_keypair(pk.data(), sk.data(), seed.data());

    return Keypair(pk, sk);
}

std::optional<Keypair> Keypair::from_bytes(const SecretKey& secret_key) {
    if (!init()) {
        return std::nullopt;
    }

    PublicKey pk;

    // Extract public key from secret key
    // In Ed25519, secret key contains both seed and public key
    if (crypto_sign_ed25519_sk_to_pk(pk.data(), secret_key.data()) != 0) {
        return std::nullopt;
    }

    return Keypair(pk, secret_key);
}

std::vector<uint8_t> Keypair::public_key_bytes() const {
    return {public_key_.begin(), public_key_.end()};
}

std::vector<uint8_t> Keypair::secret_key_bytes() const {
    return {secret_key_.begin(), secret_key_.end()};
}

} // namespace crypto
