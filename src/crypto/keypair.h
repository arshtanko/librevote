#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

namespace crypto {

// Ed25519 key sizes
constexpr size_t PUBLIC_KEY_SIZE = 32;
constexpr size_t SECRET_KEY_SIZE = 64;
constexpr size_t SEED_SIZE = 32;

using PublicKey = std::array<uint8_t, PUBLIC_KEY_SIZE>;
using SecretKey = std::array<uint8_t, SECRET_KEY_SIZE>;
using Seed = std::array<uint8_t, SEED_SIZE>;

/**
 * Ed25519 key pair for signing and verification
 */
class Keypair {
public:
    /**
     * Generate a new random key pair
     */
    static Keypair generate();

    /**
     * Create key pair from seed (deterministic)
     */
    static Keypair from_seed(const Seed& seed);

    /**
     * Load key pair from raw bytes
     */
    static std::optional<Keypair> from_bytes(const SecretKey& secret_key);

    /**
     * Get public key
     */
    [[nodiscard]] const PublicKey& public_key() const { return public_key_; }

    /**
     * Get secret key
     */
    [[nodiscard]] const SecretKey& secret_key() const { return secret_key_; }

    /**
     * Export public key as vector (for serialization)
     */
    [[nodiscard]] std::vector<uint8_t> public_key_bytes() const;

    /**
     * Export secret key as vector (for serialization)
     */
    [[nodiscard]] std::vector<uint8_t> secret_key_bytes() const;

private:
    Keypair(PublicKey public_key, SecretKey secret_key);

    PublicKey public_key_;
    SecretKey secret_key_;
};

/**
 * Initialize libsodium (must be called once at program start)
 * Returns true on success
 */
bool init();

} // namespace crypto
