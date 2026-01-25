#pragma once

#include "keypair.h"

#include <cstdint>
#include <span>
#include <vector>

namespace crypto {

// Ed25519 signature size
constexpr size_t SIGNATURE_SIZE = 64;

using Signature = std::array<uint8_t, SIGNATURE_SIZE>;

/**
 * Sign a message using Ed25519
 * 
 * @param message Data to sign
 * @param keypair Key pair containing secret key for signing
 * @return Signature bytes
 */
Signature sign(std::span<const uint8_t> message, const Keypair& keypair);

/**
 * Verify an Ed25519 signature
 * 
 * @param message Original message
 * @param signature Signature to verify
 * @param public_key Public key of the signer
 * @return true if signature is valid
 */
bool verify(std::span<const uint8_t> message,
            const Signature& signature,
            const PublicKey& public_key);

/**
 * Verify signature with public key as span (convenience overload)
 */
bool verify(std::span<const uint8_t> message,
            std::span<const uint8_t> signature,
            std::span<const uint8_t> public_key);

} // namespace crypto
