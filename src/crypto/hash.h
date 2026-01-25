#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace crypto {

// SHA-256 hash size
constexpr size_t HASH_SIZE = 32;

using Hash = std::array<uint8_t, HASH_SIZE>;

/**
 * Compute SHA-256 hash of data
 * 
 * @param data Input data to hash
 * @return 32-byte hash
 */
Hash sha256(std::span<const uint8_t> data);

/**
 * Compute SHA-256 hash of string
 */
Hash sha256(const std::string& data);

/**
 * Compute generic hash using BLAKE2b (faster than SHA-256)
 * 
 * @param data Input data to hash
 * @return 32-byte hash
 */
Hash blake2b(std::span<const uint8_t> data);

/**
 * Compute BLAKE2b hash of string
 */
Hash blake2b(const std::string& data);

/**
 * Convert hash to hexadecimal string
 */
std::string to_hex(const Hash& hash);

/**
 * Convert any byte array to hexadecimal string
 */
std::string to_hex(std::span<const uint8_t> data);

/**
 * Convert hexadecimal string to bytes
 * Returns empty vector on invalid input
 */
std::vector<uint8_t> from_hex(const std::string& hex);

} // namespace crypto
