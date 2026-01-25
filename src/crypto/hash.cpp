#include "hash.h"
#include "keypair.h" // for init()

#include <sodium.h>
#include <stdexcept>

namespace crypto {

Hash sha256(std::span<const uint8_t> data) {
    if (!init()) {
        throw std::runtime_error("Failed to initialize libsodium");
    }

    Hash hash;
    crypto_hash_sha256(hash.data(), data.data(), data.size());
    return hash;
}

Hash sha256(const std::string& data) {
    return sha256(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(data.data()),
        data.size()
    ));
}

Hash blake2b(std::span<const uint8_t> data) {
    if (!init()) {
        throw std::runtime_error("Failed to initialize libsodium");
    }

    Hash hash;
    crypto_generichash(
        hash.data(), HASH_SIZE,
        data.data(), data.size(),
        nullptr, 0  // no key
    );
    return hash;
}

Hash blake2b(const std::string& data) {
    return blake2b(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(data.data()),
        data.size()
    ));
}

std::string to_hex(const Hash& hash) {
    return to_hex(std::span<const uint8_t>(hash.data(), hash.size()));
}

std::string to_hex(std::span<const uint8_t> data) {
    if (!init()) {
        throw std::runtime_error("Failed to initialize libsodium");
    }

    std::string hex(data.size() * 2 + 1, '\0');
    sodium_bin2hex(hex.data(), hex.size(), data.data(), data.size());
    hex.pop_back(); // remove null terminator
    return hex;
}

std::vector<uint8_t> from_hex(const std::string& hex) {
    if (!init()) {
        return {};
    }

    if (hex.size() % 2 != 0) {
        return {};
    }

    std::vector<uint8_t> bytes(hex.size() / 2);
    size_t bin_len;

    if (sodium_hex2bin(
            bytes.data(), bytes.size(),
            hex.c_str(), hex.size(),
            nullptr, &bin_len, nullptr) != 0) {
        return {};
    }

    bytes.resize(bin_len);
    return bytes;
}

} // namespace crypto
