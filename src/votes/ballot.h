#pragma once

#include "../crypto/keypair.h"
#include "../crypto/signature.h"
#include "../crypto/hash.h"

#include <array>
#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

namespace votes {

/**
 * Unique identifier for an election
 */
using ElectionId = std::array<uint8_t, 32>;

/**
 * A ballot representing a single vote in an election
 */
class Ballot {
public:
    /**
     * Create a new unsigned ballot
     */
    Ballot(const ElectionId& election_id,
           uint64_t choice_id,
           const crypto::PublicKey& voter_public_key);

    /**
     * Deserialize ballot from bytes
     */
    static std::optional<Ballot> from_bytes(const std::vector<uint8_t>& data);

    /**
     * Sign the ballot with voter's secret key
     * Returns true if signing succeeded
     */
    bool sign(const crypto::Keypair& keypair);

    /**
     * Verify the ballot's signature
     * Returns true if signature is valid
     */
    [[nodiscard]] bool verify() const;

    /**
     * Check if ballot is signed
     */
    [[nodiscard]] bool is_signed() const { return is_signed_; }

    /**
     * Serialize ballot to bytes for network transmission
     */
    [[nodiscard]] std::vector<uint8_t> to_bytes() const;

    /**
     * Get hash of ballot (for deduplication and indexing)
     */
    [[nodiscard]] crypto::Hash hash() const;

    /**
     * Get the data that is signed (without signature)
     */
    [[nodiscard]] std::vector<uint8_t> signing_data() const;

    // Getters
    [[nodiscard]] const ElectionId& election_id() const { return election_id_; }
    [[nodiscard]] uint64_t choice_id() const { return choice_id_; }
    [[nodiscard]] uint64_t timestamp() const { return timestamp_; }
    [[nodiscard]] const crypto::PublicKey& voter_public_key() const { return voter_public_key_; }
    [[nodiscard]] const crypto::Signature& signature() const { return signature_; }

private:
    Ballot() = default;  // For deserialization

    ElectionId election_id_;
    uint64_t choice_id_;
    uint64_t timestamp_;
    crypto::PublicKey voter_public_key_;
    crypto::Signature signature_;
    bool is_signed_ = false;
};

/**
 * Election metadata
 */
struct Election {
    ElectionId id;                          // Unique election ID (hash of params)
    std::string name;                       // Human-readable name
    std::vector<std::string> choices;       // List of voting options
    uint64_t start_time;                    // Unix timestamp
    uint64_t end_time;                      // Unix timestamp
    std::vector<crypto::PublicKey> eligible_voters;  // Public keys of eligible voters

    /**
     * Generate election ID from parameters
     */
    void compute_id();

    /**
     * Check if election is currently active
     */
    [[nodiscard]] bool is_active() const;

    /**
     * Check if a voter is eligible
     */
    [[nodiscard]] bool is_eligible(const crypto::PublicKey& voter_key) const;

    /**
     * Check if choice_id is valid
     */
    [[nodiscard]] bool is_valid_choice(uint64_t choice_id) const;

    /**
     * Serialize to bytes
     */
    [[nodiscard]] std::vector<uint8_t> to_bytes() const;

    /**
     * Deserialize from bytes
     */
    static std::optional<Election> from_bytes(const std::vector<uint8_t>& data);
};

} // namespace votes