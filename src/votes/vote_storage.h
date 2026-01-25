#pragma once

#include "ballot.h"
#include "../crypto/hash.h"

#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace votes {

/**
 * Hash function for crypto::Hash (for use in unordered containers)
 */
struct HashHasher {
    size_t operator()(const crypto::Hash& h) const {
        size_t result = 0;
        for (size_t i = 0; i < 8 && i < h.size(); ++i) {
            result ^= static_cast<size_t>(h[i]) << (i * 8);
        }
        return result;
    }
};

/**
 * Hash function for crypto::PublicKey
 */
struct PublicKeyHasher {
    size_t operator()(const crypto::PublicKey& pk) const {
        size_t result = 0;
        for (size_t i = 0; i < 8 && i < pk.size(); ++i) {
            result ^= static_cast<size_t>(pk[i]) << (i * 8);
        }
        return result;
    }
};

/**
 * Result of ballot validation
 */
enum class ValidationResult {
    Valid,
    InvalidSignature,
    InvalidElection,
    InvalidChoice,
    VoterNotEligible,
    ElectionNotActive,
    DuplicateVote,
    ExpiredTimestamp
};

/**
 * Convert ValidationResult to string
 */
const char* validation_result_to_string(ValidationResult result);

/**
 * Storage and validation of votes for elections
 * Thread-safe
 */
class VoteStorage {
public:
    /**
     * Register a new election
     * Returns false if election with same ID already exists
     */
    bool register_election(const Election& election);

    /**
     * Get election by ID
     */
    std::optional<Election> get_election(const ElectionId& id) const;

    /**
     * Get all registered elections
     */
    std::vector<Election> get_all_elections() const;

    /**
     * Submit a ballot
     * Validates and stores if valid
     * Returns validation result
     */
    ValidationResult submit_ballot(const Ballot& ballot);

    /**
     * Check if a voter has already voted in an election
     */
    bool has_voted(const ElectionId& election_id, 
                   const crypto::PublicKey& voter_key) const;

    /**
     * Get all ballots for an election
     */
    std::vector<Ballot> get_ballots(const ElectionId& election_id) const;

    /**
     * Get ballot count for an election
     */
    size_t get_ballot_count(const ElectionId& election_id) const;

    /**
     * Count votes for each choice in an election
     * Returns map: choice_id -> vote count
     */
    std::map<uint64_t, uint64_t> count_votes(const ElectionId& election_id) const;

    /**
     * Get detailed results for an election
     * Returns map: choice_name -> vote count
     */
    std::map<std::string, uint64_t> get_results(const ElectionId& election_id) const;

    /**
     * Validate a ballot without storing it
     */
    ValidationResult validate_ballot(const Ballot& ballot) const;

    /**
     * Get ballot by hash
     */
    std::optional<Ballot> get_ballot_by_hash(const crypto::Hash& hash) const;

    /**
     * Check if ballot already exists (by hash)
     */
    bool ballot_exists(const crypto::Hash& hash) const;

    /**
     * Set callback for new valid ballots (for P2P propagation)
     */
    void set_on_ballot_accepted(std::function<void(const Ballot&)> callback);

private:
    mutable std::mutex mutex_;
    
    // Elections indexed by ID
    std::map<ElectionId, Election> elections_;
    
    // Ballots indexed by election ID
    std::map<ElectionId, std::vector<Ballot>> ballots_;
    
    // Track who has voted (election_id -> set of voter public keys)
    std::map<ElectionId, std::unordered_set<crypto::PublicKey, PublicKeyHasher>> voters_;
    
    // Ballot hashes for deduplication
    std::unordered_set<crypto::Hash, HashHasher> ballot_hashes_;
    
    // Index: ballot hash -> ballot
    std::unordered_map<crypto::Hash, Ballot, HashHasher> ballot_index_;
    
    // Callback for new ballots
    std::function<void(const Ballot&)> on_ballot_accepted_;
};

/**
 * Builder for creating elections
 */
class ElectionBuilder {
public:
    ElectionBuilder& set_name(const std::string& name);
    ElectionBuilder& add_choice(const std::string& choice);
    ElectionBuilder& set_choices(const std::vector<std::string>& choices);
    ElectionBuilder& set_start_time(uint64_t timestamp);
    ElectionBuilder& set_end_time(uint64_t timestamp);
    ElectionBuilder& set_duration(uint64_t seconds);  // From now
    ElectionBuilder& add_eligible_voter(const crypto::PublicKey& voter_key);
    ElectionBuilder& set_eligible_voters(const std::vector<crypto::PublicKey>& voters);
    
    /**
     * Build the election
     * Returns nullopt if required fields are missing
     */
    std::optional<Election> build();

private:
    Election election_;
    bool has_name_ = false;
    bool has_choices_ = false;
    bool has_time_ = false;
};

} // namespace votes