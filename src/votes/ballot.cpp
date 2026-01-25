#include "ballot.h"

#include <algorithm>
#include <chrono>
#include <cstring>

namespace votes {

namespace {

void write_u64(std::vector<uint8_t>& out, uint64_t value) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<uint8_t>(value >> (i * 8)));
    }
}

uint64_t read_u64(const uint8_t* data) {
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value |= static_cast<uint64_t>(data[i]) << (i * 8);
    }
    return value;
}

void write_bytes(std::vector<uint8_t>& out, const uint8_t* data, size_t len) {
    out.insert(out.end(), data, data + len);
}

void write_string(std::vector<uint8_t>& out, const std::string& str) {
    write_u64(out, str.size());
    out.insert(out.end(), str.begin(), str.end());
}

std::string read_string(const uint8_t*& data, size_t& remaining) {
    if (remaining < 8) return "";
    uint64_t len = read_u64(data);
    data += 8;
    remaining -= 8;
    if (remaining < len) return "";
    std::string result(reinterpret_cast<const char*>(data), len);
    data += len;
    remaining -= len;
    return result;
}

}


Ballot::Ballot(const ElectionId& election_id,
               uint64_t choice_id,
               const crypto::PublicKey& voter_public_key)
    : election_id_(election_id)
    , choice_id_(choice_id)
    , voter_public_key_(voter_public_key)
    , is_signed_(false) {
    // Set timestamp to current time
    auto now = std::chrono::system_clock::now();
    timestamp_ = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
    
    signature_.fill(0);
}

std::vector<uint8_t> Ballot::signing_data() const {
    std::vector<uint8_t> data;
    data.reserve(32 + 8 + 8 + 32);  // election_id + choice + timestamp + pubkey
    
    // Election ID
    write_bytes(data, election_id_.data(), election_id_.size());
    
    // Choice ID
    write_u64(data, choice_id_);
    
    // Timestamp
    write_u64(data, timestamp_);
    
    // Voter public key
    write_bytes(data, voter_public_key_.data(), voter_public_key_.size());
    
    return data;
}

bool Ballot::sign(const crypto::Keypair& keypair) {
    // Verify the keypair matches the voter public key
    if (keypair.public_key() != voter_public_key_) {
        return false;
    }
    
    auto data = signing_data();
    signature_ = crypto::sign(data, keypair);
    is_signed_ = true;
    return true;
}

bool Ballot::verify() const {
    if (!is_signed_) {
        return false;
    }
    
    auto data = signing_data();
    return crypto::verify(data, signature_, voter_public_key_);
}

std::vector<uint8_t> Ballot::to_bytes() const {
    std::vector<uint8_t> data;
    data.reserve(32 + 8 + 8 + 32 + 64 + 1);  // All fields
    
    // Election ID (32 bytes)
    write_bytes(data, election_id_.data(), election_id_.size());
    
    // Choice ID (8 bytes)
    write_u64(data, choice_id_);
    
    // Timestamp (8 bytes)
    write_u64(data, timestamp_);
    
    // Voter public key (32 bytes)
    write_bytes(data, voter_public_key_.data(), voter_public_key_.size());
    
    // Signature (64 bytes)
    write_bytes(data, signature_.data(), signature_.size());
    
    // Is signed flag (1 byte)
    data.push_back(is_signed_ ? 1 : 0);
    
    return data;
}

std::optional<Ballot> Ballot::from_bytes(const std::vector<uint8_t>& data) {
    constexpr size_t EXPECTED_SIZE = 32 + 8 + 8 + 32 + 64 + 1;
    if (data.size() != EXPECTED_SIZE) {
        return std::nullopt;
    }
    
    Ballot ballot;
    const uint8_t* ptr = data.data();
    
    // Election ID
    std::copy(ptr, ptr + 32, ballot.election_id_.begin());
    ptr += 32;
    
    // Choice ID
    ballot.choice_id_ = read_u64(ptr);
    ptr += 8;
    
    // Timestamp
    ballot.timestamp_ = read_u64(ptr);
    ptr += 8;
    
    // Voter public key
    std::copy(ptr, ptr + 32, ballot.voter_public_key_.begin());
    ptr += 32;
    
    // Signature
    std::copy(ptr, ptr + 64, ballot.signature_.begin());
    ptr += 64;
    
    // Is signed flag
    ballot.is_signed_ = (*ptr != 0);
    
    return ballot;
}

crypto::Hash Ballot::hash() const {
    auto data = to_bytes();
    return crypto::blake2b(data);
}


void Election::compute_id() {
    auto data = to_bytes();
    auto hash = crypto::blake2b(data);
    std::copy(hash.begin(), hash.end(), id.begin());
}

bool Election::is_active() const {
    auto now = std::chrono::system_clock::now();
    uint64_t current_time = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
    return current_time >= start_time && current_time <= end_time;
}

bool Election::is_eligible(const crypto::PublicKey& voter_key) const {
    return std::find(eligible_voters.begin(), eligible_voters.end(), voter_key) 
           != eligible_voters.end();
}

bool Election::is_valid_choice(uint64_t choice_id) const {
    return choice_id < choices.size();
}

std::vector<uint8_t> Election::to_bytes() const {
    std::vector<uint8_t> data;
    
    // Name
    write_string(data, name);
    
    // Number of choices
    write_u64(data, choices.size());
    
    // Choices
    for (const auto& choice : choices) {
        write_string(data, choice);
    }
    
    // Start time
    write_u64(data, start_time);
    
    // End time
    write_u64(data, end_time);
    
    // Number of eligible voters
    write_u64(data, eligible_voters.size());
    
    // Eligible voter public keys
    for (const auto& voter : eligible_voters) {
        write_bytes(data, voter.data(), voter.size());
    }
    
    return data;
}

std::optional<Election> Election::from_bytes(const std::vector<uint8_t>& data) {
    if (data.size() < 8) {
        return std::nullopt;
    }
    
    Election election;
    const uint8_t* ptr = data.data();
    size_t remaining = data.size();
    
    // Name
    election.name = read_string(ptr, remaining);
    
    // Number of choices
    if (remaining < 8) return std::nullopt;
    uint64_t num_choices = read_u64(ptr);
    ptr += 8;
    remaining -= 8;
    
    // Choices
    for (uint64_t i = 0; i < num_choices; ++i) {
        election.choices.push_back(read_string(ptr, remaining));
    }
    
    // Start time
    if (remaining < 8) return std::nullopt;
    election.start_time = read_u64(ptr);
    ptr += 8;
    remaining -= 8;
    
    // End time
    if (remaining < 8) return std::nullopt;
    election.end_time = read_u64(ptr);
    ptr += 8;
    remaining -= 8;
    
    // Number of eligible voters
    if (remaining < 8) return std::nullopt;
    uint64_t num_voters = read_u64(ptr);
    ptr += 8;
    remaining -= 8;
    
    // Eligible voter public keys
    for (uint64_t i = 0; i < num_voters; ++i) {
        if (remaining < 32) return std::nullopt;
        crypto::PublicKey voter;
        std::copy(ptr, ptr + 32, voter.begin());
        election.eligible_voters.push_back(voter);
        ptr += 32;
        remaining -= 32;
    }
    
    // Compute ID
    election.compute_id();
    
    return election;
}

} // namespace votes