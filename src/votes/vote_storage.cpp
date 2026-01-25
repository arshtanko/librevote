#include "vote_storage.h"

#include <chrono>

namespace votes {

const char* validation_result_to_string(ValidationResult result) {
    switch (result) {
        case ValidationResult::Valid: return "Valid";
        case ValidationResult::InvalidSignature: return "Invalid signature";
        case ValidationResult::InvalidElection: return "Invalid election";
        case ValidationResult::InvalidChoice: return "Invalid choice";
        case ValidationResult::VoterNotEligible: return "Voter not eligible";
        case ValidationResult::ElectionNotActive: return "Election not active";
        case ValidationResult::DuplicateVote: return "Duplicate vote";
        case ValidationResult::ExpiredTimestamp: return "Expired timestamp";
        default: return "Unknown error";
    }
}

bool VoteStorage::register_election(const Election& election) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (elections_.count(election.id) > 0) {
        return false;
    }
    
    elections_[election.id] = election;
    ballots_[election.id] = {};
    voters_[election.id] = {};
    return true;
}

std::optional<Election> VoteStorage::get_election(const ElectionId& id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = elections_.find(id);
    if (it == elections_.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::vector<Election> VoteStorage::get_all_elections() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<Election> result;
    result.reserve(elections_.size());
    for (const auto& [id, election] : elections_) {
        result.push_back(election);
    }
    return result;
}

ValidationResult VoteStorage::validate_ballot(const Ballot& ballot) const {
    // Check signature
    if (!ballot.verify()) {
        return ValidationResult::InvalidSignature;
    }
    
    // Check election exists
    auto election_it = elections_.find(ballot.election_id());
    if (election_it == elections_.end()) {
        return ValidationResult::InvalidElection;
    }
    
    const Election& election = election_it->second;
    
    // Check choice is valid
    if (!election.is_valid_choice(ballot.choice_id())) {
        return ValidationResult::InvalidChoice;
    }
    
    // Check voter eligibility
    if (!election.is_eligible(ballot.voter_public_key())) {
        return ValidationResult::VoterNotEligible;
    }
    
    // Check election is active
    if (!election.is_active()) {
        return ValidationResult::ElectionNotActive;
    }
    
    // Check ballot timestamp is within election period
    if (ballot.timestamp() < election.start_time || 
        ballot.timestamp() > election.end_time) {
        return ValidationResult::ExpiredTimestamp;
    }
    
    // Check for duplicate vote
    auto voters_it = voters_.find(ballot.election_id());
    if (voters_it != voters_.end() && 
        voters_it->second.count(ballot.voter_public_key()) > 0) {
        return ValidationResult::DuplicateVote;
    }
    
    // Check for duplicate ballot (by hash)
    auto hash = ballot.hash();
    if (ballot_hashes_.count(hash) > 0) {
        return ValidationResult::DuplicateVote;
    }
    
    return ValidationResult::Valid;
}

ValidationResult VoteStorage::submit_ballot(const Ballot& ballot) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Validate
    auto result = validate_ballot(ballot);
    if (result != ValidationResult::Valid) {
        return result;
    }
    
    // Store
    auto hash = ballot.hash();
    ballots_[ballot.election_id()].push_back(ballot);
    voters_[ballot.election_id()].insert(ballot.voter_public_key());
    ballot_hashes_.insert(hash);
    ballot_index_.emplace(hash, ballot);
    
    // Notify callback
    if (on_ballot_accepted_) {
        on_ballot_accepted_(ballot);
    }
    
    return ValidationResult::Valid;
}

bool VoteStorage::has_voted(const ElectionId& election_id, 
                            const crypto::PublicKey& voter_key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = voters_.find(election_id);
    if (it == voters_.end()) {
        return false;
    }
    return it->second.count(voter_key) > 0;
}

std::vector<Ballot> VoteStorage::get_ballots(const ElectionId& election_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = ballots_.find(election_id);
    if (it == ballots_.end()) {
        return {};
    }
    return it->second;
}

size_t VoteStorage::get_ballot_count(const ElectionId& election_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = ballots_.find(election_id);
    if (it == ballots_.end()) {
        return 0;
    }
    return it->second.size();
}

std::map<uint64_t, uint64_t> VoteStorage::count_votes(const ElectionId& election_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::map<uint64_t, uint64_t> counts;
    
    auto it = ballots_.find(election_id);
    if (it == ballots_.end()) {
        return counts;
    }
    
    // Initialize counts for all choices
    auto election_it = elections_.find(election_id);
    if (election_it != elections_.end()) {
        for (uint64_t i = 0; i < election_it->second.choices.size(); ++i) {
            counts[i] = 0;
        }
    }
    
    // Count votes
    for (const auto& ballot : it->second) {
        counts[ballot.choice_id()]++;
    }
    
    return counts;
}

std::map<std::string, uint64_t> VoteStorage::get_results(const ElectionId& election_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::map<std::string, uint64_t> results;
    
    auto election_it = elections_.find(election_id);
    if (election_it == elections_.end()) {
        return results;
    }
    
    const Election& election = election_it->second;
    
    // Initialize results for all choices
    for (const auto& choice : election.choices) {
        results[choice] = 0;
    }
    
    // Count votes
    auto ballots_it = ballots_.find(election_id);
    if (ballots_it != ballots_.end()) {
        for (const auto& ballot : ballots_it->second) {
            if (ballot.choice_id() < election.choices.size()) {
                results[election.choices[ballot.choice_id()]]++;
            }
        }
    }
    
    return results;
}

std::optional<Ballot> VoteStorage::get_ballot_by_hash(const crypto::Hash& hash) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = ballot_index_.find(hash);
    if (it == ballot_index_.end()) {
        return std::nullopt;
    }
    return it->second;
}

bool VoteStorage::ballot_exists(const crypto::Hash& hash) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return ballot_hashes_.count(hash) > 0;
}

void VoteStorage::set_on_ballot_accepted(std::function<void(const Ballot&)> callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    on_ballot_accepted_ = std::move(callback);
}

ElectionBuilder& ElectionBuilder::set_name(const std::string& name) {
    election_.name = name;
    has_name_ = true;
    return *this;
}

ElectionBuilder& ElectionBuilder::add_choice(const std::string& choice) {
    election_.choices.push_back(choice);
    has_choices_ = true;
    return *this;
}

ElectionBuilder& ElectionBuilder::set_choices(const std::vector<std::string>& choices) {
    election_.choices = choices;
    has_choices_ = !choices.empty();
    return *this;
}

ElectionBuilder& ElectionBuilder::set_start_time(uint64_t timestamp) {
    election_.start_time = timestamp;
    has_time_ = (election_.end_time > 0);
    return *this;
}

ElectionBuilder& ElectionBuilder::set_end_time(uint64_t timestamp) {
    election_.end_time = timestamp;
    has_time_ = (election_.start_time > 0 || election_.start_time == 0);
    return *this;
}

ElectionBuilder& ElectionBuilder::set_duration(uint64_t seconds) {
    auto now = std::chrono::system_clock::now();
    election_.start_time = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
    election_.end_time = election_.start_time + seconds;
    has_time_ = true;
    return *this;
}

ElectionBuilder& ElectionBuilder::add_eligible_voter(const crypto::PublicKey& voter_key) {
    election_.eligible_voters.push_back(voter_key);
    return *this;
}

ElectionBuilder& ElectionBuilder::set_eligible_voters(const std::vector<crypto::PublicKey>& voters) {
    election_.eligible_voters = voters;
    return *this;
}

std::optional<Election> ElectionBuilder::build() {
    if (!has_name_ || !has_choices_ || !has_time_) {
        return std::nullopt;
    }
    
    if (election_.end_time <= election_.start_time) {
        return std::nullopt;
    }
    
    election_.compute_id();
    return election_;
}

}