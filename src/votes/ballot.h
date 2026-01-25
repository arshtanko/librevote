#pragma once

#include <cinttypes>
#include <vector>

struct Ballot {
    uint64_t voter_id;
    uint64_t choice_id;
    uint64_t timestamp;
    std::vector<uint8_t> signature;
};