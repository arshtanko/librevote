#include "node_id.h"

#include <sodium.h>
#include <algorithm>
#include <bit>
#include <sstream>
#include <iomanip>

namespace network {

NodeId::NodeId() {
    data_.fill(0);
}

NodeId::NodeId(const Data& data) : data_(data) {}

NodeId NodeId::from_public_key(const crypto::PublicKey& public_key) {
    auto hash = crypto::blake2b(
        std::span<const uint8_t>(public_key.data(), public_key.size())
    );
    Data data;
    std::copy(hash.begin(), hash.end(), data.begin());
    return NodeId(data);
}

NodeId NodeId::random() {
    crypto::init();
    Data data;
    randombytes_buf(data.data(), data.size());
    return NodeId(data);
}

std::optional<NodeId> NodeId::from_hex(const std::string& hex) {
    auto bytes = crypto::from_hex(hex);
    if (bytes.size() != NODE_ID_SIZE) {
        return std::nullopt;
    }
    Data data;
    std::copy(bytes.begin(), bytes.end(), data.begin());
    return NodeId(data);
}

NodeId NodeId::distance(const NodeId& other) const {
    Data result;
    for (size_t i = 0; i < NODE_ID_SIZE; ++i) {
        result[i] = data_[i] ^ other.data_[i];
    }
    return NodeId(result);
}

size_t NodeId::bucket_index(const NodeId& other) const {
    auto dist = distance(other);
    
    // Find the first non-zero byte
    for (size_t i = 0; i < NODE_ID_SIZE; ++i) {
        if (dist.data_[i] != 0) {
            // Find the first set bit in this byte
            int leading_zeros = std::countl_zero(dist.data_[i]);
            return (NODE_ID_SIZE - 1 - i) * 8 + (7 - leading_zeros);
        }
    }
    
    // IDs are equal
    return NODE_ID_SIZE * 8;
}

bool NodeId::is_closer_to(const NodeId& target, const NodeId& other) const {
    auto my_dist = distance(target);
    auto other_dist = other.distance(target);
    return my_dist < other_dist;
}

std::string NodeId::to_hex() const {
    return crypto::to_hex(std::span<const uint8_t>(data_.data(), data_.size()));
}

size_t NodeIdHasher::operator()(const NodeId& id) const {
    size_t result = 0;
    const auto& data = id.data();
    for (size_t i = 0; i < 8 && i < data.size(); ++i) {
        result ^= static_cast<size_t>(data[i]) << (i * 8);
    }
    return result;
}

} // namespace network
