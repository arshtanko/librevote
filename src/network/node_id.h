#pragma once

#include "../crypto/hash.h"
#include "../crypto/keypair.h"

#include <array>
#include <compare>
#include <cstdint>
#include <string>

namespace network {

// 256-bit node identifier (same as crypto::Hash)
constexpr size_t NODE_ID_SIZE = 32;

/**
 * Kademlia-style node identifier
 * 256-bit identifier used for XOR distance calculations
 */
class NodeId {
public:
    using Data = std::array<uint8_t, NODE_ID_SIZE>;

    /**
     * Create zero node ID
     */
    NodeId();

    /**
     * Create from raw bytes
     */
    explicit NodeId(const Data& data);

    /**
     * Create from public key (hash of public key)
     */
    static NodeId from_public_key(const crypto::PublicKey& public_key);

    /**
     * Generate random node ID
     */
    static NodeId random();

    /**
     * Create from hex string
     */
    static std::optional<NodeId> from_hex(const std::string& hex);

    /**
     * XOR distance between two node IDs
     */
    [[nodiscard]] NodeId distance(const NodeId& other) const;

    /**
     * Get the index of the first differing bit (0-255)
     * Returns 256 if IDs are equal
     * Used to determine which k-bucket a node belongs to
     */
    [[nodiscard]] size_t bucket_index(const NodeId& other) const;

    /**
     * Check if this ID is closer to target than other ID
     */
    [[nodiscard]] bool is_closer_to(const NodeId& target, const NodeId& other) const;

    /**
     * Convert to hex string
     */
    [[nodiscard]] std::string to_hex() const;

    /**
     * Get raw data
     */
    [[nodiscard]] const Data& data() const { return data_; }

    /**
     * Get byte at index
     */
    [[nodiscard]] uint8_t operator[](size_t index) const { return data_[index]; }

    /**
     * Comparison operators
     */
    bool operator==(const NodeId& other) const = default;
    auto operator<=>(const NodeId& other) const = default;

private:
    Data data_;
};

/**
 * Hash function for NodeId (for use in unordered containers)
 */
struct NodeIdHasher {
    size_t operator()(const NodeId& id) const;
};

/**
 * Information about a peer node
 */
struct PeerInfo {
    NodeId id;
    std::string address;  // IP:port or other address format
    uint16_t port;
    uint64_t last_seen;   // Unix timestamp

    bool operator==(const PeerInfo& other) const {
        return id == other.id;
    }
};

} // namespace network
