#pragma once

#include "node_id.h"

#include <chrono>
#include <list>
#include <mutex>
#include <optional>
#include <vector>

namespace network {

// Kademlia parameters
constexpr size_t K_BUCKET_SIZE = 20;      // Max nodes per bucket
constexpr size_t ALPHA = 3;                // Parallel lookups
constexpr size_t NUM_BUCKETS = 256;        // Number of k-buckets (256-bit IDs)

/**
 * A single k-bucket in the routing table
 * Stores up to K_BUCKET_SIZE peers ordered by last-seen time (LRU)
 */
class KBucket {
public:
    /**
     * Add or update a peer in the bucket
     * Returns true if peer was added/updated
     * Returns false if bucket is full and peer is new
     */
    bool add_or_update(const PeerInfo& peer);

    /**
     * Remove a peer from the bucket
     */
    void remove(const NodeId& id);

    /**
     * Get peer by ID
     */
    std::optional<PeerInfo> get(const NodeId& id) const;

    /**
     * Check if bucket contains peer
     */
    bool contains(const NodeId& id) const;

    /**
     * Check if bucket is full
     */
    bool is_full() const { return peers_.size() >= K_BUCKET_SIZE; }

    /**
     * Get number of peers
     */
    size_t size() const { return peers_.size(); }

    /**
     * Get all peers in the bucket
     */
    std::vector<PeerInfo> get_all() const;

    /**
     * Get the least recently seen peer (for replacement policy)
     */
    std::optional<PeerInfo> get_least_recent() const;

    /**
     * Mark a peer as seen (move to end of list)
     */
    void touch(const NodeId& id);

private:
    // List for efficient LRU operations
    // Front = least recently seen, Back = most recently seen
    std::list<PeerInfo> peers_;
};

/**
 * Kademlia routing table
 * Stores known peers organized by XOR distance from local node
 */
class RoutingTable {
public:
    /**
     * Create routing table for given local node ID
     */
    explicit RoutingTable(const NodeId& local_id);

    /**
     * Add or update a peer in the routing table
     * Returns true if peer was added/updated
     */
    bool add_or_update(const PeerInfo& peer);

    /**
     * Remove a peer from the routing table
     */
    void remove(const NodeId& id);

    /**
     * Get peer by ID
     */
    std::optional<PeerInfo> get(const NodeId& id) const;

    /**
     * Check if routing table contains peer
     */
    bool contains(const NodeId& id) const;

    /**
     * Find the K closest nodes to a target ID
     */
    std::vector<PeerInfo> find_closest(const NodeId& target, size_t count = K_BUCKET_SIZE) const;

    /**
     * Get all known peers
     */
    std::vector<PeerInfo> get_all_peers() const;

    /**
     * Get total number of known peers
     */
    size_t size() const;

    /**
     * Get the local node ID
     */
    const NodeId& local_id() const { return local_id_; }

    /**
     * Get bucket statistics (for debugging)
     */
    std::vector<size_t> get_bucket_sizes() const;

    /**
     * Mark a peer as recently seen
     */
    void touch(const NodeId& id);

    /**
     * Remove stale peers (not seen for given duration)
     */
    size_t remove_stale(std::chrono::seconds max_age);

private:
    NodeId local_id_;
    mutable std::mutex mutex_;
    std::array<KBucket, NUM_BUCKETS> buckets_;

    /**
     * Get bucket index for a given node ID
     */
    size_t get_bucket_index(const NodeId& id) const;
};

} // namespace network
