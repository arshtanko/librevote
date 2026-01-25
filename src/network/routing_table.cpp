#include "routing_table.h"

#include <algorithm>

namespace network {

// ============================================================================
// KBucket implementation
// ============================================================================

bool KBucket::add_or_update(const PeerInfo& peer) {
    // Check if peer already exists
    auto it = std::find_if(peers_.begin(), peers_.end(),
        [&peer](const PeerInfo& p) { return p.id == peer.id; });

    if (it != peers_.end()) {
        // Update existing peer and move to back (most recently seen)
        *it = peer;
        peers_.splice(peers_.end(), peers_, it);
        return true;
    }

    // New peer
    if (peers_.size() < K_BUCKET_SIZE) {
        peers_.push_back(peer);
        return true;
    }

    // Bucket is full
    return false;
}

void KBucket::remove(const NodeId& id) {
    peers_.remove_if([&id](const PeerInfo& p) { return p.id == id; });
}

std::optional<PeerInfo> KBucket::get(const NodeId& id) const {
    auto it = std::find_if(peers_.begin(), peers_.end(),
        [&id](const PeerInfo& p) { return p.id == id; });

    if (it != peers_.end()) {
        return *it;
    }
    return std::nullopt;
}

bool KBucket::contains(const NodeId& id) const {
    return get(id).has_value();
}

std::vector<PeerInfo> KBucket::get_all() const {
    return {peers_.begin(), peers_.end()};
}

std::optional<PeerInfo> KBucket::get_least_recent() const {
    if (peers_.empty()) {
        return std::nullopt;
    }
    return peers_.front();
}

void KBucket::touch(const NodeId& id) {
    auto it = std::find_if(peers_.begin(), peers_.end(),
        [&id](const PeerInfo& p) { return p.id == id; });

    if (it != peers_.end()) {
        // Update last seen time
        auto now = std::chrono::system_clock::now();
        it->last_seen = std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()).count();
        // Move to back (most recently seen)
        peers_.splice(peers_.end(), peers_, it);
    }
}

// ============================================================================
// RoutingTable implementation
// ============================================================================

RoutingTable::RoutingTable(const NodeId& local_id) : local_id_(local_id) {}

size_t RoutingTable::get_bucket_index(const NodeId& id) const {
    size_t index = local_id_.bucket_index(id);
    // Clamp to valid range (255 for equal IDs shouldn't happen in practice)
    return std::min(index, NUM_BUCKETS - 1);
}

bool RoutingTable::add_or_update(const PeerInfo& peer) {
    // Don't add ourselves
    if (peer.id == local_id_) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    size_t bucket_idx = get_bucket_index(peer.id);
    return buckets_[bucket_idx].add_or_update(peer);
}

void RoutingTable::remove(const NodeId& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t bucket_idx = get_bucket_index(id);
    buckets_[bucket_idx].remove(id);
}

std::optional<PeerInfo> RoutingTable::get(const NodeId& id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t bucket_idx = get_bucket_index(id);
    return buckets_[bucket_idx].get(id);
}

bool RoutingTable::contains(const NodeId& id) const {
    return get(id).has_value();
}

std::vector<PeerInfo> RoutingTable::find_closest(const NodeId& target, size_t count) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<PeerInfo> candidates;

    // Collect all peers
    for (const auto& bucket : buckets_) {
        auto peers = bucket.get_all();
        candidates.insert(candidates.end(), peers.begin(), peers.end());
    }

    // Sort by XOR distance to target
    std::sort(candidates.begin(), candidates.end(),
        [&target](const PeerInfo& a, const PeerInfo& b) {
            auto dist_a = a.id.distance(target);
            auto dist_b = b.id.distance(target);
            return dist_a < dist_b;  // Use operator< for strict weak ordering
        });

    // Return up to count closest
    if (candidates.size() > count) {
        candidates.resize(count);
    }

    return candidates;
}

std::vector<PeerInfo> RoutingTable::get_all_peers() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<PeerInfo> all_peers;
    for (const auto& bucket : buckets_) {
        auto peers = bucket.get_all();
        all_peers.insert(all_peers.end(), peers.begin(), peers.end());
    }

    return all_peers;
}

size_t RoutingTable::size() const {
    std::lock_guard<std::mutex> lock(mutex_);

    size_t total = 0;
    for (const auto& bucket : buckets_) {
        total += bucket.size();
    }
    return total;
}

std::vector<size_t> RoutingTable::get_bucket_sizes() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<size_t> sizes;
    sizes.reserve(NUM_BUCKETS);
    for (const auto& bucket : buckets_) {
        sizes.push_back(bucket.size());
    }
    return sizes;
}

void RoutingTable::touch(const NodeId& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t bucket_idx = get_bucket_index(id);
    buckets_[bucket_idx].touch(id);
}

size_t RoutingTable::remove_stale(std::chrono::seconds max_age) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto now = std::chrono::system_clock::now();
    uint64_t threshold = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count() - max_age.count();

    size_t removed = 0;

    for (auto& bucket : buckets_) {
        auto peers = bucket.get_all();
        for (const auto& peer : peers) {
            if (peer.last_seen < threshold) {
                bucket.remove(peer.id);
                ++removed;
            }
        }
    }

    return removed;
}

} // namespace network
