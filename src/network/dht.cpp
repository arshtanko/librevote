#include "dht.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <set>

namespace network {

namespace {

void write_u8(std::vector<uint8_t>& out, uint8_t value) {
    out.push_back(value);
}

void write_u16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
}

void write_u64(std::vector<uint8_t>& out, uint64_t value) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
    }
}

void write_bytes(std::vector<uint8_t>& out, const uint8_t* data, size_t len) {
    out.insert(out.end(), data, data + len);
}

void write_vec(std::vector<uint8_t>& out, const std::vector<uint8_t>& vec) {
    write_u64(out, vec.size());
    out.insert(out.end(), vec.begin(), vec.end());
}

void write_string(std::vector<uint8_t>& out, const std::string& str) {
    write_u64(out, str.size());
    out.insert(out.end(), str.begin(), str.end());
}

uint8_t read_u8(const uint8_t*& ptr, size_t& remaining) {
    if (remaining < 1) return 0;
    remaining -= 1;
    return *ptr++;
}

uint16_t read_u16(const uint8_t*& ptr, size_t& remaining) {
    if (remaining < 2) return 0;
    uint16_t value = ptr[0] | (static_cast<uint16_t>(ptr[1]) << 8);
    ptr += 2;
    remaining -= 2;
    return value;
}

uint64_t read_u64(const uint8_t*& ptr, size_t& remaining) {
    if (remaining < 8) return 0;
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value |= static_cast<uint64_t>(ptr[i]) << (i * 8);
    }
    ptr += 8;
    remaining -= 8;
    return value;
}

std::vector<uint8_t> read_vec(const uint8_t*& ptr, size_t& remaining) {
    uint64_t len = read_u64(ptr, remaining);
    if (remaining < len) return {};
    std::vector<uint8_t> vec(ptr, ptr + len);
    ptr += len;
    remaining -= len;
    return vec;
}

std::string read_string(const uint8_t*& ptr, size_t& remaining) {
    uint64_t len = read_u64(ptr, remaining);
    if (remaining < len) return "";
    std::string str(reinterpret_cast<const char*>(ptr), len);
    ptr += len;
    remaining -= len;
    return str;
}

} // anonymous namespace

std::vector<uint8_t> DHTMessage::serialize() const {
    std::vector<uint8_t> data;
    
    write_u8(data, static_cast<uint8_t>(type));
    write_bytes(data, sender_id.data().data(), NODE_ID_SIZE);
    write_u64(data, transaction_id);
    write_bytes(data, target_id.data().data(), NODE_ID_SIZE);
    
    // Peers
    write_u64(data, peers.size());
    for (const auto& peer : peers) {
        write_bytes(data, peer.id.data().data(), NODE_ID_SIZE);
        write_string(data, peer.address);
        write_u16(data, peer.port);
        write_u64(data, peer.last_seen);
    }
    
    // Key-value
    write_vec(data, key);
    write_vec(data, value);
    
    // Sender info
    write_string(data, sender_address);
    write_u16(data, sender_port);
    
    return data;
}

std::optional<DHTMessage> DHTMessage::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < 1 + NODE_ID_SIZE + 8 + NODE_ID_SIZE) {
        return std::nullopt;
    }
    
    DHTMessage msg;
    const uint8_t* ptr = data.data();
    size_t remaining = data.size();
    
    msg.type = static_cast<MessageType>(read_u8(ptr, remaining));
    
    NodeId::Data sender_data;
    std::copy(ptr, ptr + NODE_ID_SIZE, sender_data.begin());
    ptr += NODE_ID_SIZE;
    remaining -= NODE_ID_SIZE;
    msg.sender_id = NodeId(sender_data);
    
    msg.transaction_id = read_u64(ptr, remaining);
    
    NodeId::Data target_data;
    if (remaining < NODE_ID_SIZE) return std::nullopt;
    std::copy(ptr, ptr + NODE_ID_SIZE, target_data.begin());
    ptr += NODE_ID_SIZE;
    remaining -= NODE_ID_SIZE;
    msg.target_id = NodeId(target_data);
    
    // Peers
    uint64_t peer_count = read_u64(ptr, remaining);
    for (uint64_t i = 0; i < peer_count; ++i) {
        PeerInfo peer;
        if (remaining < NODE_ID_SIZE) return std::nullopt;
        NodeId::Data peer_data;
        std::copy(ptr, ptr + NODE_ID_SIZE, peer_data.begin());
        ptr += NODE_ID_SIZE;
        remaining -= NODE_ID_SIZE;
        peer.id = NodeId(peer_data);
        peer.address = read_string(ptr, remaining);
        peer.port = read_u16(ptr, remaining);
        peer.last_seen = read_u64(ptr, remaining);
        msg.peers.push_back(peer);
    }
    
    // Key-value
    msg.key = read_vec(ptr, remaining);
    msg.value = read_vec(ptr, remaining);
    
    // Sender info
    msg.sender_address = read_string(ptr, remaining);
    msg.sender_port = read_u16(ptr, remaining);
    
    return msg;
}

DHT::DHT(const crypto::Keypair& keypair)
    : local_id_(NodeId::from_public_key(keypair.public_key()))
    , keypair_(keypair)
    , routing_table_(local_id_) {}

PeerInfo DHT::local_peer_info() const {
    return PeerInfo{
        .id = local_id_,
        .address = local_address_,
        .port = local_port_,
        .last_seen = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count())
    };
}

void DHT::set_send_callback(SendCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    send_callback_ = std::move(callback);
}

void DHT::set_local_address(const std::string& address, uint16_t port) {
    std::lock_guard<std::mutex> lock(mutex_);
    local_address_ = address;
    local_port_ = port;
}

void DHT::set_value_callback(ValueCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    value_callback_ = std::move(callback);
}

uint64_t DHT::generate_transaction_id() {
    return next_transaction_id_++;
}

bool DHT::send_message(const PeerInfo& peer, const DHTMessage& message) {
    SendCallback callback;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        callback = send_callback_;
    }
    
    if (!callback) {
        return false;
    }
    
    return callback(peer, message.serialize());
}

std::optional<DHTMessage> DHT::send_and_wait(const PeerInfo& peer, DHTMessage message,
                                              std::chrono::milliseconds timeout) {
    std::promise<DHTMessage> promise;
    auto future = promise.get_future();
    
    {
        std::lock_guard<std::mutex> lock(mutex_);
        pending_requests_[message.transaction_id] = std::move(promise);
    }
    
    if (!send_message(peer, message)) {
        std::lock_guard<std::mutex> lock(mutex_);
        pending_requests_.erase(message.transaction_id);
        return std::nullopt;
    }
    
    if (future.wait_for(timeout) == std::future_status::timeout) {
        std::lock_guard<std::mutex> lock(mutex_);
        pending_requests_.erase(message.transaction_id);
        return std::nullopt;
    }
    
    return future.get();
}

void DHT::bootstrap(const std::vector<PeerInfo>& bootstrap_nodes) {
    // Add bootstrap nodes to routing table
    for (const auto& node : bootstrap_nodes) {
        routing_table_.add_or_update(node);
    }
    
    // Find nodes close to ourselves to populate routing table
    find_node(local_id_);
}

void DHT::update_sender(const DHTMessage& message) {
    if (!message.sender_address.empty() && message.sender_port != 0) {
        auto now = std::chrono::system_clock::now();
        PeerInfo peer{
            .id = message.sender_id,
            .address = message.sender_address,
            .port = message.sender_port,
            .last_seen = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    now.time_since_epoch()).count())
        };
        routing_table_.add_or_update(peer);
    }
}

void DHT::handle_message(const DHTMessage& message) {
    // Always update routing table with sender info
    update_sender(message);
    
    // Check if this is a response to a pending request
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = pending_requests_.find(message.transaction_id);
        if (it != pending_requests_.end()) {
            it->second.set_value(message);
            pending_requests_.erase(it);
            return;
        }
    }
    
    // Handle based on message type
    switch (message.type) {
        case MessageType::PING:
            handle_ping(message);
            break;
        case MessageType::FIND_NODE:
            handle_find_node(message);
            break;
        case MessageType::FIND_NODE_RESPONSE:
            handle_find_node_response(message);
            break;
        case MessageType::STORE:
            handle_store(message);
            break;
        case MessageType::FIND_VALUE:
            handle_find_value(message);
            break;
        case MessageType::FIND_VALUE_RESPONSE:
            handle_find_value_response(message);
            break;
        default:
            break;
    }
}

void DHT::handle_ping(const DHTMessage& message) {
    // Send PONG response
    DHTMessage response;
    response.type = MessageType::PONG;
    response.sender_id = local_id_;
    response.transaction_id = message.transaction_id;
    response.sender_address = local_address_;
    response.sender_port = local_port_;
    
    PeerInfo sender{
        .id = message.sender_id,
        .address = message.sender_address,
        .port = message.sender_port,
        .last_seen = 0
    };
    
    send_message(sender, response);
}

void DHT::handle_find_node(const DHTMessage& message) {
    // Find closest nodes to the target
    auto closest = routing_table_.find_closest(message.target_id, K_BUCKET_SIZE);
    
    // Send response
    DHTMessage response;
    response.type = MessageType::FIND_NODE_RESPONSE;
    response.sender_id = local_id_;
    response.transaction_id = message.transaction_id;
    response.target_id = message.target_id;
    response.peers = closest;
    response.sender_address = local_address_;
    response.sender_port = local_port_;
    
    PeerInfo sender{
        .id = message.sender_id,
        .address = message.sender_address,
        .port = message.sender_port,
        .last_seen = 0
    };
    
    send_message(sender, response);
}

void DHT::handle_find_node_response(const DHTMessage& message) {
    // Add received peers to routing table
    for (const auto& peer : message.peers) {
        routing_table_.add_or_update(peer);
    }
}

void DHT::handle_store(const DHTMessage& message) {
    // Store the value locally
    std::string key_str = key_to_string(message.key);
    
    {
        std::lock_guard<std::mutex> lock(mutex_);
        storage_[key_str] = message.value;
    }
    
    // Notify callback if set
    ValueCallback callback;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        callback = value_callback_;
    }
    if (callback) {
        callback(message.key, message.value);
    }
    
    // Send response
    DHTMessage response;
    response.type = MessageType::STORE_RESPONSE;
    response.sender_id = local_id_;
    response.transaction_id = message.transaction_id;
    response.sender_address = local_address_;
    response.sender_port = local_port_;
    
    PeerInfo sender{
        .id = message.sender_id,
        .address = message.sender_address,
        .port = message.sender_port,
        .last_seen = 0
    };
    
    send_message(sender, response);
}

void DHT::handle_find_value(const DHTMessage& message) {
    std::string key_str = key_to_string(message.key);
    
    DHTMessage response;
    response.sender_id = local_id_;
    response.transaction_id = message.transaction_id;
    response.sender_address = local_address_;
    response.sender_port = local_port_;
    response.key = message.key;
    
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = storage_.find(key_str);
        if (it != storage_.end()) {
            // Found value locally
            response.type = MessageType::FIND_VALUE_RESPONSE;
            response.value = it->second;
        } else {
            // Return closest nodes instead
            response.type = MessageType::FIND_NODE_RESPONSE;
            response.peers = routing_table_.find_closest(message.target_id, K_BUCKET_SIZE);
        }
    }
    
    PeerInfo sender{
        .id = message.sender_id,
        .address = message.sender_address,
        .port = message.sender_port,
        .last_seen = 0
    };
    
    send_message(sender, response);
}

void DHT::handle_find_value_response(const DHTMessage& message) {
    // Value found - will be handled by pending request
    // Also add any peers to routing table
    for (const auto& peer : message.peers) {
        routing_table_.add_or_update(peer);
    }
}

std::vector<PeerInfo> DHT::iterative_find_node(const NodeId& target) {
    // Start with closest known nodes
    auto closest = routing_table_.find_closest(target, ALPHA);
    
    if (closest.empty()) {
        return {};
    }
    
    std::set<NodeId> queried;
    std::vector<PeerInfo> results;
    
    // Iteratively query nodes
    for (int round = 0; round < 10 && !closest.empty(); ++round) {
        std::vector<std::future<std::optional<DHTMessage>>> futures;
        
        // Query ALPHA nodes in parallel
        for (size_t i = 0; i < std::min(closest.size(), ALPHA); ++i) {
            const auto& peer = closest[i];
            
            if (queried.count(peer.id) > 0) {
                continue;
            }
            queried.insert(peer.id);
            
            DHTMessage request;
            request.type = MessageType::FIND_NODE;
            request.sender_id = local_id_;
            request.transaction_id = generate_transaction_id();
            request.target_id = target;
            request.sender_address = local_address_;
            request.sender_port = local_port_;
            
            futures.push_back(std::async(std::launch::async, [this, peer, request]() {
                return send_and_wait(peer, request, std::chrono::milliseconds(3000));
            }));
        }
        
        // Collect responses
        bool found_closer = false;
        for (auto& future : futures) {
            auto response = future.get();
            if (response && response->type == MessageType::FIND_NODE_RESPONSE) {
                for (const auto& peer : response->peers) {
                    routing_table_.add_or_update(peer);
                    
                    // Check if this is closer than what we have
                    if (queried.count(peer.id) == 0) {
                        found_closer = true;
                    }
                }
            }
        }
        
        if (!found_closer) {
            break;
        }
        
        // Get new closest nodes
        closest = routing_table_.find_closest(target, K_BUCKET_SIZE);
    }
    
    return routing_table_.find_closest(target, K_BUCKET_SIZE);
}

std::vector<PeerInfo> DHT::find_node(const NodeId& target) {
    return iterative_find_node(target);
}

bool DHT::store(const std::vector<uint8_t>& key, const std::vector<uint8_t>& value) {
    // Compute target ID from key
    auto hash = crypto::blake2b(key);
    NodeId::Data target_data;
    std::copy(hash.begin(), hash.end(), target_data.begin());
    NodeId target(target_data);
    
    // Find K closest nodes to the key
    auto closest = find_node(target);
    
    if (closest.empty()) {
        // Store locally if no peers
        std::string key_str = key_to_string(key);
        std::lock_guard<std::mutex> lock(mutex_);
        storage_[key_str] = value;
        return true;
    }
    
    // Store on all K closest nodes
    bool success = false;
    for (const auto& peer : closest) {
        DHTMessage request;
        request.type = MessageType::STORE;
        request.sender_id = local_id_;
        request.transaction_id = generate_transaction_id();
        request.key = key;
        request.value = value;
        request.sender_address = local_address_;
        request.sender_port = local_port_;
        
        if (send_message(peer, request)) {
            success = true;
        }
    }
    
    // Also store locally
    std::string key_str = key_to_string(key);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        storage_[key_str] = value;
    }
    
    return success;
}

std::optional<std::vector<uint8_t>> DHT::find_value(const std::vector<uint8_t>& key) {
    // Check local storage first
    std::string key_str = key_to_string(key);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = storage_.find(key_str);
        if (it != storage_.end()) {
            return it->second;
        }
    }
    
    // Compute target ID from key
    auto hash = crypto::blake2b(key);
    NodeId::Data target_data;
    std::copy(hash.begin(), hash.end(), target_data.begin());
    NodeId target(target_data);
    
    // Iterative lookup similar to find_node but return early if value found
    auto closest = routing_table_.find_closest(target, ALPHA);
    
    std::set<NodeId> queried;
    
    for (int round = 0; round < 10 && !closest.empty(); ++round) {
        for (const auto& peer : closest) {
            if (queried.count(peer.id) > 0) {
                continue;
            }
            queried.insert(peer.id);
            
            DHTMessage request;
            request.type = MessageType::FIND_VALUE;
            request.sender_id = local_id_;
            request.transaction_id = generate_transaction_id();
            request.target_id = target;
            request.key = key;
            request.sender_address = local_address_;
            request.sender_port = local_port_;
            
            auto response = send_and_wait(peer, request, std::chrono::milliseconds(3000));
            if (response) {
                if (response->type == MessageType::FIND_VALUE_RESPONSE && !response->value.empty()) {
                    // Found the value!
                    // Cache it locally
                    std::lock_guard<std::mutex> lock(mutex_);
                    storage_[key_str] = response->value;
                    return response->value;
                }
                
                // Add returned peers to routing table
                for (const auto& p : response->peers) {
                    routing_table_.add_or_update(p);
                }
            }
        }
        
        closest = routing_table_.find_closest(target, ALPHA);
    }
    
    return std::nullopt;
}

bool DHT::ping(const PeerInfo& peer) {
    DHTMessage request;
    request.type = MessageType::PING;
    request.sender_id = local_id_;
    request.transaction_id = generate_transaction_id();
    request.sender_address = local_address_;
    request.sender_port = local_port_;
    
    auto response = send_and_wait(peer, request, std::chrono::milliseconds(3000));
    
    if (response && response->type == MessageType::PONG) {
        routing_table_.touch(peer.id);
        return true;
    }
    
    return false;
}

void DHT::refresh() {
    // Find a random node in each bucket to keep routing table fresh
    for (size_t i = 0; i < NUM_BUCKETS; ++i) {
        auto random_id = NodeId::random();
        find_node(random_id);
    }
}

std::string DHT::key_to_string(const std::vector<uint8_t>& key) {
    return crypto::to_hex(key);
}

} // namespace network
