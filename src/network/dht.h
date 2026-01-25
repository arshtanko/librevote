#pragma once

#include "node_id.h"
#include "routing_table.h"
#include "../crypto/keypair.h"

#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <unordered_map>

namespace network {

/**
 * DHT message types (Kademlia protocol)
 */
enum class MessageType : uint8_t {
    PING = 0x01,
    PONG = 0x02,
    FIND_NODE = 0x03,
    FIND_NODE_RESPONSE = 0x04,
    STORE = 0x05,
    STORE_RESPONSE = 0x06,
    FIND_VALUE = 0x07,
    FIND_VALUE_RESPONSE = 0x08,
};

/**
 * DHT message structure
 */
struct DHTMessage {
    MessageType type;
    NodeId sender_id;
    uint64_t transaction_id;  // For matching requests/responses
    
    // FIND_NODE / FIND_VALUE
    NodeId target_id;
    
    // FIND_NODE_RESPONSE / FIND_VALUE_RESPONSE
    std::vector<PeerInfo> peers;
    
    // STORE / FIND_VALUE_RESPONSE
    std::vector<uint8_t> key;
    std::vector<uint8_t> value;
    
    // Sender info for routing table updates
    std::string sender_address;
    uint16_t sender_port;
    
    /**
     * Serialize message to bytes
     */
    std::vector<uint8_t> serialize() const;
    
    /**
     * Deserialize message from bytes
     */
    static std::optional<DHTMessage> deserialize(const std::vector<uint8_t>& data);
};

/**
 * Callback type for sending messages (network layer will implement this)
 */
using SendCallback = std::function<bool(const PeerInfo& peer, const std::vector<uint8_t>& data)>;

/**
 * Callback type for receiving stored values
 */
using ValueCallback = std::function<void(const std::vector<uint8_t>& key, const std::vector<uint8_t>& value)>;

/**
 * Distributed Hash Table node
 * Implements Kademlia-style DHT for peer discovery and data storage
 */
class DHT {
public:
    /**
     * Create DHT node with given keypair
     */
    explicit DHT(const crypto::Keypair& keypair);

    /**
     * Get the local node ID
     */
    const NodeId& local_id() const { return local_id_; }

    /**
     * Get the local peer info
     */
    PeerInfo local_peer_info() const;

    /**
     * Set the send callback (for network integration)
     */
    void set_send_callback(SendCallback callback);

    /**
     * Set local address information
     */
    void set_local_address(const std::string& address, uint16_t port);

    /**
     * Bootstrap the DHT by connecting to known nodes
     */
    void bootstrap(const std::vector<PeerInfo>& bootstrap_nodes);

    /**
     * Handle incoming DHT message
     * Called by network layer when message is received
     */
    void handle_message(const DHTMessage& message);

    /**
     * Find nodes close to a target ID
     * Uses iterative lookup process
     */
    std::vector<PeerInfo> find_node(const NodeId& target);

    /**
     * Store a key-value pair in the DHT
     */
    bool store(const std::vector<uint8_t>& key, const std::vector<uint8_t>& value);

    /**
     * Retrieve a value from the DHT
     */
    std::optional<std::vector<uint8_t>> find_value(const std::vector<uint8_t>& key);

    /**
     * Ping a node to check if it's alive
     */
    bool ping(const PeerInfo& peer);

    /**
     * Get the routing table (read-only access)
     */
    const RoutingTable& routing_table() const { return routing_table_; }

    /**
     * Get number of known peers
     */
    size_t peer_count() const { return routing_table_.size(); }

    /**
     * Get all known peers
     */
    std::vector<PeerInfo> get_all_peers() const { return routing_table_.get_all_peers(); }

    /**
     * Refresh buckets (find random nodes to keep routing table fresh)
     */
    void refresh();

    /**
     * Set callback for stored values (for receiving broadcasts)
     */
    void set_value_callback(ValueCallback callback);

private:
    NodeId local_id_;
    crypto::Keypair keypair_;
    RoutingTable routing_table_;
    
    std::string local_address_;
    uint16_t local_port_ = 0;
    
    SendCallback send_callback_;
    ValueCallback value_callback_;
    
    mutable std::mutex mutex_;
    
    // Local storage
    std::unordered_map<std::string, std::vector<uint8_t>> storage_;
    
    // Pending requests (transaction_id -> promise)
    std::unordered_map<uint64_t, std::promise<DHTMessage>> pending_requests_;
    uint64_t next_transaction_id_ = 1;
    
    /**
     * Generate unique transaction ID
     */
    uint64_t generate_transaction_id();
    
    /**
     * Send a message and wait for response
     */
    std::optional<DHTMessage> send_and_wait(const PeerInfo& peer, DHTMessage message, 
                                             std::chrono::milliseconds timeout);
    
    /**
     * Send a message without waiting
     */
    bool send_message(const PeerInfo& peer, const DHTMessage& message);
    
    /**
     * Handle specific message types
     */
    void handle_ping(const DHTMessage& message);
    void handle_find_node(const DHTMessage& message);
    void handle_find_node_response(const DHTMessage& message);
    void handle_store(const DHTMessage& message);
    void handle_find_value(const DHTMessage& message);
    void handle_find_value_response(const DHTMessage& message);
    
    /**
     * Update routing table with sender info
     */
    void update_sender(const DHTMessage& message);
    
    /**
     * Iterative node lookup
     */
    std::vector<PeerInfo> iterative_find_node(const NodeId& target);
    
    /**
     * Convert key bytes to storage key string
     */
    static std::string key_to_string(const std::vector<uint8_t>& key);
};

} // namespace network
