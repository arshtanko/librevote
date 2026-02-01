#pragma once

#include "udp_transport.h"
#include "../network/dht.h"
#include "../crypto/keypair.h"

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>

namespace network {

/**
 * Callback for application-level messages (non-DHT)
 */
using MessageCallback = std::function<void(const NodeId& sender, 
                                            const std::vector<uint8_t>& data)>;

/**
 * P2P Node that integrates DHT with UDP transport
 * Main entry point for P2P networking
 */
class P2PNode {
public:
    /**
     * Create P2P node with given keypair
     * @param keypair Node's cryptographic identity
     * @param port UDP port to bind (0 for auto-assign)
     */
    P2PNode(const crypto::Keypair& keypair, uint16_t port = 0);
    
    ~P2PNode();

    // Non-copyable
    P2PNode(const P2PNode&) = delete;
    P2PNode& operator=(const P2PNode&) = delete;

    /**
     * Start the P2P node
     * Begins listening for incoming connections
     */
    bool start();

    /**
     * Stop the P2P node
     */
    void stop();

    /**
     * Check if node is running
     */
    bool is_running() const { return running_.load(); }

    /**
     * Bootstrap by connecting to known nodes
     */
    void bootstrap(const std::vector<PeerInfo>& nodes);

    /**
     * Bootstrap from address string (ip:port)
     */
    void bootstrap(const std::string& address);

    /**
     * Get local node ID
     */
    const NodeId& local_id() const { return dht_.local_id(); }

    /**
     * Get local peer info
     */
    PeerInfo local_peer_info() const;

    /**
     * Get number of known peers
     */
    size_t peer_count() const { return dht_.peer_count(); }

    /**
     * Get all known peers
     */
    std::vector<PeerInfo> get_peers() const { return dht_.get_all_peers(); }

    /**
     * Find nodes close to a target ID
     */
    std::vector<PeerInfo> find_node(const NodeId& target);

    /**
     * Store a value in the DHT
     */
    bool store(const std::vector<uint8_t>& key, const std::vector<uint8_t>& value);

    /**
     * Retrieve a value from the DHT
     */
    std::optional<std::vector<uint8_t>> find_value(const std::vector<uint8_t>& key);

    /**
     * Broadcast data to all known peers
     */
    void broadcast(const std::vector<uint8_t>& data);

    /**
     * Send data to a specific peer
     */
    bool send_to(const NodeId& peer_id, const std::vector<uint8_t>& data);
    bool send_to(const PeerInfo& peer, const std::vector<uint8_t>& data);

    /**
     * Set callback for DHT value storage (for receiving broadcasts)
     */
    void set_value_callback(ValueCallback callback);

    /**
     * Set callback for direct messages
     */
    void set_message_callback(MessageCallback callback);

    /**
     * Get local address
     */
    std::string local_address() const;
    uint16_t local_port() const;

    /**
     * Get DHT (for advanced usage)
     */
    DHT& dht() { return dht_; }
    const DHT& dht() const { return dht_; }

    /**
     * Get transport statistics
     */
    size_t bytes_sent() const { return transport_.bytes_sent(); }
    size_t bytes_received() const { return transport_.bytes_received(); }

private:
    crypto::Keypair keypair_;
    DHT dht_;
    AsyncUdpTransport transport_;
    
    std::atomic<bool> running_{false};
    
    MessageCallback message_callback_;
    std::mutex callback_mutex_;
    
    // Message type prefixes
    static constexpr uint8_t MSG_TYPE_DHT = 0x01;
    static constexpr uint8_t MSG_TYPE_APP = 0x02;
    
    /**
     * Handle incoming UDP packet
     */
    void handle_packet(const std::vector<uint8_t>& data,
                       const std::string& sender_ip,
                       uint16_t sender_port);
    
    /**
     * Send callback for DHT
     */
    bool send_dht_message(const PeerInfo& peer, const std::vector<uint8_t>& data);
    
    /**
     * Parse bootstrap address (ip:port)
     */
    static std::optional<std::pair<std::string, uint16_t>> parse_address(const std::string& addr);
};

/**
 * Simple peer discovery via multicast (LAN only)
 */
class MulticastDiscovery {
public:
    /**
     * Create discovery service
     * @param node P2P node to announce
     * @param multicast_group Multicast group address (default: 239.255.255.250)
     * @param port Multicast port (default: 19850)
     */
    MulticastDiscovery(P2PNode& node, 
                       const std::string& multicast_group = "239.255.255.250",
                       uint16_t port = 19850);
    
    ~MulticastDiscovery();

    /**
     * Start discovery (announcing and listening)
     */
    bool start();

    /**
     * Stop discovery
     */
    void stop();

    /**
     * Announce presence immediately
     */
    void announce();

    /**
     * Set discovery interval
     */
    void set_interval(std::chrono::seconds interval) { interval_ = interval; }

private:
    P2PNode& node_;
    std::string multicast_group_;
    uint16_t multicast_port_;
    
    int socket_fd_ = -1;
    std::atomic<bool> running_{false};
    std::thread announce_thread_;
    std::thread listen_thread_;
    std::chrono::seconds interval_{30};
    
    void announce_loop();
    void listen_loop();
};

} // namespace network
