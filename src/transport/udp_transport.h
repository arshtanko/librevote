#pragma once

#include "../network/dht.h"
#include "../network/node_id.h"

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <queue>
#include <condition_variable>

namespace network {

/**
 * Callback for received data
 */
using ReceiveCallback = std::function<void(const std::vector<uint8_t>& data, 
                                            const std::string& sender_ip, 
                                            uint16_t sender_port)>;

/**
 * UDP Transport for P2P communication
 * Handles low-level UDP socket operations
 */
class UdpTransport {
public:
    /**
     * Create UDP transport bound to specified port
     */
    explicit UdpTransport(uint16_t port = 0);
    
    ~UdpTransport();

    // Non-copyable
    UdpTransport(const UdpTransport&) = delete;
    UdpTransport& operator=(const UdpTransport&) = delete;

    /**
     * Start listening for incoming messages
     * Returns true on success
     */
    bool start();

    /**
     * Stop the transport
     */
    void stop();

    /**
     * Check if transport is running
     */
    bool is_running() const { return running_.load(); }

    /**
     * Send data to a specific address
     * Returns true if send succeeded
     */
    bool send(const std::string& ip, uint16_t port, const std::vector<uint8_t>& data);

    /**
     * Send data to a peer
     */
    bool send(const PeerInfo& peer, const std::vector<uint8_t>& data);

    /**
     * Set callback for received messages
     */
    void set_receive_callback(ReceiveCallback callback);

    /**
     * Get the local port (useful when port=0 was specified)
     */
    uint16_t local_port() const { return local_port_; }

    /**
     * Get the local IP address
     */
    std::string local_ip() const { return local_ip_; }

    /**
     * Get statistics
     */
    size_t bytes_sent() const { return bytes_sent_.load(); }
    size_t bytes_received() const { return bytes_received_.load(); }
    size_t packets_sent() const { return packets_sent_.load(); }
    size_t packets_received() const { return packets_received_.load(); }

private:
    uint16_t local_port_;
    std::string local_ip_;
    int socket_fd_ = -1;
    
    std::atomic<bool> running_{false};
    std::thread receive_thread_;
    
    ReceiveCallback receive_callback_;
    std::mutex callback_mutex_;
    
    // Statistics
    std::atomic<size_t> bytes_sent_{0};
    std::atomic<size_t> bytes_received_{0};
    std::atomic<size_t> packets_sent_{0};
    std::atomic<size_t> packets_received_{0};
    
    // Buffer size for UDP packets
    static constexpr size_t MAX_PACKET_SIZE = 65507;  // Max UDP payload
    
    /**
     * Receive loop running in background thread
     */
    void receive_loop();
    
    /**
     * Detect local IP address
     */
    static std::string detect_local_ip();
};

/**
 * Message queue for outgoing messages
 * Thread-safe producer-consumer queue
 */
class MessageQueue {
public:
    struct OutgoingMessage {
        std::string ip;
        uint16_t port;
        std::vector<uint8_t> data;
    };

    /**
     * Push message to queue
     */
    void push(OutgoingMessage msg);

    /**
     * Pop message from queue (blocking)
     * Returns false if queue is stopped
     */
    bool pop(OutgoingMessage& msg);

    /**
     * Stop the queue (unblocks waiting consumers)
     */
    void stop();

    /**
     * Get queue size
     */
    size_t size() const;

private:
    std::queue<OutgoingMessage> queue_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::atomic<bool> stopped_{false};
};

/**
 * Async UDP Transport with send queue
 * Provides non-blocking send operations
 */
class AsyncUdpTransport {
public:
    explicit AsyncUdpTransport(uint16_t port = 0);
    ~AsyncUdpTransport();

    // Non-copyable
    AsyncUdpTransport(const AsyncUdpTransport&) = delete;
    AsyncUdpTransport& operator=(const AsyncUdpTransport&) = delete;

    /**
     * Start transport (receive and send threads)
     */
    bool start();

    /**
     * Stop transport
     */
    void stop();

    /**
     * Check if running
     */
    bool is_running() const { return transport_.is_running(); }

    /**
     * Queue message for sending (non-blocking)
     */
    void send_async(const std::string& ip, uint16_t port, const std::vector<uint8_t>& data);
    void send_async(const PeerInfo& peer, const std::vector<uint8_t>& data);

    /**
     * Send synchronously
     */
    bool send(const std::string& ip, uint16_t port, const std::vector<uint8_t>& data);
    bool send(const PeerInfo& peer, const std::vector<uint8_t>& data);

    /**
     * Set receive callback
     */
    void set_receive_callback(ReceiveCallback callback);

    /**
     * Get local address info
     */
    uint16_t local_port() const { return transport_.local_port(); }
    std::string local_ip() const { return transport_.local_ip(); }

    /**
     * Get pending messages count
     */
    size_t pending_messages() const { return send_queue_.size(); }

    /**
     * Get statistics
     */
    size_t bytes_sent() const { return transport_.bytes_sent(); }
    size_t bytes_received() const { return transport_.bytes_received(); }

private:
    UdpTransport transport_;
    MessageQueue send_queue_;
    std::thread send_thread_;
    std::atomic<bool> running_{false};

    void send_loop();
};

} // namespace network
