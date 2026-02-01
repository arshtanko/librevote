#include "udp_transport.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <cstring>
#include <stdexcept>

namespace network {

UdpTransport::UdpTransport(uint16_t port) : local_port_(port) {
    local_ip_ = detect_local_ip();
}

UdpTransport::~UdpTransport() {
    stop();
}

bool UdpTransport::start() {
    if (running_.load()) {
        return true;
    }

    // Create UDP socket
    socket_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd_ < 0) {
        return false;
    }

    // Allow address reuse
    int opt = 1;
    setsockopt(socket_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Bind to local address
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(local_port_);

    if (bind(socket_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(socket_fd_);
        socket_fd_ = -1;
        return false;
    }

    // Get actual port if we bound to port 0
    if (local_port_ == 0) {
        socklen_t addr_len = sizeof(addr);
        if (getsockname(socket_fd_, reinterpret_cast<sockaddr*>(&addr), &addr_len) == 0) {
            local_port_ = ntohs(addr.sin_port);
        }
    }

    // Set receive timeout (100ms) to allow checking running_ flag
    timeval tv{};
    tv.tv_sec = 0;
    tv.tv_usec = 100000;
    setsockopt(socket_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    running_.store(true);

    // Start receive thread
    receive_thread_ = std::thread(&UdpTransport::receive_loop, this);

    return true;
}

void UdpTransport::stop() {
    if (!running_.load()) {
        return;
    }

    running_.store(false);

    if (receive_thread_.joinable()) {
        receive_thread_.join();
    }

    if (socket_fd_ >= 0) {
        close(socket_fd_);
        socket_fd_ = -1;
    }
}

bool UdpTransport::send(const std::string& ip, uint16_t port, const std::vector<uint8_t>& data) {
    if (!running_.load() || socket_fd_ < 0) {
        return false;
    }

    sockaddr_in dest_addr{};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, ip.c_str(), &dest_addr.sin_addr) <= 0) {
        return false;
    }

    ssize_t sent = sendto(socket_fd_, data.data(), data.size(), 0,
                          reinterpret_cast<sockaddr*>(&dest_addr), sizeof(dest_addr));

    if (sent > 0) {
        bytes_sent_ += sent;
        packets_sent_++;
        return true;
    }

    return false;
}

bool UdpTransport::send(const PeerInfo& peer, const std::vector<uint8_t>& data) {
    return send(peer.address, peer.port, data);
}

void UdpTransport::set_receive_callback(ReceiveCallback callback) {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    receive_callback_ = std::move(callback);
}

void UdpTransport::receive_loop() {
    std::vector<uint8_t> buffer(MAX_PACKET_SIZE);

    while (running_.load()) {
        sockaddr_in sender_addr{};
        socklen_t sender_len = sizeof(sender_addr);

        ssize_t received = recvfrom(socket_fd_, buffer.data(), buffer.size(), 0,
                                    reinterpret_cast<sockaddr*>(&sender_addr), &sender_len);

        if (received > 0) {
            bytes_received_ += received;
            packets_received_++;

            // Get sender IP
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sender_addr.sin_addr, ip_str, sizeof(ip_str));
            uint16_t sender_port = ntohs(sender_addr.sin_port);

            // Copy received data
            std::vector<uint8_t> data(buffer.begin(), buffer.begin() + received);

            // Invoke callback
            ReceiveCallback callback;
            {
                std::lock_guard<std::mutex> lock(callback_mutex_);
                callback = receive_callback_;
            }

            if (callback) {
                callback(data, std::string(ip_str), sender_port);
            }
        }
        // Timeout or error - continue loop to check running_ flag
    }
}

std::string UdpTransport::detect_local_ip() {
    ifaddrs* ifaddr = nullptr;
    
    if (getifaddrs(&ifaddr) == -1) {
        return "127.0.0.1";
    }

    std::string result = "127.0.0.1";

    for (ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) {
            continue;
        }

        if (ifa->ifa_addr->sa_family == AF_INET) {
            auto* addr = reinterpret_cast<sockaddr_in*>(ifa->ifa_addr);
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr->sin_addr, ip_str, sizeof(ip_str));

            std::string ip(ip_str);
            
            // Skip loopback
            if (ip != "127.0.0.1" && ip.substr(0, 4) != "127.") {
                result = ip;
                break;
            }
        }
    }

    freeifaddrs(ifaddr);
    return result;
}

void MessageQueue::push(OutgoingMessage msg) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push(std::move(msg));
    }
    cv_.notify_one();
}

bool MessageQueue::pop(OutgoingMessage& msg) {
    std::unique_lock<std::mutex> lock(mutex_);
    
    cv_.wait(lock, [this] { 
        return !queue_.empty() || stopped_.load(); 
    });

    if (stopped_.load() && queue_.empty()) {
        return false;
    }

    msg = std::move(queue_.front());
    queue_.pop();
    return true;
}

void MessageQueue::stop() {
    stopped_.store(true);
    cv_.notify_all();
}

size_t MessageQueue::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
}

AsyncUdpTransport::AsyncUdpTransport(uint16_t port) : transport_(port) {}

AsyncUdpTransport::~AsyncUdpTransport() {
    stop();
}

bool AsyncUdpTransport::start() {
    if (running_.load()) {
        return true;
    }

    if (!transport_.start()) {
        return false;
    }

    running_.store(true);
    send_thread_ = std::thread(&AsyncUdpTransport::send_loop, this);

    return true;
}

void AsyncUdpTransport::stop() {
    if (!running_.load()) {
        return;
    }

    running_.store(false);
    send_queue_.stop();

    if (send_thread_.joinable()) {
        send_thread_.join();
    }

    transport_.stop();
}

void AsyncUdpTransport::send_async(const std::string& ip, uint16_t port, 
                                    const std::vector<uint8_t>& data) {
    send_queue_.push({ip, port, data});
}

void AsyncUdpTransport::send_async(const PeerInfo& peer, const std::vector<uint8_t>& data) {
    send_async(peer.address, peer.port, data);
}

bool AsyncUdpTransport::send(const std::string& ip, uint16_t port, 
                              const std::vector<uint8_t>& data) {
    return transport_.send(ip, port, data);
}

bool AsyncUdpTransport::send(const PeerInfo& peer, const std::vector<uint8_t>& data) {
    return transport_.send(peer, data);
}

void AsyncUdpTransport::set_receive_callback(ReceiveCallback callback) {
    transport_.set_receive_callback(std::move(callback));
}

void AsyncUdpTransport::send_loop() {
    MessageQueue::OutgoingMessage msg;

    while (running_.load()) {
        if (send_queue_.pop(msg)) {
            transport_.send(msg.ip, msg.port, msg.data);
        }
    }
}

} // namespace network
