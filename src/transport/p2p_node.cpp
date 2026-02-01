#include "p2p_node.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <sstream>

namespace network {

P2PNode::P2PNode(const crypto::Keypair& keypair, uint16_t port)
    : keypair_(keypair)
    , dht_(keypair)
    , transport_(port) {}

P2PNode::~P2PNode() {
    stop();
}

bool P2PNode::start() {
    if (running_.load()) {
        return true;
    }

    if (!transport_.start()) {
        return false;
    }

    // Set up DHT send callback
    dht_.set_send_callback([this](const PeerInfo& peer, const std::vector<uint8_t>& data) {
        return send_dht_message(peer, data);
    });

    // Set up transport receive callback
    transport_.set_receive_callback([this](const std::vector<uint8_t>& data,
                                           const std::string& ip, uint16_t port) {
        handle_packet(data, ip, port);
    });

    // Set local address in DHT
    dht_.set_local_address(transport_.local_ip(), transport_.local_port());

    running_.store(true);
    return true;
}

void P2PNode::stop() {
    if (!running_.load()) {
        return;
    }

    running_.store(false);
    transport_.stop();
}

void P2PNode::bootstrap(const std::vector<PeerInfo>& nodes) {
    dht_.bootstrap(nodes);
}

void P2PNode::bootstrap(const std::string& address) {
    auto parsed = parse_address(address);
    if (!parsed) {
        return;
    }

    // Create a temporary peer info with unknown ID
    // The real ID will be discovered during PING
    PeerInfo peer;
    peer.id = NodeId::random();  // Placeholder
    peer.address = parsed->first;
    peer.port = parsed->second;
    peer.last_seen = 0;

    bootstrap({peer});
}

PeerInfo P2PNode::local_peer_info() const {
    return PeerInfo{
        .id = dht_.local_id(),
        .address = transport_.local_ip(),
        .port = transport_.local_port(),
        .last_seen = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count())
    };
}

std::vector<PeerInfo> P2PNode::find_node(const NodeId& target) {
    return dht_.find_node(target);
}

bool P2PNode::store(const std::vector<uint8_t>& key, const std::vector<uint8_t>& value) {
    return dht_.store(key, value);
}

std::optional<std::vector<uint8_t>> P2PNode::find_value(const std::vector<uint8_t>& key) {
    return dht_.find_value(key);
}

void P2PNode::broadcast(const std::vector<uint8_t>& data) {
    auto peers = get_peers();
    for (const auto& peer : peers) {
        send_to(peer, data);
    }
}

bool P2PNode::send_to(const NodeId& peer_id, const std::vector<uint8_t>& data) {
    auto peer = dht_.routing_table().get(peer_id);
    if (!peer) {
        return false;
    }
    return send_to(*peer, data);
}

bool P2PNode::send_to(const PeerInfo& peer, const std::vector<uint8_t>& data) {
    // Wrap with APP message type
    std::vector<uint8_t> packet;
    packet.reserve(1 + NODE_ID_SIZE + data.size());
    
    packet.push_back(MSG_TYPE_APP);
    
    // Add sender ID
    const auto& local_id = dht_.local_id().data();
    packet.insert(packet.end(), local_id.begin(), local_id.end());
    
    // Add data
    packet.insert(packet.end(), data.begin(), data.end());
    
    return transport_.send(peer, packet);
}

void P2PNode::set_value_callback(ValueCallback callback) {
    dht_.set_value_callback(std::move(callback));
}

void P2PNode::set_message_callback(MessageCallback callback) {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    message_callback_ = std::move(callback);
}

std::string P2PNode::local_address() const {
    return transport_.local_ip();
}

uint16_t P2PNode::local_port() const {
    return transport_.local_port();
}

void P2PNode::handle_packet(const std::vector<uint8_t>& data,
                            const std::string& sender_ip,
                            uint16_t sender_port) {
    if (data.empty()) {
        return;
    }

    uint8_t msg_type = data[0];

    if (msg_type == MSG_TYPE_DHT) {
        // DHT message
        std::vector<uint8_t> dht_data(data.begin() + 1, data.end());
        auto msg = DHTMessage::deserialize(dht_data);
        if (msg) {
            // Fill in sender address if not present
            if (msg->sender_address.empty()) {
                msg->sender_address = sender_ip;
                msg->sender_port = sender_port;
            }
            dht_.handle_message(*msg);
        }
    } else if (msg_type == MSG_TYPE_APP) {
        // Application message
        if (data.size() < 1 + NODE_ID_SIZE) {
            return;
        }
        
        // Extract sender ID
        NodeId::Data sender_id_data;
        std::copy(data.begin() + 1, data.begin() + 1 + NODE_ID_SIZE, sender_id_data.begin());
        NodeId sender_id(sender_id_data);
        
        // Extract payload
        std::vector<uint8_t> payload(data.begin() + 1 + NODE_ID_SIZE, data.end());
        
        // Invoke callback
        MessageCallback callback;
        {
            std::lock_guard<std::mutex> lock(callback_mutex_);
            callback = message_callback_;
        }
        
        if (callback) {
            callback(sender_id, payload);
        }
    }
}

bool P2PNode::send_dht_message(const PeerInfo& peer, const std::vector<uint8_t>& data) {
    // Wrap with DHT message type
    std::vector<uint8_t> packet;
    packet.reserve(1 + data.size());
    packet.push_back(MSG_TYPE_DHT);
    packet.insert(packet.end(), data.begin(), data.end());
    
    return transport_.send(peer, packet);
}

std::optional<std::pair<std::string, uint16_t>> P2PNode::parse_address(const std::string& addr) {
    size_t colon_pos = addr.rfind(':');
    if (colon_pos == std::string::npos) {
        return std::nullopt;
    }
    
    std::string ip = addr.substr(0, colon_pos);
    std::string port_str = addr.substr(colon_pos + 1);
    
    try {
        uint16_t port = static_cast<uint16_t>(std::stoi(port_str));
        return std::make_pair(ip, port);
    } catch (...) {
        return std::nullopt;
    }
}


MulticastDiscovery::MulticastDiscovery(P2PNode& node,
                                       const std::string& multicast_group,
                                       uint16_t port)
    : node_(node)
    , multicast_group_(multicast_group)
    , multicast_port_(port) {}

MulticastDiscovery::~MulticastDiscovery() {
    stop();
}

bool MulticastDiscovery::start() {
    if (running_.load()) {
        return true;
    }

    // Create UDP socket for multicast
    socket_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd_ < 0) {
        return false;
    }

    // Allow multiple sockets to use the same port
    int opt = 1;
    setsockopt(socket_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Bind to multicast port
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(multicast_port_);

    if (bind(socket_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(socket_fd_);
        socket_fd_ = -1;
        return false;
    }

    // Join multicast group
    ip_mreq mreq{};
    inet_pton(AF_INET, multicast_group_.c_str(), &mreq.imr_multiaddr);
    mreq.imr_interface.s_addr = INADDR_ANY;

    if (setsockopt(socket_fd_, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        close(socket_fd_);
        socket_fd_ = -1;
        return false;
    }

    // Set receive timeout
    timeval tv{};
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(socket_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    running_.store(true);

    announce_thread_ = std::thread(&MulticastDiscovery::announce_loop, this);
    listen_thread_ = std::thread(&MulticastDiscovery::listen_loop, this);

    return true;
}

void MulticastDiscovery::stop() {
    if (!running_.load()) {
        return;
    }

    running_.store(false);

    if (announce_thread_.joinable()) {
        announce_thread_.join();
    }

    if (listen_thread_.joinable()) {
        listen_thread_.join();
    }

    if (socket_fd_ >= 0) {
        close(socket_fd_);
        socket_fd_ = -1;
    }
}

void MulticastDiscovery::announce() {
    if (socket_fd_ < 0) {
        return;
    }

    // Build announcement message
    // Format: "LIBREVOTE:" + hex(node_id) + ":" + port
    auto local_info = node_.local_peer_info();
    std::string msg = "LIBREVOTE:" + local_info.id.to_hex() + ":" + 
                      std::to_string(local_info.port);

    sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(multicast_port_);
    inet_pton(AF_INET, multicast_group_.c_str(), &dest.sin_addr);

    sendto(socket_fd_, msg.c_str(), msg.size(), 0,
           reinterpret_cast<sockaddr*>(&dest), sizeof(dest));
}

void MulticastDiscovery::announce_loop() {
    while (running_.load()) {
        announce();

        // Sleep for interval
        for (int i = 0; i < interval_.count() && running_.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

void MulticastDiscovery::listen_loop() {
    char buffer[256];

    while (running_.load()) {
        sockaddr_in sender_addr{};
        socklen_t sender_len = sizeof(sender_addr);

        ssize_t received = recvfrom(socket_fd_, buffer, sizeof(buffer) - 1, 0,
                                    reinterpret_cast<sockaddr*>(&sender_addr), &sender_len);

        if (received > 0) {
            buffer[received] = '\0';
            std::string msg(buffer);

            // Parse announcement
            if (msg.substr(0, 10) == "LIBREVOTE:") {
                size_t first_colon = msg.find(':', 10);
                if (first_colon != std::string::npos) {
                    std::string node_id_hex = msg.substr(10, first_colon - 10);
                    std::string port_str = msg.substr(first_colon + 1);

                    auto node_id = NodeId::from_hex(node_id_hex);
                    if (node_id && *node_id != node_.local_id()) {
                        try {
                            uint16_t port = static_cast<uint16_t>(std::stoi(port_str));
                            
                            char ip_str[INET_ADDRSTRLEN];
                            inet_ntop(AF_INET, &sender_addr.sin_addr, ip_str, sizeof(ip_str));

                            PeerInfo peer;
                            peer.id = *node_id;
                            peer.address = ip_str;
                            peer.port = port;
                            peer.last_seen = static_cast<uint64_t>(
                                std::chrono::duration_cast<std::chrono::seconds>(
                                    std::chrono::system_clock::now().time_since_epoch()).count());

                            node_.bootstrap({peer});
                        } catch (...) {
                            // Invalid port
                        }
                    }
                }
            }
        }
    }
}

} // namespace network
