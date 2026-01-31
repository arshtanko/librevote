#include <gtest/gtest.h>

#include "network/node_id.h"
#include "network/routing_table.h"
#include "network/dht.h"
#include "crypto/keypair.h"

using namespace network;
using namespace crypto;

// ============================================================================
// NodeId Tests
// ============================================================================

class NodeIdTest : public ::testing::Test {
protected:
    void SetUp() override {
        crypto::init();
    }
};

TEST_F(NodeIdTest, DefaultConstructorCreatesZeroId) {
    NodeId id;
    for (size_t i = 0; i < NODE_ID_SIZE; ++i) {
        EXPECT_EQ(id[i], 0);
    }
}

TEST_F(NodeIdTest, RandomGeneratesUniqueIds) {
    auto id1 = NodeId::random();
    auto id2 = NodeId::random();
    EXPECT_NE(id1, id2);
}

TEST_F(NodeIdTest, FromPublicKeyIsDeterministic) {
    auto keypair = Keypair::generate();
    auto id1 = NodeId::from_public_key(keypair.public_key());
    auto id2 = NodeId::from_public_key(keypair.public_key());
    EXPECT_EQ(id1, id2);
}

TEST_F(NodeIdTest, DifferentKeysProduceDifferentIds) {
    auto keypair1 = Keypair::generate();
    auto keypair2 = Keypair::generate();
    auto id1 = NodeId::from_public_key(keypair1.public_key());
    auto id2 = NodeId::from_public_key(keypair2.public_key());
    EXPECT_NE(id1, id2);
}

TEST_F(NodeIdTest, DistanceIsSymmetric) {
    auto id1 = NodeId::random();
    auto id2 = NodeId::random();
    EXPECT_EQ(id1.distance(id2), id2.distance(id1));
}

TEST_F(NodeIdTest, DistanceToSelfIsZero) {
    auto id = NodeId::random();
    auto dist = id.distance(id);
    for (size_t i = 0; i < NODE_ID_SIZE; ++i) {
        EXPECT_EQ(dist[i], 0);
    }
}

TEST_F(NodeIdTest, XorDistanceIsCorrect) {
    NodeId::Data data1, data2;
    data1.fill(0);
    data2.fill(0);
    data1[0] = 0b10101010;
    data2[0] = 0b01010101;
    
    NodeId id1(data1);
    NodeId id2(data2);
    auto dist = id1.distance(id2);
    
    EXPECT_EQ(dist[0], 0xFF);  // XOR result
}

TEST_F(NodeIdTest, BucketIndexIsCorrectForDistantNodes) {
    NodeId::Data data1, data2;
    data1.fill(0);
    data2.fill(0);
    data2[0] = 0x80;  // Most significant bit set
    
    NodeId id1(data1);
    NodeId id2(data2);
    
    // Bucket index should be 255 (highest bucket for most distant nodes)
    EXPECT_EQ(id1.bucket_index(id2), 255);
}

TEST_F(NodeIdTest, BucketIndexIsCorrectForCloseNodes) {
    NodeId::Data data1, data2;
    data1.fill(0);
    data2.fill(0);
    data2[31] = 0x01;  // Only least significant bit differs
    
    NodeId id1(data1);
    NodeId id2(data2);
    
    EXPECT_EQ(id1.bucket_index(id2), 0);
}

TEST_F(NodeIdTest, BucketIndexForEqualNodesIs256) {
    auto id = NodeId::random();
    EXPECT_EQ(id.bucket_index(id), 256);
}

TEST_F(NodeIdTest, IsCloserToWorksCorrectly) {
    NodeId::Data target_data, closer_data, farther_data;
    target_data.fill(0);
    closer_data.fill(0);
    farther_data.fill(0);
    
    closer_data[31] = 0x01;   // Distance = 1
    farther_data[31] = 0x0F;  // Distance = 15
    
    NodeId target(target_data);
    NodeId closer(closer_data);
    NodeId farther(farther_data);
    
    EXPECT_TRUE(closer.is_closer_to(target, farther));
    EXPECT_FALSE(farther.is_closer_to(target, closer));
}

TEST_F(NodeIdTest, HexConversionRoundtrip) {
    auto id = NodeId::random();
    auto hex = id.to_hex();
    auto restored = NodeId::from_hex(hex);
    
    ASSERT_TRUE(restored.has_value());
    EXPECT_EQ(id, *restored);
}

TEST_F(NodeIdTest, FromHexRejectsInvalidInput) {
    EXPECT_FALSE(NodeId::from_hex("invalid").has_value());
    EXPECT_FALSE(NodeId::from_hex("abc").has_value());  // Too short
    EXPECT_FALSE(NodeId::from_hex("").has_value());
}

// ============================================================================
// KBucket Tests
// ============================================================================

class KBucketTest : public ::testing::Test {
protected:
    void SetUp() override {
        crypto::init();
    }
    
    PeerInfo make_peer(uint8_t id_byte = 0) {
        NodeId::Data data;
        data.fill(0);
        data[0] = id_byte;
        return PeerInfo{
            .id = NodeId(data),
            .address = "127.0.0.1",
            .port = static_cast<uint16_t>(8000 + id_byte),
            .last_seen = 1000
        };
    }
};

TEST_F(KBucketTest, AddPeerToEmptyBucket) {
    KBucket bucket;
    auto peer = make_peer(1);
    
    EXPECT_TRUE(bucket.add_or_update(peer));
    EXPECT_EQ(bucket.size(), 1);
    EXPECT_TRUE(bucket.contains(peer.id));
}

TEST_F(KBucketTest, UpdateExistingPeer) {
    KBucket bucket;
    auto peer = make_peer(1);
    peer.last_seen = 1000;
    
    EXPECT_TRUE(bucket.add_or_update(peer));
    
    peer.last_seen = 2000;
    EXPECT_TRUE(bucket.add_or_update(peer));
    
    EXPECT_EQ(bucket.size(), 1);
    
    auto retrieved = bucket.get(peer.id);
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(retrieved->last_seen, 2000);
}

TEST_F(KBucketTest, BucketRejectsWhenFull) {
    KBucket bucket;
    
    // Fill the bucket
    for (size_t i = 0; i < K_BUCKET_SIZE; ++i) {
        auto peer = make_peer(static_cast<uint8_t>(i));
        EXPECT_TRUE(bucket.add_or_update(peer));
    }
    
    EXPECT_TRUE(bucket.is_full());
    
    // Try to add one more
    auto extra_peer = make_peer(99);
    EXPECT_FALSE(bucket.add_or_update(extra_peer));
    EXPECT_EQ(bucket.size(), K_BUCKET_SIZE);
}

TEST_F(KBucketTest, RemovePeer) {
    KBucket bucket;
    auto peer = make_peer(1);
    
    bucket.add_or_update(peer);
    EXPECT_TRUE(bucket.contains(peer.id));
    
    bucket.remove(peer.id);
    EXPECT_FALSE(bucket.contains(peer.id));
    EXPECT_EQ(bucket.size(), 0);
}

TEST_F(KBucketTest, GetLeastRecentReturnsOldestPeer) {
    KBucket bucket;
    
    auto peer1 = make_peer(1);
    peer1.last_seen = 1000;
    bucket.add_or_update(peer1);
    
    auto peer2 = make_peer(2);
    peer2.last_seen = 2000;
    bucket.add_or_update(peer2);
    
    auto least_recent = bucket.get_least_recent();
    ASSERT_TRUE(least_recent.has_value());
    EXPECT_EQ(least_recent->id, peer1.id);
}

TEST_F(KBucketTest, TouchMovesPeerToEnd) {
    KBucket bucket;
    
    auto peer1 = make_peer(1);
    auto peer2 = make_peer(2);
    
    bucket.add_or_update(peer1);
    bucket.add_or_update(peer2);
    
    // peer1 should be least recent
    EXPECT_EQ(bucket.get_least_recent()->id, peer1.id);
    
    // Touch peer1
    bucket.touch(peer1.id);
    
    // Now peer2 should be least recent
    EXPECT_EQ(bucket.get_least_recent()->id, peer2.id);
}

// ============================================================================
// RoutingTable Tests
// ============================================================================

class RoutingTableTest : public ::testing::Test {
protected:
    void SetUp() override {
        crypto::init();
        local_id_ = NodeId::random();
        routing_table_ = std::make_unique<RoutingTable>(local_id_);
    }
    
    PeerInfo make_peer_with_id(const NodeId& id) {
        return PeerInfo{
            .id = id,
            .address = "127.0.0.1",
            .port = 8000,
            .last_seen = 1000
        };
    }
    
    NodeId local_id_;
    std::unique_ptr<RoutingTable> routing_table_;
};

TEST_F(RoutingTableTest, AddPeer) {
    auto peer_id = NodeId::random();
    auto peer = make_peer_with_id(peer_id);
    
    EXPECT_TRUE(routing_table_->add_or_update(peer));
    EXPECT_TRUE(routing_table_->contains(peer_id));
    EXPECT_EQ(routing_table_->size(), 1);
}

TEST_F(RoutingTableTest, DoesNotAddSelf) {
    auto peer = make_peer_with_id(local_id_);
    
    EXPECT_FALSE(routing_table_->add_or_update(peer));
    EXPECT_EQ(routing_table_->size(), 0);
}

TEST_F(RoutingTableTest, RemovePeer) {
    auto peer_id = NodeId::random();
    auto peer = make_peer_with_id(peer_id);
    
    routing_table_->add_or_update(peer);
    EXPECT_TRUE(routing_table_->contains(peer_id));
    
    routing_table_->remove(peer_id);
    EXPECT_FALSE(routing_table_->contains(peer_id));
}

TEST_F(RoutingTableTest, FindClosestReturnsCorrectOrder) {
    // Add several peers
    std::vector<NodeId> peer_ids;
    for (int i = 0; i < 10; ++i) {
        auto id = NodeId::random();
        peer_ids.push_back(id);
        routing_table_->add_or_update(make_peer_with_id(id));
    }
    
    auto target = NodeId::random();
    auto closest = routing_table_->find_closest(target, 5);
    
    EXPECT_LE(closest.size(), 5);
    
    // Verify ordering
    for (size_t i = 1; i < closest.size(); ++i) {
        EXPECT_TRUE(closest[i-1].id.is_closer_to(target, closest[i].id) ||
                    closest[i-1].id.distance(target) == closest[i].id.distance(target));
    }
}

TEST_F(RoutingTableTest, FindClosestReturnsAllWhenFewerThanK) {
    auto peer1 = make_peer_with_id(NodeId::random());
    auto peer2 = make_peer_with_id(NodeId::random());
    
    routing_table_->add_or_update(peer1);
    routing_table_->add_or_update(peer2);
    
    auto closest = routing_table_->find_closest(NodeId::random(), 10);
    EXPECT_EQ(closest.size(), 2);
}

TEST_F(RoutingTableTest, GetAllPeers) {
    for (int i = 0; i < 5; ++i) {
        routing_table_->add_or_update(make_peer_with_id(NodeId::random()));
    }
    
    auto all = routing_table_->get_all_peers();
    EXPECT_EQ(all.size(), 5);
}

// ============================================================================
// DHTMessage Tests
// ============================================================================

class DHTMessageTest : public ::testing::Test {
protected:
    void SetUp() override {
        crypto::init();
    }
};

TEST_F(DHTMessageTest, SerializeDeserializePing) {
    DHTMessage msg;
    msg.type = MessageType::PING;
    msg.sender_id = NodeId::random();
    msg.transaction_id = 12345;
    msg.sender_address = "192.168.1.1";
    msg.sender_port = 8080;
    
    auto serialized = msg.serialize();
    auto deserialized = DHTMessage::deserialize(serialized);
    
    ASSERT_TRUE(deserialized.has_value());
    EXPECT_EQ(deserialized->type, MessageType::PING);
    EXPECT_EQ(deserialized->sender_id, msg.sender_id);
    EXPECT_EQ(deserialized->transaction_id, 12345);
    EXPECT_EQ(deserialized->sender_address, "192.168.1.1");
    EXPECT_EQ(deserialized->sender_port, 8080);
}

TEST_F(DHTMessageTest, SerializeDeserializeFindNodeResponse) {
    DHTMessage msg;
    msg.type = MessageType::FIND_NODE_RESPONSE;
    msg.sender_id = NodeId::random();
    msg.transaction_id = 67890;
    msg.target_id = NodeId::random();
    
    // Add some peers
    for (int i = 0; i < 3; ++i) {
        NodeId::Data data;
        data.fill(static_cast<uint8_t>(i));
        msg.peers.push_back(PeerInfo{
            .id = NodeId(data),
            .address = "10.0.0." + std::to_string(i),
            .port = static_cast<uint16_t>(9000 + i),
            .last_seen = static_cast<uint64_t>(1000 + i)
        });
    }
    
    auto serialized = msg.serialize();
    auto deserialized = DHTMessage::deserialize(serialized);
    
    ASSERT_TRUE(deserialized.has_value());
    EXPECT_EQ(deserialized->type, MessageType::FIND_NODE_RESPONSE);
    EXPECT_EQ(deserialized->peers.size(), 3);
    
    for (size_t i = 0; i < 3; ++i) {
        EXPECT_EQ(deserialized->peers[i].id, msg.peers[i].id);
        EXPECT_EQ(deserialized->peers[i].address, msg.peers[i].address);
        EXPECT_EQ(deserialized->peers[i].port, msg.peers[i].port);
    }
}

TEST_F(DHTMessageTest, SerializeDeserializeStore) {
    DHTMessage msg;
    msg.type = MessageType::STORE;
    msg.sender_id = NodeId::random();
    msg.transaction_id = 11111;
    msg.key = {0x01, 0x02, 0x03, 0x04};
    msg.value = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    
    auto serialized = msg.serialize();
    auto deserialized = DHTMessage::deserialize(serialized);
    
    ASSERT_TRUE(deserialized.has_value());
    EXPECT_EQ(deserialized->type, MessageType::STORE);
    EXPECT_EQ(deserialized->key, msg.key);
    EXPECT_EQ(deserialized->value, msg.value);
}

// ============================================================================
// DHT Tests
// ============================================================================

class DHTTest : public ::testing::Test {
protected:
    void SetUp() override {
        crypto::init();
        
        keypair1_ = Keypair::generate();
        keypair2_ = Keypair::generate();
        
        dht1_ = std::make_unique<DHT>(keypair1_);
        dht2_ = std::make_unique<DHT>(keypair2_);
        
        dht1_->set_local_address("127.0.0.1", 8001);
        dht2_->set_local_address("127.0.0.1", 8002);
        
        // Set up message passing between DHTs (simulated network)
        dht1_->set_send_callback([this](const PeerInfo& peer, const std::vector<uint8_t>& data) {
            sent_messages_1_.push_back({peer, data});
            return true;
        });
        
        dht2_->set_send_callback([this](const PeerInfo& peer, const std::vector<uint8_t>& data) {
            sent_messages_2_.push_back({peer, data});
            return true;
        });
    }
    
    void deliver_messages() {
        // Deliver messages from dht1 to dht2
        for (const auto& [peer, data] : sent_messages_1_) {
            if (peer.id == dht2_->local_id()) {
                auto msg = DHTMessage::deserialize(data);
                if (msg) {
                    dht2_->handle_message(*msg);
                }
            }
        }
        sent_messages_1_.clear();
        
        // Deliver messages from dht2 to dht1
        for (const auto& [peer, data] : sent_messages_2_) {
            if (peer.id == dht1_->local_id()) {
                auto msg = DHTMessage::deserialize(data);
                if (msg) {
                    dht1_->handle_message(*msg);
                }
            }
        }
        sent_messages_2_.clear();
    }
    
    Keypair keypair1_, keypair2_;
    std::unique_ptr<DHT> dht1_, dht2_;
    std::vector<std::pair<PeerInfo, std::vector<uint8_t>>> sent_messages_1_;
    std::vector<std::pair<PeerInfo, std::vector<uint8_t>>> sent_messages_2_;
};

TEST_F(DHTTest, LocalIdFromKeypair) {
    auto expected_id = NodeId::from_public_key(keypair1_.public_key());
    EXPECT_EQ(dht1_->local_id(), expected_id);
}

TEST_F(DHTTest, LocalPeerInfo) {
    auto info = dht1_->local_peer_info();
    EXPECT_EQ(info.id, dht1_->local_id());
    EXPECT_EQ(info.address, "127.0.0.1");
    EXPECT_EQ(info.port, 8001);
}

TEST_F(DHTTest, BootstrapAddsPeersToRoutingTable) {
    std::vector<PeerInfo> bootstrap_nodes = {
        dht2_->local_peer_info()
    };
    
    dht1_->bootstrap(bootstrap_nodes);
    
    EXPECT_GE(dht1_->peer_count(), 1);
    EXPECT_TRUE(dht1_->routing_table().contains(dht2_->local_id()));
}

TEST_F(DHTTest, HandlePingReturnsPong) {
    DHTMessage ping;
    ping.type = MessageType::PING;
    ping.sender_id = dht2_->local_id();
    ping.transaction_id = 12345;
    ping.sender_address = "127.0.0.1";
    ping.sender_port = 8002;
    
    dht1_->handle_message(ping);
    
    ASSERT_EQ(sent_messages_1_.size(), 1);
    
    auto response = DHTMessage::deserialize(sent_messages_1_[0].second);
    ASSERT_TRUE(response.has_value());
    EXPECT_EQ(response->type, MessageType::PONG);
    EXPECT_EQ(response->transaction_id, 12345);
}

TEST_F(DHTTest, HandleFindNodeReturnsClosestPeers) {
    // Add some peers to dht1 via bootstrap
    std::vector<PeerInfo> peers;
    for (int i = 0; i < 5; ++i) {
        auto kp = Keypair::generate();
        PeerInfo peer{
            .id = NodeId::from_public_key(kp.public_key()),
            .address = "10.0.0." + std::to_string(i),
            .port = static_cast<uint16_t>(9000 + i),
            .last_seen = 1000
        };
        peers.push_back(peer);
    }
    dht1_->bootstrap(peers);
    sent_messages_1_.clear();  // Clear bootstrap messages
    
    DHTMessage find_node;
    find_node.type = MessageType::FIND_NODE;
    find_node.sender_id = dht2_->local_id();
    find_node.transaction_id = 11111;
    find_node.target_id = NodeId::random();
    find_node.sender_address = "127.0.0.1";
    find_node.sender_port = 8002;
    
    dht1_->handle_message(find_node);
    
    ASSERT_EQ(sent_messages_1_.size(), 1);
    
    auto response = DHTMessage::deserialize(sent_messages_1_[0].second);
    ASSERT_TRUE(response.has_value());
    EXPECT_EQ(response->type, MessageType::FIND_NODE_RESPONSE);
    EXPECT_FALSE(response->peers.empty());
}

TEST_F(DHTTest, StoreAndRetrieveValue) {
    std::vector<uint8_t> key = {0x01, 0x02, 0x03};
    std::vector<uint8_t> value = {0xAA, 0xBB, 0xCC, 0xDD};
    
    // Store locally (no peers)
    EXPECT_TRUE(dht1_->store(key, value));
    
    // Retrieve locally
    auto retrieved = dht1_->find_value(key);
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(*retrieved, value);
}

TEST_F(DHTTest, FindValueReturnsNulloptForMissingKey) {
    std::vector<uint8_t> key = {0xFF, 0xFF, 0xFF};
    
    auto result = dht1_->find_value(key);
    EXPECT_FALSE(result.has_value());
}

TEST_F(DHTTest, ValueCallbackIsInvoked) {
    bool callback_invoked = false;
    std::vector<uint8_t> received_key;
    std::vector<uint8_t> received_value;
    
    dht1_->set_value_callback([&](const std::vector<uint8_t>& key, const std::vector<uint8_t>& value) {
        callback_invoked = true;
        received_key = key;
        received_value = value;
    });
    
    DHTMessage store_msg;
    store_msg.type = MessageType::STORE;
    store_msg.sender_id = dht2_->local_id();
    store_msg.transaction_id = 22222;
    store_msg.key = {0x01, 0x02};
    store_msg.value = {0xAA, 0xBB};
    store_msg.sender_address = "127.0.0.1";
    store_msg.sender_port = 8002;
    
    dht1_->handle_message(store_msg);
    
    EXPECT_TRUE(callback_invoked);
    EXPECT_EQ(received_key, store_msg.key);
    EXPECT_EQ(received_value, store_msg.value);
}

TEST_F(DHTTest, RoutingTableUpdatedOnMessage) {
    EXPECT_FALSE(dht1_->routing_table().contains(dht2_->local_id()));
    
    DHTMessage ping;
    ping.type = MessageType::PING;
    ping.sender_id = dht2_->local_id();
    ping.transaction_id = 33333;
    ping.sender_address = "127.0.0.1";
    ping.sender_port = 8002;
    
    dht1_->handle_message(ping);
    
    EXPECT_TRUE(dht1_->routing_table().contains(dht2_->local_id()));
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
