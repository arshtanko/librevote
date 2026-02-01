#include <iostream>
#include <iomanip>
#include <thread>
#include <chrono>

#include "src/crypto/keypair.h"
#include "src/crypto/signature.h"
#include "src/crypto/hash.h"
#include "src/votes/ballot.h"
#include "src/votes/vote_storage.h"
#include "src/transport/p2p_node.h"

void print_hex(const std::string& label, const uint8_t* data, size_t len) {
    std::cout << label << ": ";
    for (size_t i = 0; i < len && i < 8; ++i) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) 
                  << static_cast<int>(data[i]);
    }
    std::cout << "..." << std::dec << std::endl;
}

void demo_voting_system() {
    std::cout << "\n=== Часть 1: Система голосования ===" << std::endl;
    std::cout << std::endl;

    // Create voters
    std::cout << "1. Создание избирателей..." << std::endl;
    auto voter1 = crypto::Keypair::generate();
    auto voter2 = crypto::Keypair::generate();
    auto voter3 = crypto::Keypair::generate();
    
    print_hex("   Избиратель 1", voter1.public_key().data(), voter1.public_key().size());
    print_hex("   Избиратель 2", voter2.public_key().data(), voter2.public_key().size());
    print_hex("   Избиратель 3", voter3.public_key().data(), voter3.public_key().size());
    std::cout << std::endl;

    // Create election
    std::cout << "2. Создание выборов..." << std::endl;
    auto election_opt = votes::ElectionBuilder()
        .set_name("Выборы председателя")
        .add_choice("Кандидат А")
        .add_choice("Кандидат Б")
        .add_choice("Кандидат В")
        .set_duration(3600)
        .add_eligible_voter(voter1.public_key())
        .add_eligible_voter(voter2.public_key())
        .add_eligible_voter(voter3.public_key())
        .build();

    if (!election_opt) {
        std::cerr << "Failed to create election" << std::endl;
        return;
    }
    
    auto election = *election_opt;
    std::cout << "   Название: " << election.name << std::endl;
    std::cout << "   Варианты: ";
    for (size_t i = 0; i < election.choices.size(); ++i) {
        std::cout << "[" << i << "] " << election.choices[i];
        if (i < election.choices.size() - 1) std::cout << ", ";
    }
    std::cout << std::endl;
    std::cout << "   Избирателей: " << election.eligible_voters.size() << std::endl;
    std::cout << std::endl;

    // Register election
    std::cout << "3. Регистрация выборов в хранилище..." << std::endl;
    votes::VoteStorage storage;
    storage.register_election(election);
    std::cout << "   OK" << std::endl;
    std::cout << std::endl;

    // Cast votes
    std::cout << "4. Голосование..." << std::endl;
    
    votes::Ballot ballot1(election.id, 0, voter1.public_key());
    ballot1.sign(voter1);
    auto result1 = storage.submit_ballot(ballot1);
    std::cout << "   Избиратель 1 -> Кандидат А: " 
              << votes::validation_result_to_string(result1) << std::endl;

    votes::Ballot ballot2(election.id, 1, voter2.public_key());
    ballot2.sign(voter2);
    auto result2 = storage.submit_ballot(ballot2);
    std::cout << "   Избиратель 2 -> Кандидат Б: " 
              << votes::validation_result_to_string(result2) << std::endl;

    votes::Ballot ballot3(election.id, 0, voter3.public_key());
    ballot3.sign(voter3);
    auto result3 = storage.submit_ballot(ballot3);
    std::cout << "   Избиратель 3 -> Кандидат А: " 
              << votes::validation_result_to_string(result3) << std::endl;
    std::cout << std::endl;

    // Count votes
    std::cout << "5. Подсчёт голосов..." << std::endl;
    auto results = storage.get_results(election.id);
    for (const auto& [choice, count] : results) {
        std::cout << "   " << choice << ": " << count << " голос(ов)" << std::endl;
    }
}

void demo_p2p_network() {
    std::cout << "\n=== Часть 2: P2P Сеть ===" << std::endl;
    std::cout << std::endl;

    // Create 3 P2P nodes
    std::cout << "1. Создание P2P узлов..." << std::endl;
    
    auto kp1 = crypto::Keypair::generate();
    auto kp2 = crypto::Keypair::generate();
    auto kp3 = crypto::Keypair::generate();

    network::P2PNode node1(kp1, 19001);
    network::P2PNode node2(kp2, 19002);
    network::P2PNode node3(kp3, 19003);

    std::cout << "   Узел 1: " << node1.local_id().to_hex().substr(0, 16) << "..." << std::endl;
    std::cout << "   Узел 2: " << node2.local_id().to_hex().substr(0, 16) << "..." << std::endl;
    std::cout << "   Узел 3: " << node3.local_id().to_hex().substr(0, 16) << "..." << std::endl;
    std::cout << std::endl;

    // Start nodes
    std::cout << "2. Запуск узлов..." << std::endl;
    
    if (!node1.start()) {
        std::cerr << "   Ошибка запуска узла 1" << std::endl;
        return;
    }
    std::cout << "   Узел 1: " << node1.local_address() << ":" << node1.local_port() << std::endl;

    if (!node2.start()) {
        std::cerr << "   Ошибка запуска узла 2" << std::endl;
        return;
    }
    std::cout << "   Узел 2: " << node2.local_address() << ":" << node2.local_port() << std::endl;

    if (!node3.start()) {
        std::cerr << "   Ошибка запуска узла 3" << std::endl;
        return;
    }
    std::cout << "   Узел 3: " << node3.local_address() << ":" << node3.local_port() << std::endl;
    std::cout << std::endl;

    // Set up message handlers
    std::atomic<int> messages_received{0};
    
    auto msg_handler = [&messages_received](const network::NodeId& sender, 
                                             const std::vector<uint8_t>& data) {
        messages_received++;
        std::string msg(data.begin(), data.end());
        std::cout << "   [Получено] от " << sender.to_hex().substr(0, 8) 
                  << "...: \"" << msg << "\"" << std::endl;
    };
    
    node1.set_message_callback(msg_handler);
    node2.set_message_callback(msg_handler);
    node3.set_message_callback(msg_handler);

    // Bootstrap: connect nodes to each other
    std::cout << "3. Подключение узлов (bootstrap)..." << std::endl;
    
    // Node 2 connects to Node 1
    node2.bootstrap(node1.local_peer_info().address + ":" + std::to_string(node1.local_peer_info().port));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Node 3 connects to Node 1
    node3.bootstrap(node1.local_peer_info().address + ":" + std::to_string(node1.local_peer_info().port));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    std::cout << "   Узел 1 знает пиров: " << node1.peer_count() << std::endl;
    std::cout << "   Узел 2 знает пиров: " << node2.peer_count() << std::endl;
    std::cout << "   Узел 3 знает пиров: " << node3.peer_count() << std::endl;
    std::cout << std::endl;

    // Test direct messaging
    std::cout << "4. Отправка прямых сообщений..." << std::endl;
    
    std::string test_msg = "Привет от узла 1!";
    std::vector<uint8_t> msg_data(test_msg.begin(), test_msg.end());
    
    // Node 1 sends to Node 2
    if (node1.send_to(node2.local_id(), msg_data)) {
        std::cout << "   Узел 1 -> Узел 2: отправлено" << std::endl;
    }
    
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    std::cout << std::endl;

    // Test broadcast
    std::cout << "5. Broadcast от узла 2..." << std::endl;
    
    std::string broadcast_msg = "Broadcast: Голосование началось!";
    std::vector<uint8_t> broadcast_data(broadcast_msg.begin(), broadcast_msg.end());
    node2.broadcast(broadcast_data);
    
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    std::cout << std::endl;

    // Test DHT store/find
    std::cout << "6. DHT: сохранение и поиск данных..." << std::endl;
    
    std::string key_str = "election_2024";
    std::string value_str = "Выборы активны, кандидаты: А, Б, В";
    
    std::vector<uint8_t> key(key_str.begin(), key_str.end());
    std::vector<uint8_t> value(value_str.begin(), value_str.end());
    
    // Node 1 stores data
    std::cout << "   Узел 1 сохраняет: \"" << key_str << "\" = \"" << value_str << "\"" << std::endl;
    node1.store(key, value);
    
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Node 3 tries to find the data (it's stored locally on node1, 
    // but in real network would propagate)
    std::cout << "   Узел 1 ищет ключ..." << std::endl;
    auto found = node1.find_value(key);
    if (found) {
        std::string found_str(found->begin(), found->end());
        std::cout << "   Найдено: \"" << found_str << "\"" << std::endl;
    } else {
        std::cout << "   Не найдено (ожидаемо в локальной сети)" << std::endl;
    }
    std::cout << std::endl;

    // Statistics
    std::cout << "7. Статистика..." << std::endl;
    std::cout << "   Узел 1: отправлено " << node1.bytes_sent() << " байт, "
              << "получено " << node1.bytes_received() << " байт" << std::endl;
    std::cout << "   Узел 2: отправлено " << node2.bytes_sent() << " байт, "
              << "получено " << node2.bytes_received() << " байт" << std::endl;
    std::cout << "   Узел 3: отправлено " << node3.bytes_sent() << " байт, "
              << "получено " << node3.bytes_received() << " байт" << std::endl;
    std::cout << "   Всего сообщений получено: " << messages_received.load() << std::endl;
    std::cout << std::endl;

    // Stop nodes
    std::cout << "8. Остановка узлов..." << std::endl;
    node1.stop();
    node2.stop();
    node3.stop();
    std::cout << "   OK" << std::endl;
}

void demo_integrated() {
    std::cout << "\n=== Часть 3: Интегрированная демонстрация ===" << std::endl;
    std::cout << "(Голосование через P2P сеть с 3 узлами)" << std::endl;
    std::cout << std::endl;

    // Create 3 voting nodes
    auto voter_kp1 = crypto::Keypair::generate();
    auto voter_kp2 = crypto::Keypair::generate();
    auto voter_kp3 = crypto::Keypair::generate();

    network::P2PNode node1(voter_kp1, 19011);
    network::P2PNode node2(voter_kp2, 19012);
    network::P2PNode node3(voter_kp3, 19013);

    // Each node has its own vote storage
    votes::VoteStorage storage1;
    votes::VoteStorage storage2;
    votes::VoteStorage storage3;

    // Create shared election
    auto election = votes::ElectionBuilder()
        .set_name("P2P Голосование")
        .add_choice("За")
        .add_choice("Против")
        .add_choice("Воздержался")
        .set_duration(3600)
        .add_eligible_voter(voter_kp1.public_key())
        .add_eligible_voter(voter_kp2.public_key())
        .add_eligible_voter(voter_kp3.public_key())
        .build();

    if (!election) {
        std::cerr << "Ошибка создания выборов" << std::endl;
        return;
    }

    storage1.register_election(*election);
    storage2.register_election(*election);
    storage3.register_election(*election);

    std::cout << "1. Выборы: " << election->name << std::endl;
    std::cout << "   ID: " << crypto::to_hex(election->id).substr(0, 16) << "..." << std::endl;
    std::cout << "   Избирателей: 3" << std::endl;
    std::cout << std::endl;

    // Start nodes
    node1.start();
    node2.start();
    node3.start();

    std::cout << "2. Узлы запущены:" << std::endl;
    std::cout << "   Узел 1 (Избиратель 1): порт " << node1.local_port() << std::endl;
    std::cout << "   Узел 2 (Избиратель 2): порт " << node2.local_port() << std::endl;
    std::cout << "   Узел 3 (Избиратель 3): порт " << node3.local_port() << std::endl;
    std::cout << std::endl;

    // Connect nodes in a chain: 2->1, 3->1
    node2.bootstrap(node1.local_peer_info().address + ":" + std::to_string(node1.local_port()));
    node3.bootstrap(node1.local_peer_info().address + ":" + std::to_string(node1.local_port()));
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    std::cout << "3. Сеть сформирована:" << std::endl;
    std::cout << "   Узел 1 знает пиров: " << node1.peer_count() << std::endl;
    std::cout << "   Узел 2 знает пиров: " << node2.peer_count() << std::endl;
    std::cout << "   Узел 3 знает пиров: " << node3.peer_count() << std::endl;
    std::cout << std::endl;

    // Handler for receiving ballots
    auto ballot_handler = [&](const network::NodeId& sender, 
                              const std::vector<uint8_t>& data,
                              votes::VoteStorage& storage,
                              const std::string& node_name) {
        auto ballot = votes::Ballot::from_bytes(data);
        if (ballot) {
            auto result = storage.submit_ballot(*ballot);
            std::cout << "   " << node_name << " получил бюллетень: " 
                      << votes::validation_result_to_string(result) << std::endl;
        }
    };

    node1.set_message_callback([&](const network::NodeId& s, const std::vector<uint8_t>& d) {
        ballot_handler(s, d, storage1, "Узел 1");
    });
    node2.set_message_callback([&](const network::NodeId& s, const std::vector<uint8_t>& d) {
        ballot_handler(s, d, storage2, "Узел 2");
    });
    node3.set_message_callback([&](const network::NodeId& s, const std::vector<uint8_t>& d) {
        ballot_handler(s, d, storage3, "Узел 3");
    });

    // Voter 1 votes and broadcasts
    std::cout << "4. Избиратель 1 голосует 'За' и рассылает бюллетень..." << std::endl;
    votes::Ballot ballot1(election->id, 0, voter_kp1.public_key());
    ballot1.sign(voter_kp1);
    storage1.submit_ballot(ballot1);
    node1.broadcast(ballot1.to_bytes());
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    std::cout << std::endl;

    // Voter 2 votes and broadcasts
    std::cout << "5. Избиратель 2 голосует 'Против' и рассылает бюллетень..." << std::endl;
    votes::Ballot ballot2(election->id, 1, voter_kp2.public_key());
    ballot2.sign(voter_kp2);
    storage2.submit_ballot(ballot2);
    node2.broadcast(ballot2.to_bytes());
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    std::cout << std::endl;

    // Voter 3 votes and broadcasts
    std::cout << "6. Избиратель 3 голосует 'За' и рассылает бюллетень..." << std::endl;
    votes::Ballot ballot3(election->id, 0, voter_kp3.public_key());
    ballot3.sign(voter_kp3);
    storage3.submit_ballot(ballot3);
    node3.broadcast(ballot3.to_bytes());
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    std::cout << std::endl;

    // Show results on all nodes
    std::cout << "7. Результаты на узлах:" << std::endl;
    
    auto print_results = [](const std::string& name, votes::VoteStorage& storage, 
                            const std::array<uint8_t, 32>& election_id) {
        std::cout << "   " << name << " видит:" << std::endl;
        auto results = storage.get_results(election_id);
        for (const auto& [choice, count] : results) {
            std::cout << "      " << choice << ": " << count << std::endl;
        }
    };

    print_results("Узел 1", storage1, election->id);
    print_results("Узел 2", storage2, election->id);
    print_results("Узел 3", storage3, election->id);
    std::cout << std::endl;

    // Cleanup
    node1.stop();
    node2.stop();
    node3.stop();
    
    std::cout << "   Узлы остановлены" << std::endl;
}

int main() {
    std::cout << "╔═══════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║                       LibreVote                           ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════════╝" << std::endl;

    // Initialize crypto
    if (!crypto::init()) {
        std::cerr << "Failed to initialize crypto" << std::endl;
        return 1;
    }

    // Run demos
    demo_voting_system();
    demo_p2p_network();
    demo_integrated();

    return 0;
}
