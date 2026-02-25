/// @file cluster_test.cc
/// @brief Standalone test for SS Cluster with load balancing and health checks

#include "shadowsocks/ss_cluster.hpp"
#include <iostream>
#include <map>
#include <fstream>
#include <sstream>
#include <chrono>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

/// TCP connect health check with timeout
bool tcp_health_check(const shadowsocks::ServerConfig& server, uint64_t& latency) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;
    
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(server.port);
    inet_pton(AF_INET, server.host.c_str(), &addr.sin_addr);
    
    auto start = std::chrono::steady_clock::now();
    connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    
    struct pollfd pfd = {sock, POLLOUT, 0};
    int ret = poll(&pfd, 1, 3000); // 3 second timeout
    
    close(sock);
    
    if (ret > 0 && (pfd.revents & POLLOUT)) {
        auto elapsed = std::chrono::steady_clock::now() - start;
        latency = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
        return true;
    }
    
    return false;
}

int main(int argc, char* argv[]) {
    std::string keys_path = "../gost-proxy/data/keys.json";
    if (argc > 1) {
        keys_path = argv[1];
    }
    
    std::cout << "=== SS Cluster Test ===" << std::endl;
    std::cout << "Loading servers from: " << keys_path << std::endl;
    
    // Load config
    std::ifstream f(keys_path);
    if (!f.is_open()) {
        std::cerr << "Failed to open " << keys_path << std::endl;
        return 1;
    }
    
    std::stringstream buf;
    buf << f.rdbuf();
    auto servers = shadowsocks::load_servers_from_json(buf.str());
    
    std::cout << "Found " << servers.size() << " servers" << std::endl;
    
    // Create cluster
    shadowsocks::Cluster::Config config;
    config.lb_policy = shadowsocks::LbPolicy::WeightedLatency;
    config.health_check_interval = std::chrono::seconds(5);
    
    shadowsocks::Cluster cluster(config);
    
    for (auto& server : servers) {
        cluster.add_server(std::move(server));
    }
    
    std::cout << "\n--- Running Health Checks ---" << std::endl;
    
    // Run one synchronous health-check pass (start_health_checks is now a
    // no-op; async checks are driven by Envoy's Dispatcher in production).
    cluster.run_health_check_iteration(tcp_health_check);
    
    // Print server stats
    auto server_stats = cluster.get_server_stats();
    for (const auto& s : server_stats) {
        std::cout << (s.healthy ? "✓" : "✗") << " "
                  << s.tag << " (" << s.host << ":" << s.port << ")"
                  << " latency=" << s.latency_ms << "ms"
                  << std::endl;
    }
    
    // Test load balancing
    std::cout << "\n--- Load Balancing Test (10 selections) ---" << std::endl;
    
    std::map<std::string, int> selection_count;
    
    for (int i = 0; i < 10; i++) {
        const auto* server = cluster.select_server();
        if (server) {
            selection_count[server->tag]++;
            cluster.release_connection(server, true);
        }
    }
    
    for (const auto& [tag, count] : selection_count) {
        std::cout << "  " << tag << ": " << count << " times" << std::endl;
    }
    
    // Print cluster stats
    auto stats = cluster.get_stats();
    std::cout << "\n--- Cluster Stats ---" << std::endl;
    std::cout << "  Total servers: " << stats.total_servers << std::endl;
    std::cout << "  Healthy servers: " << stats.healthy_servers << std::endl;
    std::cout << "  Total connections: " << stats.total_connections << std::endl;
    
    std::cout << "\n=== Test Complete ===" << std::endl;
    
    return 0;
}
