#pragma once

/// @file ss_cluster.hpp
/// @brief Shadowsocks server cluster with load balancing and health checks

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>
#include <random>
#include <thread>
#include <functional>
#include <fstream>

#include "shadowsocks.hpp"

namespace shadowsocks {

// ============================================================================
// Server Configuration
// ============================================================================

struct ServerConfig {
    std::string host;
    uint16_t port;
    std::string method;      // chacha20-ietf-poly1305, aes-256-gcm, etc
    std::string password;
    std::string tag;         // Human-readable name
    std::string country;
    
    // Derived
    std::unique_ptr<Session> session;
    
    void init_session() {
        session = std::make_unique<Session>(method, password);
    }
};

// ============================================================================
// Server Health State
// ============================================================================

struct ServerHealth {
    std::atomic<bool> healthy{true};
    std::atomic<uint64_t> latency_ms{0};
    std::atomic<uint64_t> total_connections{0};
    std::atomic<uint64_t> active_connections{0};
    std::atomic<uint64_t> failed_connections{0};
    std::atomic<uint64_t> bytes_sent{0};
    std::atomic<uint64_t> bytes_received{0};
    std::chrono::steady_clock::time_point last_check;
    std::chrono::steady_clock::time_point last_success;
};

// ============================================================================
// Load Balancing Policies
// ============================================================================

enum class LbPolicy {
    RoundRobin,
    LeastConnections,
    Random,
    WeightedLatency
};

// Forward declaration
std::vector<ServerConfig> load_servers_from_json(const std::string& json);

// ============================================================================
// Shadowsocks Cluster
// ============================================================================

class Cluster {
public:
    struct Config {
        LbPolicy lb_policy = LbPolicy::RoundRobin;
        std::chrono::seconds health_check_interval{30};
        std::chrono::milliseconds health_check_timeout{5000};
        uint32_t unhealthy_threshold = 3;
        uint32_t healthy_threshold = 1;
    };
    
    Cluster() : config_(), rr_index_(0), running_(false) {}
    
    explicit Cluster(const Config& config) 
        : config_(config), rr_index_(0), running_(false) {}
    
    ~Cluster() {
        stop_health_checks();
    }
    
    /// Add server to cluster
    void add_server(ServerConfig server) {
        std::lock_guard<std::mutex> lock(mutex_);
        server.init_session();
        servers_.push_back(std::move(server));
        health_.push_back(std::make_unique<ServerHealth>());
    }
    
    /// Get server count
    size_t server_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return servers_.size();
    }
    
    /// Select server based on LB policy
    /// Returns nullptr if no healthy servers available
    ServerConfig* select_server() {
        std::lock_guard<std::mutex> lock(mutex_);
        
        if (servers_.empty()) return nullptr;
        
        // Get list of healthy servers
        std::vector<size_t> healthy_indices;
        for (size_t i = 0; i < servers_.size(); ++i) {
            if (health_[i]->healthy.load()) {
                healthy_indices.push_back(i);
            }
        }
        
        if (healthy_indices.empty()) {
            // Fallback: try any server
            return &servers_[rr_index_.fetch_add(1) % servers_.size()];
        }
        
        size_t selected = 0;
        
        switch (config_.lb_policy) {
            case LbPolicy::RoundRobin: {
                size_t idx = rr_index_.fetch_add(1) % healthy_indices.size();
                selected = healthy_indices[idx];
                break;
            }
            
            case LbPolicy::LeastConnections: {
                uint64_t min_conn = UINT64_MAX;
                for (size_t i : healthy_indices) {
                    uint64_t conn = health_[i]->active_connections.load();
                    if (conn < min_conn) {
                        min_conn = conn;
                        selected = i;
                    }
                }
                break;
            }
            
            case LbPolicy::Random: {
                std::random_device rd;
                std::mt19937 gen(rd());
                std::uniform_int_distribution<size_t> dist(0, healthy_indices.size() - 1);
                selected = healthy_indices[dist(gen)];
                break;
            }
            
            case LbPolicy::WeightedLatency: {
                // Prefer servers with lower latency
                uint64_t min_latency = UINT64_MAX;
                for (size_t i : healthy_indices) {
                    uint64_t lat = health_[i]->latency_ms.load();
                    if (lat == 0) lat = 1; // Avoid division by zero
                    if (lat < min_latency) {
                        min_latency = lat;
                        selected = i;
                    }
                }
                break;
            }
        }
        
        health_[selected]->active_connections.fetch_add(1);
        health_[selected]->total_connections.fetch_add(1);
        
        return &servers_[selected];
    }
    
    /// Release connection (decrement active count)
    void release_connection(const ServerConfig* server, bool success = true) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (size_t i = 0; i < servers_.size(); ++i) {
            if (&servers_[i] == server) {
                health_[i]->active_connections.fetch_sub(1);
                if (!success) {
                    health_[i]->failed_connections.fetch_add(1);
                }
                break;
            }
        }
    }
    
    /// Record bytes transferred
    void record_bytes(const ServerConfig* server, uint64_t sent, uint64_t received) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (size_t i = 0; i < servers_.size(); ++i) {
            if (&servers_[i] == server) {
                health_[i]->bytes_sent.fetch_add(sent);
                health_[i]->bytes_received.fetch_add(received);
                break;
            }
        }
    }
    
    /// Start background health checks
    void start_health_checks(std::function<bool(const ServerConfig&, uint64_t&)> checker) {
        if (running_.exchange(true)) return;
        
        health_check_thread_ = std::thread([this, checker]() {
            while (running_.load()) {
                run_health_checks(checker);
                std::this_thread::sleep_for(config_.health_check_interval);
            }
        });
    }
    
    /// Stop health checks
    void stop_health_checks() {
        running_.store(false);
        if (health_check_thread_.joinable()) {
            health_check_thread_.join();
        }
    }
    
    /// Get cluster statistics
    struct Stats {
        size_t total_servers;
        size_t healthy_servers;
        uint64_t total_connections;
        uint64_t active_connections;
        uint64_t failed_connections;
        uint64_t total_bytes_sent;
        uint64_t total_bytes_received;
    };
    
    Stats get_stats() const {
        std::lock_guard<std::mutex> lock(mutex_);
        Stats stats{};
        stats.total_servers = servers_.size();
        
        for (const auto& h : health_) {
            if (h->healthy.load()) stats.healthy_servers++;
            stats.total_connections += h->total_connections.load();
            stats.active_connections += h->active_connections.load();
            stats.failed_connections += h->failed_connections.load();
            stats.total_bytes_sent += h->bytes_sent.load();
            stats.total_bytes_received += h->bytes_received.load();
        }
        
        return stats;
    }
    
    /// Total servers count
    size_t total_servers() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return servers_.size();
    }
    
    /// Healthy servers count
    size_t healthy_servers() const {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t count = 0;
        for (const auto& h : health_) {
            if (h->healthy.load()) count++;
        }
        return count;
    }
    
    /// Acquire connection (increment active count) - used when connection is being made
    void acquire_connection(ServerConfig* /*server*/) {
        // Already done in select_server, but can be used for external tracking
    }
    
    /// Load cluster from keys.json file
    void load_from_keys_json(const std::string& filepath, LbPolicy policy = LbPolicy::RoundRobin) {
        config_.lb_policy = policy;
        
        std::ifstream file(filepath);
        if (!file.is_open()) {
            throw std::runtime_error("Cannot open keys file: " + filepath);
        }
        
        std::string json((std::istreambuf_iterator<char>(file)),
                          std::istreambuf_iterator<char>());
        
        auto loaded = load_servers_from_json(json);
        for (auto& srv : loaded) {
            add_server(std::move(srv));
        }
    }
    
    /// Get individual server health
    struct ServerStats {
        std::string tag;
        std::string host;
        uint16_t port;
        bool healthy;
        uint64_t latency_ms;
        uint64_t active_connections;
        uint64_t total_connections;
        uint64_t failed_connections;
    };
    
    std::vector<ServerStats> get_server_stats() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ServerStats> result;
        
        for (size_t i = 0; i < servers_.size(); ++i) {
            result.push_back({
                servers_[i].tag,
                servers_[i].host,
                servers_[i].port,
                health_[i]->healthy.load(),
                health_[i]->latency_ms.load(),
                health_[i]->active_connections.load(),
                health_[i]->total_connections.load(),
                health_[i]->failed_connections.load()
            });
        }
        
        return result;
    }

private:
    void run_health_checks(std::function<bool(const ServerConfig&, uint64_t&)> checker) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        for (size_t i = 0; i < servers_.size(); ++i) {
            uint64_t latency = 0;
            bool success = checker(servers_[i], latency);
            
            health_[i]->last_check = std::chrono::steady_clock::now();
            
            if (success) {
                health_[i]->latency_ms.store(latency);
                health_[i]->last_success = std::chrono::steady_clock::now();
                health_[i]->healthy.store(true);
            } else {
                health_[i]->healthy.store(false);
            }
        }
    }
    
    Config config_;
    mutable std::mutex mutex_;
    std::vector<ServerConfig> servers_;
    std::vector<std::unique_ptr<ServerHealth>> health_;
    std::atomic<size_t> rr_index_;
    std::atomic<bool> running_;
    std::thread health_check_thread_;
};

// ============================================================================
// JSON Config Loader
// ============================================================================

inline std::vector<ServerConfig> load_servers_from_json(const std::string& json) {
    std::vector<ServerConfig> servers;
    
    size_t pos = 0;
    while ((pos = json.find("\"method\":", pos)) != std::string::npos) {
        ServerConfig cfg;
        
        // Parse method
        size_t start = json.find('"', pos + 9) + 1;
        size_t end = json.find('"', start);
        cfg.method = json.substr(start, end - start);
        
        // Parse password
        pos = json.find("\"password\":", end);
        start = json.find('"', pos + 11) + 1;
        end = json.find('"', start);
        cfg.password = json.substr(start, end - start);
        
        // Parse host
        pos = json.find("\"host\":", end);
        start = json.find('"', pos + 7) + 1;
        end = json.find('"', start);
        cfg.host = json.substr(start, end - start);
        
        // Parse port
        pos = json.find("\"port\":", end);
        start = pos + 7;
        while (json[start] == ' ' || json[start] == ':') start++;
        end = start;
        while (std::isdigit(json[end])) end++;
        cfg.port = static_cast<uint16_t>(std::stoi(json.substr(start, end - start)));
        
        // Parse tag
        pos = json.find("\"tag\":", end);
        start = json.find('"', pos + 6) + 1;
        end = json.find('"', start);
        cfg.tag = json.substr(start, end - start);
        
        // Parse country (optional)
        size_t country_pos = json.find("\"country\":", end);
        if (country_pos != std::string::npos && country_pos < json.find("\"method\":", end)) {
            start = json.find('"', country_pos + 10) + 1;
            end = json.find('"', start);
            cfg.country = json.substr(start, end - start);
        }
        
        servers.push_back(std::move(cfg));
        pos = end;
    }
    
    return servers;
}

} // namespace shadowsocks
