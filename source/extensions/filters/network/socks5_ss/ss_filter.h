#pragma once

/// @file ss_filter.h
/// @brief Envoy Network Filter with Shadowsocks upstream and load balancing

#include <string>
#include <memory>
#include <chrono>

#include "envoy/network/filter.h"
#include "envoy/network/connection.h"
#include "envoy/buffer/buffer.h"
#include "envoy/event/dispatcher.h"
#include "envoy/event/timer.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"

#include "source/common/common/logger.h"
#include "source/common/buffer/buffer_impl.h"

#include "socks5/socks5.hpp"
#include "shadowsocks/shadowsocks.hpp"
#include "shadowsocks/ss_cluster.hpp"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace Socks5Ss {

// ============================================================================
// Statistics
// ============================================================================

#define SS_FILTER_STATS(COUNTER, GAUGE, HISTOGRAM)                              \
    COUNTER(connections_total)                                                   \
    COUNTER(connections_success)                                                 \
    COUNTER(connections_failed)                                                  \
    COUNTER(auth_success)                                                        \
    COUNTER(auth_failed)                                                         \
    COUNTER(upstream_connect_success)                                            \
    COUNTER(upstream_connect_failed)                                             \
    COUNTER(bytes_sent)                                                          \
    COUNTER(bytes_received)                                                      \
    GAUGE(active_connections, Accumulate)                                        \
    GAUGE(healthy_servers, NeverImport)                                          \
    HISTOGRAM(upstream_latency_ms, Milliseconds)

struct SsFilterStats {
    SS_FILTER_STATS(GENERATE_COUNTER_STRUCT, GENERATE_GAUGE_STRUCT, GENERATE_HISTOGRAM_STRUCT)
};

inline SsFilterStats generateStats(const std::string& prefix, Stats::Scope& scope) {
    return {SS_FILTER_STATS(POOL_COUNTER_PREFIX(scope, prefix),
                           POOL_GAUGE_PREFIX(scope, prefix),
                           POOL_HISTOGRAM_PREFIX(scope, prefix))};
}

// ============================================================================
// Filter Configuration
// ============================================================================

struct SsFilterConfig {
    std::string stat_prefix = "socks5_ss";
    bool auth_required = false;
    std::string servers_config_path;  // Path to keys.json
    shadowsocks::LbPolicy lb_policy = shadowsocks::LbPolicy::WeightedLatency;
    std::chrono::seconds health_check_interval{30};
    std::chrono::seconds config_reload_interval{60};
    
    // Runtime cluster
    std::shared_ptr<shadowsocks::Cluster> cluster;
    std::shared_ptr<SsFilterStats> stats;
};

using SsFilterConfigSharedPtr = std::shared_ptr<SsFilterConfig>;

// ============================================================================
// SOCKS5 + Shadowsocks Network Filter
// ============================================================================

class SsFilter : public Network::Filter,
                 public Network::ConnectionCallbacks,
                 Logger::Loggable<Logger::Id::filter> {
public:
    explicit SsFilter(SsFilterConfigSharedPtr config);
    ~SsFilter() override;

    // Network::ReadFilter
    Network::FilterStatus onData(Buffer::Instance& data, bool end_stream) override;
    Network::FilterStatus onNewConnection() override;
    void initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) override;

    // Network::WriteFilter
    Network::FilterStatus onWrite(Buffer::Instance& data, bool end_stream) override;

    // Network::ConnectionCallbacks
    void onEvent(Network::ConnectionEvent event) override;
    void onAboveWriteBufferHighWatermark() override {}
    void onBelowWriteBufferLowWatermark() override {}

private:
    /// State machine states
    enum class State {
        AwaitingMethods,
        AwaitingAuth,
        AwaitingRequest,
        ConnectingUpstream,
        Connected,
        Error
    };
    
    void processData(Buffer::Instance& data);
    void handleMethodSelection(Buffer::Instance& data);
    void handleAuthentication(Buffer::Instance& data);
    void handleRequest(Buffer::Instance& data);
    void connectToSsServer();
    void onUpstreamConnected();
    void onUpstreamData(Buffer::Instance& data);
    void sendSocksReply(socks5::Reply reply);
    void closeWithError(socks5::Reply reply);
    void cleanup();
    
    SsFilterConfigSharedPtr config_;
    Network::ReadFilterCallbacks* read_callbacks_{};
    
    State state_{State::AwaitingMethods};
    socks5::Session socks_session_;
    Buffer::OwnedImpl pending_data_;
    
    // Shadowsocks connection
    const shadowsocks::ServerConfig* selected_server_{};
    Network::ClientConnectionPtr upstream_connection_;
    std::unique_ptr<shadowsocks::AeadCipher> encryptor_;
    std::unique_ptr<shadowsocks::AeadCipher> decryptor_;
    std::vector<uint8_t> client_salt_;
    bool salt_sent_{false};
    bool received_salt_{false};
    
    // Upstream decode state — buffers partial SS AEAD frames across onUpstreamData calls
    std::vector<uint8_t> upstream_pending_;
    shadowsocks::Session::DecodeContext decode_ctx_;
    
    // Target from SOCKS5 request
    std::string target_host_;
    uint16_t target_port_{0};
    bool target_is_domain_{false};
    
    // Stats
    std::chrono::steady_clock::time_point connect_start_;
    uint64_t bytes_sent_{0};
    uint64_t bytes_received_{0};
};

// ============================================================================
// Config Manager with Hot Reload
// ============================================================================

class ConfigManager : Logger::Loggable<Logger::Id::config> {
public:
    ConfigManager(Event::Dispatcher& dispatcher, 
                  SsFilterConfigSharedPtr config,
                  const std::string& config_path);
    
    ~ConfigManager();
    
    /// Force reload configuration
    void reload();
    
    /// Get current cluster
    std::shared_ptr<shadowsocks::Cluster> cluster() const;

private:
    void onReloadTimer();
    void loadServersFromFile(const std::string& path);
    bool checkServerHealth(const shadowsocks::ServerConfig& server, uint64_t& latency);
    
    Event::Dispatcher& dispatcher_;
    SsFilterConfigSharedPtr config_;
    std::string config_path_;
    Event::TimerPtr reload_timer_;
    std::chrono::system_clock::time_point last_modified_;
};

} // namespace Socks5Ss
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
