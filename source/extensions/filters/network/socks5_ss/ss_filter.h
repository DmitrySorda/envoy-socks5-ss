#pragma once

/**
 * @file ss_filter.h
 * @brief Envoy network filter: SOCKS5 proxy with Shadowsocks upstream encryption.
 */

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "envoy/buffer/buffer.h"
#include "envoy/event/dispatcher.h"
#include "envoy/event/timer.h"
#include "envoy/network/connection.h"
#include "envoy/network/filter.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/logger.h"

#include "socks5/socks5.hpp"
#include "shadowsocks/shadowsocks.hpp"
#include "shadowsocks/ss_cluster.hpp"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace Socks5Ss {

/**
 * All SOCKS5-SS filter stats. @see stats_macros.h
 */
#define SS_FILTER_STATS(COUNTER, GAUGE, HISTOGRAM) \
  COUNTER(connections_total)                       \
  COUNTER(connections_success)                     \
  COUNTER(connections_failed)                      \
  COUNTER(auth_success)                            \
  COUNTER(auth_failed)                             \
  COUNTER(upstream_connect_success)                \
  COUNTER(upstream_connect_failed)                 \
  COUNTER(upstream_retries)                        \
  COUNTER(circuit_breaker_open)                    \
  COUNTER(bytes_sent)                              \
  COUNTER(bytes_received)                          \
  GAUGE(active_connections, Accumulate)            \
  GAUGE(healthy_servers, NeverImport)              \
  HISTOGRAM(upstream_latency_ms, Milliseconds)

/**
 * Struct definition for all SOCKS5-SS filter stats. @see stats_macros.h
 */
struct SsFilterStats {
  SS_FILTER_STATS(GENERATE_COUNTER_STRUCT, GENERATE_GAUGE_STRUCT,
                  GENERATE_HISTOGRAM_STRUCT)
};

SsFilterStats generateStats(const std::string& prefix, Stats::Scope& scope);

/**
 * Configuration for the SOCKS5-SS network filter.
 */
struct SsFilterConfig {
  std::string stat_prefix{"socks5_ss"};
  bool auth_required{false};
  std::string servers_config_path;
  shadowsocks::LbPolicy lb_policy{shadowsocks::LbPolicy::WeightedLatency};
  std::chrono::seconds health_check_interval{30};
  std::chrono::seconds config_reload_interval{60};
  uint32_t max_retries{2};
  uint32_t max_connections_per_server{0};

  std::shared_ptr<shadowsocks::Cluster> cluster;
  std::shared_ptr<SsFilterStats> stats;
};

using SsFilterConfigSharedPtr = std::shared_ptr<SsFilterConfig>;

/**
 * SOCKS5 + Shadowsocks network filter.
 *
 * Implements the SOCKS5 handshake on the downstream side and tunnels traffic to
 * a Shadowsocks server selected by the configured load-balancing policy.
 * This is a terminal filter — it does not pass data further down the filter chain.
 */
class SsFilter : public Network::ReadFilter,
                 Logger::Loggable<Logger::Id::filter> {
public:
  explicit SsFilter(SsFilterConfigSharedPtr config);
  ~SsFilter() override;

  // Network::ReadFilter
  Network::FilterStatus onData(Buffer::Instance& data, bool end_stream) override;
  Network::FilterStatus onNewConnection() override;
  void initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) override;

  // Called by nested UpstreamReadFilter / callback structs.
  void onUpstreamData(Buffer::Instance& data, bool end_stream);
  void onUpstreamEvent(Network::ConnectionEvent event);
  void onDownstreamEvent(Network::ConnectionEvent event);

  // Flow control (called by watermark callbacks).
  void readDisableUpstream(bool disable);
  void readDisableDownstream(bool disable);

private:
  /**
   * Read filter installed on the upstream (Shadowsocks) connection so that
   * response data is delivered to the filter via onData() → onUpstreamData().
   */
  struct UpstreamReadFilter : public Network::ReadFilter {
    explicit UpstreamReadFilter(SsFilter& parent) : parent_(parent) {}

    Network::FilterStatus onData(Buffer::Instance& data, bool end_stream) override {
      parent_.onUpstreamData(data, end_stream);
      return Network::FilterStatus::StopIteration;
    }
    Network::FilterStatus onNewConnection() override {
      return Network::FilterStatus::Continue;
    }
    void initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) override {
      read_callbacks_ = &callbacks;
    }

    SsFilter& parent_;
    Network::ReadFilterCallbacks* read_callbacks_{};
  };

  /**
   * Connection callbacks for the upstream (Shadowsocks) connection.
   * Delivers connect/close events and upstream watermarks.
   */
  struct UpstreamCallbacks : public Network::ConnectionCallbacks {
    explicit UpstreamCallbacks(SsFilter& parent) : parent_(parent) {}

    void onEvent(Network::ConnectionEvent event) override {
      parent_.onUpstreamEvent(event);
    }
    void onAboveWriteBufferHighWatermark() override {
      parent_.readDisableDownstream(true);
    }
    void onBelowWriteBufferLowWatermark() override {
      parent_.readDisableDownstream(false);
    }

    SsFilter& parent_;
  };

  /**
   * Connection callbacks for the downstream (client) connection.
   * Delivers close events and downstream watermarks.
   */
  struct DownstreamCallbacks : public Network::ConnectionCallbacks {
    explicit DownstreamCallbacks(SsFilter& parent) : parent_(parent) {}

    void onEvent(Network::ConnectionEvent event) override {
      parent_.onDownstreamEvent(event);
    }
    void onAboveWriteBufferHighWatermark() override {
      parent_.readDisableUpstream(true);
    }
    void onBelowWriteBufferLowWatermark() override {
      parent_.readDisableUpstream(false);
    }

    SsFilter& parent_;
  };

  /** SOCKS5 handshake state machine. */
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
  void sendSocksReply(socks5::Reply reply);
  void closeWithError(socks5::Reply reply);
  void cleanup();

  SsFilterConfigSharedPtr config_;
  Network::ReadFilterCallbacks* read_callbacks_{};
  DownstreamCallbacks downstream_callbacks_;
  UpstreamCallbacks upstream_callbacks_;

  State state_{State::AwaitingMethods};
  socks5::Session socks_session_;
  Buffer::OwnedImpl pending_data_;

  // Shadowsocks upstream connection state.
  std::shared_ptr<shadowsocks::Cluster> active_cluster_;
  const shadowsocks::ServerConfig* selected_server_{};
  Network::ClientConnectionPtr upstream_connection_;
  std::shared_ptr<UpstreamReadFilter> upstream_read_filter_;
  std::unique_ptr<shadowsocks::AeadCipher> encryptor_;
  std::unique_ptr<shadowsocks::AeadCipher> decryptor_;
  std::vector<uint8_t> client_salt_;
  bool salt_sent_{false};
  bool received_salt_{false};

  // Upstream decode state — buffers partial SS AEAD frames.
  std::vector<uint8_t> upstream_pending_;
  shadowsocks::Session::DecodeContext decode_ctx_;

  // SOCKS5 CONNECT target.
  std::string target_host_;
  uint16_t target_port_{0};
  bool target_is_domain_{false};

  // Retry state.
  uint32_t retry_count_{0};

  // Idempotent cleanup guard.
  bool cleanup_done_{false};

  // Per-connection metrics.
  std::chrono::steady_clock::time_point connect_start_;
  uint64_t bytes_sent_{0};
  uint64_t bytes_received_{0};
};

/**
 * Configuration manager with hot-reload and async health checks.
 *
 * Periodically reloads the server list from a JSON file and runs async
 * TCP-connect probes to each server via the Envoy Dispatcher.
 */
class ConfigManager : Logger::Loggable<Logger::Id::config> {
public:
  ConfigManager(Event::Dispatcher& dispatcher, SsFilterConfigSharedPtr config,
                const std::string& config_path);
  ~ConfigManager();

  /** Force-reload configuration from disk. */
  void reload();

  /** Get current cluster snapshot. */
  std::shared_ptr<shadowsocks::Cluster> cluster() const;

private:
  /** Async TCP-connect health-check probe for a single server. */
  struct HealthProbe : public Network::ConnectionCallbacks {
    HealthProbe(ConfigManager& mgr, size_t idx) : manager(mgr), server_index(idx) {}

    // Network::ConnectionCallbacks
    void onEvent(Network::ConnectionEvent event) override;
    void onAboveWriteBufferHighWatermark() override {}
    void onBelowWriteBufferLowWatermark() override {}

    ConfigManager& manager;
    size_t server_index;
    Network::ClientConnectionPtr connection;
    Event::TimerPtr timeout_timer;
    std::chrono::steady_clock::time_point start;
    bool completed{false};
  };

  void onReloadTimer();
  void onHealthCheckTimer();
  void onProbeComplete();
  void clearProbes();
  void loadServersFromFile(const std::string& path);

  Event::Dispatcher& dispatcher_;
  SsFilterConfigSharedPtr config_;
  std::string config_path_;
  Event::TimerPtr reload_timer_;
  Event::TimerPtr health_check_timer_;
  std::vector<std::unique_ptr<HealthProbe>> active_probes_;
  std::chrono::system_clock::time_point last_modified_;
};

} // namespace Socks5Ss
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
