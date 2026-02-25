/**
 * @file ss_filter.cc
 * @brief SOCKS5 + Shadowsocks network filter implementation.
 */

#include "source/extensions/filters/network/socks5_ss/ss_filter.h"

#include <cstring>
#include <fstream>
#include <sstream>
#include <sys/stat.h>

#include "envoy/network/connection.h"

#include "source/common/network/address_impl.h"
#include "source/common/network/raw_buffer_socket.h"
#include "source/common/network/utility.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace Socks5Ss {

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

SsFilterStats generateStats(const std::string& prefix, Stats::Scope& scope) {
  return {SS_FILTER_STATS(POOL_COUNTER_PREFIX(scope, prefix),
                          POOL_GAUGE_PREFIX(scope, prefix),
                          POOL_HISTOGRAM_PREFIX(scope, prefix))};
}

// ---------------------------------------------------------------------------
// SsFilter — lifecycle
// ---------------------------------------------------------------------------

SsFilter::SsFilter(SsFilterConfigSharedPtr config)
    : config_(std::move(config)),
      downstream_callbacks_(*this),
      upstream_callbacks_(*this) {
  ENVOY_LOG(debug, "SOCKS5-SS filter created");
  config_->stats->connections_total_.inc();
  config_->stats->active_connections_.inc();
}

SsFilter::~SsFilter() { cleanup(); }

void SsFilter::cleanup() {
  if (cleanup_done_) {
    return;
  }
  cleanup_done_ = true;

  config_->stats->active_connections_.dec();

  if (selected_server_ && active_cluster_) {
    active_cluster_->record_bytes(selected_server_, bytes_sent_, bytes_received_);
    active_cluster_->release_connection(selected_server_,
                                        state_ == State::Connected);
    selected_server_ = nullptr;
  }

  if (upstream_connection_) {
    upstream_connection_->close(Network::ConnectionCloseType::NoFlush);
    upstream_connection_.reset();
  }

  upstream_read_filter_.reset();
  active_cluster_.reset();
}

// ---------------------------------------------------------------------------
// Network::ReadFilter
// ---------------------------------------------------------------------------

Network::FilterStatus SsFilter::onNewConnection() {
  ENVOY_LOG(debug, "SOCKS5-SS: new downstream connection");
  read_callbacks_->connection().addConnectionCallbacks(downstream_callbacks_);
  return Network::FilterStatus::Continue;
}

void SsFilter::initializeReadFilterCallbacks(
    Network::ReadFilterCallbacks& callbacks) {
  read_callbacks_ = &callbacks;
}

Network::FilterStatus SsFilter::onData(Buffer::Instance& data,
                                        bool end_stream) {
  ENVOY_LOG(trace, "SOCKS5-SS: downstream {} bytes, end_stream={}",
            data.length(), end_stream);

  if (state_ == State::Connected && upstream_connection_) {
    // Fast path — encrypt and forward to upstream.
    const uint64_t len = data.length();
    const uint8_t* ptr =
        static_cast<const uint8_t*>(data.linearize(len));

    auto encrypted =
        shadowsocks::Session::encode_payload(*encryptor_, ptr, len);
    data.drain(len);

    Buffer::OwnedImpl send_buf;
    send_buf.add(encrypted.data(), encrypted.size());
    upstream_connection_->write(send_buf, end_stream);

    bytes_sent_ += encrypted.size();
    config_->stats->bytes_sent_.add(encrypted.size());
    return Network::FilterStatus::StopIteration;
  }

  // Accumulate data for the SOCKS5 handshake state machine.
  pending_data_.move(data);
  processData(pending_data_);
  return Network::FilterStatus::StopIteration;
}

// ---------------------------------------------------------------------------
// SOCKS5 handshake
// ---------------------------------------------------------------------------

void SsFilter::processData(Buffer::Instance& data) {
  switch (state_) {
  case State::AwaitingMethods:
    handleMethodSelection(data);
    break;
  case State::AwaitingAuth:
    handleAuthentication(data);
    break;
  case State::AwaitingRequest:
    handleRequest(data);
    break;
  default:
    break;
  }
}

void SsFilter::handleMethodSelection(Buffer::Instance& data) {
  const uint64_t len = data.length();
  const uint8_t* ptr =
      static_cast<const uint8_t*>(data.linearize(len));
  std::vector<uint8_t> raw(ptr, ptr + len);

  socks5::MethodSelectionRequest request;
  auto [result, consumed] =
      socks5::Parser::parse_method_selection(raw, request);

  if (result == socks5::ParseResult::Incomplete) {
    return;
  }
  if (result == socks5::ParseResult::Invalid) {
    closeWithError(socks5::Reply::GeneralFailure);
    return;
  }
  data.drain(consumed);

  socks5::AuthMethod selected = socks5::AuthMethod::NoAcceptable;
  for (auto method : request.methods) {
    if (!config_->auth_required &&
        method == socks5::AuthMethod::NoAuth) {
      selected = method;
      break;
    }
    if (config_->auth_required &&
        method == socks5::AuthMethod::UsernamePassword) {
      selected = method;
      break;
    }
  }

  socks5::MethodSelectionResponse response;
  response.method = selected;
  auto serialized = response.serialize();

  Buffer::OwnedImpl reply_buf;
  reply_buf.add(serialized.data(), serialized.size());
  read_callbacks_->connection().write(reply_buf, false);

  if (selected == socks5::AuthMethod::NoAcceptable) {
    read_callbacks_->connection().close(
        Network::ConnectionCloseType::FlushWrite);
    state_ = State::Error;
    return;
  }

  socks_session_.set_selected_method(selected);
  state_ = (selected == socks5::AuthMethod::NoAuth) ? State::AwaitingRequest
                                                     : State::AwaitingAuth;
  if (data.length() > 0) {
    processData(data);
  }
}

void SsFilter::handleAuthentication(Buffer::Instance& data) {
  const uint64_t len = data.length();
  const uint8_t* ptr =
      static_cast<const uint8_t*>(data.linearize(len));
  std::vector<uint8_t> raw(ptr, ptr + len);

  socks5::AuthRequest request;
  auto [result, consumed] =
      socks5::Parser::parse_auth_request(raw, request);

  if (result == socks5::ParseResult::Incomplete) {
    return;
  }
  if (result == socks5::ParseResult::Invalid) {
    closeWithError(socks5::Reply::GeneralFailure);
    return;
  }
  data.drain(consumed);

  // TODO(DmitrySorda): implement real username/password verification.
  const bool authenticated = true;

  socks5::AuthResponse response;
  response.status = authenticated ? 0x00 : 0x01;
  auto serialized = response.serialize();

  Buffer::OwnedImpl reply_buf;
  reply_buf.add(serialized.data(), serialized.size());
  read_callbacks_->connection().write(reply_buf, false);

  if (authenticated) {
    config_->stats->auth_success_.inc();
    state_ = State::AwaitingRequest;
  } else {
    config_->stats->auth_failed_.inc();
    read_callbacks_->connection().close(
        Network::ConnectionCloseType::FlushWrite);
    state_ = State::Error;
  }
}

void SsFilter::handleRequest(Buffer::Instance& data) {
  const uint64_t len = data.length();
  const uint8_t* ptr =
      static_cast<const uint8_t*>(data.linearize(len));
  std::vector<uint8_t> raw(ptr, ptr + len);

  socks5::Request request;
  auto [result, consumed] = socks5::Parser::parse_request(raw, request);

  if (result == socks5::ParseResult::Incomplete) {
    return;
  }
  if (result == socks5::ParseResult::Invalid) {
    closeWithError(socks5::Reply::GeneralFailure);
    return;
  }
  data.drain(consumed);
  socks_session_.set_request(request);

  std::visit(
      [this](const auto& addr) {
        using T = std::decay_t<decltype(addr)>;
        if constexpr (std::is_same_v<T, socks5::DomainName>) {
          target_host_ = addr.name;
          target_is_domain_ = true;
        } else {
          target_host_ = addr.to_string();
          target_is_domain_ = false;
        }
      },
      request.destination);
  target_port_ = request.port;

  ENVOY_LOG(info, "SOCKS5-SS: CONNECT {}:{}", target_host_, target_port_);

  if (request.command != socks5::Command::Connect) {
    closeWithError(socks5::Reply::CommandNotSupported);
    return;
  }

  state_ = State::ConnectingUpstream;
  connectToSsServer();
}

// ---------------------------------------------------------------------------
// Upstream connection
// ---------------------------------------------------------------------------

void SsFilter::connectToSsServer() {
  // Hold a strong reference so the cluster (and the ServerConfig* inside it)
  // stays alive for our entire connection lifetime.
  active_cluster_ = std::atomic_load(&config_->cluster);

  selected_server_ = active_cluster_->select_server();
  if (!selected_server_) {
    ENVOY_LOG(error,
              "SOCKS5-SS: no healthy/available servers (retry {}/{})",
              retry_count_, config_->max_retries);
    config_->stats->circuit_breaker_open_.inc();
    closeWithError(socks5::Reply::NetworkUnreachable);
    return;
  }

  ENVOY_LOG(debug,
            "SOCKS5-SS: selected server {} ({}:{}) attempt {}",
            selected_server_->tag, selected_server_->host,
            selected_server_->port, retry_count_ + 1);

  connect_start_ = std::chrono::steady_clock::now();

  auto address = std::make_shared<Network::Address::Ipv4Instance>(
      selected_server_->host, selected_server_->port);

  upstream_connection_ =
      read_callbacks_->connection().dispatcher().createClientConnection(
          address, Network::Address::InstanceConstSharedPtr{},
          std::make_unique<Network::RawBufferSocket>(), nullptr, nullptr);

  // Separate callbacks: events go to UpstreamCallbacks, data to
  // UpstreamReadFilter — mirrors the Envoy tcp_proxy pattern.
  upstream_connection_->addConnectionCallbacks(upstream_callbacks_);

  upstream_read_filter_ = std::make_shared<UpstreamReadFilter>(*this);
  upstream_connection_->addReadFilter(upstream_read_filter_);

  upstream_connection_->connect();
}

void SsFilter::onUpstreamConnected() {
  auto elapsed = std::chrono::steady_clock::now() - connect_start_;
  auto latency_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();

  config_->stats->upstream_latency_ms_.recordValue(latency_ms);
  config_->stats->upstream_connect_success_.inc();
  ENVOY_LOG(debug, "SOCKS5-SS: upstream connected in {}ms", latency_ms);

  // Create encryptor with fresh salt.
  auto [salt, enc] = selected_server_->session->create_encryptor();
  client_salt_ = std::move(salt);
  encryptor_ = std::move(enc);

  // Encode SOCKS5 target address in the Shadowsocks wire format.
  auto target_addr = shadowsocks::Session::encode_address(
      target_host_, target_port_, target_is_domain_);

  // First SS packet: salt + encrypted(target_address).
  auto encrypted_addr =
      shadowsocks::Session::encode_payload(*encryptor_, target_addr);

  Buffer::OwnedImpl send_buf;
  send_buf.add(client_salt_.data(), client_salt_.size());
  send_buf.add(encrypted_addr.data(), encrypted_addr.size());
  upstream_connection_->write(send_buf, false);

  bytes_sent_ += client_salt_.size() + encrypted_addr.size();
  salt_sent_ = true;

  // Tell the downstream client that the tunnel is ready.
  sendSocksReply(socks5::Reply::Succeeded);
  state_ = State::Connected;
  config_->stats->connections_success_.inc();

  // Forward any data that arrived while we were connecting.
  if (pending_data_.length() > 0) {
    const uint64_t len = pending_data_.length();
    const uint8_t* ptr =
        static_cast<const uint8_t*>(pending_data_.linearize(len));

    auto encrypted =
        shadowsocks::Session::encode_payload(*encryptor_, ptr, len);
    pending_data_.drain(len);

    Buffer::OwnedImpl fwd_buf;
    fwd_buf.add(encrypted.data(), encrypted.size());
    upstream_connection_->write(fwd_buf, false);
    bytes_sent_ += encrypted.size();
  }
}

void SsFilter::onUpstreamData(Buffer::Instance& data,
                               bool /*end_stream*/) {
  const uint64_t incoming = data.length();
  const uint8_t* ptr =
      static_cast<const uint8_t*>(data.linearize(incoming));

  const size_t old_size = upstream_pending_.size();
  upstream_pending_.resize(old_size + incoming);
  std::memcpy(upstream_pending_.data() + old_size, ptr, incoming);
  data.drain(incoming);

  bytes_received_ += incoming;
  config_->stats->bytes_received_.add(incoming);

  // Extract salt from the first upstream response.
  if (!received_salt_) {
    const size_t salt_size = selected_server_->session->salt_size();
    if (upstream_pending_.size() < salt_size) {
      ENVOY_LOG(debug, "SOCKS5-SS: waiting for full salt ({}/{})",
                upstream_pending_.size(), salt_size);
      return;
    }

    std::vector<uint8_t> server_salt(upstream_pending_.begin(),
                                     upstream_pending_.begin() + salt_size);
    decryptor_ = selected_server_->session->create_decryptor(server_salt);
    received_salt_ = true;
    upstream_pending_.erase(upstream_pending_.begin(),
                            upstream_pending_.begin() + salt_size);
  }

  if (upstream_pending_.empty()) {
    return;
  }

  // Decode AEAD frames (handles partial frames across calls).
  try {
    auto plaintext = shadowsocks::Session::decode_payloads(
        *decryptor_, upstream_pending_, decode_ctx_);

    if (!plaintext.empty()) {
      Buffer::OwnedImpl client_buf;
      client_buf.add(plaintext.data(), plaintext.size());
      read_callbacks_->connection().write(client_buf, false);
    }
  } catch (const std::exception& e) {
    ENVOY_LOG(warn, "SOCKS5-SS: upstream decryption error: {}", e.what());
    read_callbacks_->connection().close(
        Network::ConnectionCloseType::NoFlush);
  }
}

// ---------------------------------------------------------------------------
// Event handling — split per Envoy convention (upstream vs. downstream)
// ---------------------------------------------------------------------------

void SsFilter::onUpstreamEvent(Network::ConnectionEvent event) {
  if (event == Network::ConnectionEvent::Connected) {
    onUpstreamConnected();
    return;
  }

  // RemoteClose / LocalClose
  if (state_ == State::ConnectingUpstream) {
    config_->stats->upstream_connect_failed_.inc();

    // Retry with a different server.
    if (retry_count_ < config_->max_retries) {
      retry_count_++;
      config_->stats->upstream_retries_.inc();
      ENVOY_LOG(warn,
                "SOCKS5-SS: upstream connect failed, retry {}/{}",
                retry_count_, config_->max_retries);

      if (selected_server_ && active_cluster_) {
        active_cluster_->release_connection(selected_server_,
                                            /*success=*/false);
        selected_server_ = nullptr;
      }

      upstream_connection_.reset();
      upstream_read_filter_.reset();
      connectToSsServer();
      return;
    }

    closeWithError(socks5::Reply::ConnectionRefused);
    return;
  }

  // Upstream disconnected after we were Connected.
  cleanup();
  read_callbacks_->connection().close(
      Network::ConnectionCloseType::FlushWrite);
}

void SsFilter::onDownstreamEvent(Network::ConnectionEvent event) {
  if (event == Network::ConnectionEvent::RemoteClose ||
      event == Network::ConnectionEvent::LocalClose) {
    cleanup();
  }
}

// ---------------------------------------------------------------------------
// Flow control
// ---------------------------------------------------------------------------

void SsFilter::readDisableUpstream(bool disable) {
  if (upstream_connection_) {
    upstream_connection_->readDisable(disable);
  }
}

void SsFilter::readDisableDownstream(bool disable) {
  read_callbacks_->connection().readDisable(disable);
}

// ---------------------------------------------------------------------------
// SOCKS5 replies
// ---------------------------------------------------------------------------

void SsFilter::sendSocksReply(socks5::Reply reply) {
  socks5::ReplyMessage response;
  response.reply = reply;
  response.bind_address = socks5::IPv4Address{{0, 0, 0, 0}};
  response.bind_port = 0;

  auto serialized = response.serialize();

  Buffer::OwnedImpl reply_buf;
  reply_buf.add(serialized.data(), serialized.size());
  read_callbacks_->connection().write(reply_buf, false);
}

void SsFilter::closeWithError(socks5::Reply reply) {
  config_->stats->connections_failed_.inc();
  sendSocksReply(reply);
  read_callbacks_->connection().close(
      Network::ConnectionCloseType::FlushWrite);
  state_ = State::Error;
}

// ===========================================================================
// ConfigManager
// ===========================================================================

ConfigManager::ConfigManager(Event::Dispatcher& dispatcher,
                             SsFilterConfigSharedPtr config,
                             const std::string& config_path)
    : dispatcher_(dispatcher),
      config_(std::move(config)),
      config_path_(config_path) {
  // Initial server load.
  loadServersFromFile(config_path_);

  // Periodic config-file change detection.
  reload_timer_ = dispatcher_.createTimer([this]() { onReloadTimer(); });
  reload_timer_->enableTimer(config_->config_reload_interval);

  // Periodic async health checks.
  health_check_timer_ =
      dispatcher_.createTimer([this]() { onHealthCheckTimer(); });
  health_check_timer_->enableTimer(config_->health_check_interval);

  ENVOY_LOG(info, "ConfigManager: loaded {} servers from {}",
            config_->cluster->server_count(), config_path_);
}

ConfigManager::~ConfigManager() {
  clearProbes();
  if (reload_timer_) {
    reload_timer_->disableTimer();
  }
  if (health_check_timer_) {
    health_check_timer_->disableTimer();
  }
}

void ConfigManager::clearProbes() {
  for (auto& probe : active_probes_) {
    if (probe && !probe->completed && probe->connection) {
      probe->completed = true;
      if (probe->timeout_timer) {
        probe->timeout_timer->disableTimer();
      }
      probe->connection->close(Network::ConnectionCloseType::NoFlush);
    }
  }
  active_probes_.clear();
}

void ConfigManager::reload() { loadServersFromFile(config_path_); }

std::shared_ptr<shadowsocks::Cluster> ConfigManager::cluster() const {
  return config_->cluster;
}

// ---------------------------------------------------------------------------
// Async health checks
// ---------------------------------------------------------------------------

void ConfigManager::HealthProbe::onEvent(
    Network::ConnectionEvent event) {
  if (completed) {
    return;
  }
  completed = true;

  if (timeout_timer) {
    timeout_timer->disableTimer();
  }

  const bool success = (event == Network::ConnectionEvent::Connected);
  uint64_t latency_ms = 0;
  if (success) {
    auto elapsed = std::chrono::steady_clock::now() - start;
    latency_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(elapsed)
            .count());
  }

  manager.config_->cluster->update_server_health(server_index, success,
                                                  latency_ms);
  if (connection) {
    connection->close(Network::ConnectionCloseType::NoFlush);
  }

  manager.onProbeComplete();
}

void ConfigManager::onHealthCheckTimer() {
  clearProbes();

  auto cluster = config_->cluster;
  const size_t count = cluster->server_count();

  for (size_t i = 0; i < count; ++i) {
    const auto* server = cluster->server_at(i);
    if (server == nullptr) {
      continue;
    }

    auto probe = std::make_unique<HealthProbe>(*this, i);
    probe->start = std::chrono::steady_clock::now();

    auto address = std::make_shared<Network::Address::Ipv4Instance>(
        server->host, server->port);

    probe->connection = dispatcher_.createClientConnection(
        address, Network::Address::InstanceConstSharedPtr{},
        std::make_unique<Network::RawBufferSocket>(), nullptr, nullptr);

    const size_t probe_idx = active_probes_.size();
    probe->timeout_timer = dispatcher_.createTimer([this, probe_idx]() {
      if (probe_idx < active_probes_.size()) {
        auto& p = active_probes_[probe_idx];
        if (p && !p->completed) {
          p->completed = true;
          config_->cluster->update_server_health(p->server_index, false,
                                                 0);
          if (p->connection) {
            p->connection->close(Network::ConnectionCloseType::NoFlush);
          }
          onProbeComplete();
        }
      }
    });
    probe->timeout_timer->enableTimer(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            config_->health_check_interval) /
        2);

    probe->connection->addConnectionCallbacks(*probe);
    probe->connection->connect();

    active_probes_.push_back(std::move(probe));
  }

  // No servers — re-arm immediately.
  if (active_probes_.empty()) {
    health_check_timer_->enableTimer(config_->health_check_interval);
  }
}

void ConfigManager::onProbeComplete() {
  for (const auto& probe : active_probes_) {
    if (probe && !probe->completed) {
      return;
    }
  }

  auto stats = config_->cluster->get_stats();
  config_->stats->healthy_servers_.set(stats.healthy_servers);

  // Defer cleanup to avoid destroying the probe while in its callback.
  dispatcher_.post([this]() {
    clearProbes();
    health_check_timer_->enableTimer(config_->health_check_interval);
  });
}

// ---------------------------------------------------------------------------
// Config reload
// ---------------------------------------------------------------------------

void ConfigManager::onReloadTimer() {
  struct stat st;
  if (stat(config_path_.c_str(), &st) == 0) {
    auto modified = std::chrono::system_clock::from_time_t(st.st_mtime);
    if (modified > last_modified_) {
      ENVOY_LOG(info, "ConfigManager: config file changed, reloading");
      loadServersFromFile(config_path_);
      last_modified_ = modified;
    }
  }

  auto stats = config_->cluster->get_stats();
  config_->stats->healthy_servers_.set(stats.healthy_servers);

  reload_timer_->enableTimer(config_->config_reload_interval);
}

void ConfigManager::loadServersFromFile(const std::string& path) {
  std::ifstream f(path);
  if (!f.is_open()) {
    ENVOY_LOG(error, "ConfigManager: failed to open {}", path);
    return;
  }

  std::stringstream buf;
  buf << f.rdbuf();
  std::string json = buf.str();

  auto servers = shadowsocks::load_servers_from_json(json);

  shadowsocks::Cluster::Config cluster_config;
  cluster_config.lb_policy = config_->lb_policy;
  cluster_config.health_check_interval = config_->health_check_interval;
  cluster_config.max_connections_per_server =
      config_->max_connections_per_server;

  auto new_cluster =
      std::make_shared<shadowsocks::Cluster>(cluster_config);
  for (auto& server : servers) {
    new_cluster->add_server(std::move(server));
  }

  // Atomic swap — old cluster stays alive via active_cluster_ in SsFilter
  // instances until those connections close.
  std::atomic_store(&config_->cluster, new_cluster);

  ENVOY_LOG(info, "ConfigManager: loaded {} servers", servers.size());
}

} // namespace Socks5Ss
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
