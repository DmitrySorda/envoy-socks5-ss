/// @file ss_filter.cc
/// @brief Envoy SOCKS5 + Shadowsocks Network Filter implementation

#include "ss_filter.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <fstream>
#include <netinet/in.h>
#include <poll.h>
#include <sstream>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "envoy/network/connection.h"
#include "source/common/network/address_impl.h"
#include "source/common/network/raw_buffer_socket.h"
#include "source/common/network/utility.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace Socks5Ss {

// ============================================================================
// SsFilter Implementation
// ============================================================================

SsFilter::SsFilter(SsFilterConfigSharedPtr config)
    : config_(std::move(config)) {
    ENVOY_LOG(debug, "SOCKS5-SS filter created");
    config_->stats->connections_total_.inc();
    config_->stats->active_connections_.inc();
}

SsFilter::~SsFilter() {
    cleanup();
}

void SsFilter::cleanup() {
    config_->stats->active_connections_.dec();
    
    if (selected_server_) {
        config_->cluster->record_bytes(selected_server_, bytes_sent_, bytes_received_);
        config_->cluster->release_connection(selected_server_, state_ == State::Connected);
        selected_server_ = nullptr;
    }
    
    if (upstream_connection_) {
        upstream_connection_->close(Network::ConnectionCloseType::NoFlush);
        upstream_connection_.reset();
    }
}

Network::FilterStatus SsFilter::onNewConnection() {
    ENVOY_LOG(debug, "SOCKS5-SS: new connection");
    read_callbacks_->connection().addConnectionCallbacks(*this);
    return Network::FilterStatus::Continue;
}

void SsFilter::initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) {
    read_callbacks_ = &callbacks;
}

Network::FilterStatus SsFilter::onData(Buffer::Instance& data, bool end_stream) {
    ENVOY_LOG(trace, "SOCKS5-SS: received {} bytes, end_stream={}", data.length(), end_stream);
    
    if (state_ == State::Connected && upstream_connection_) {
        // Forward to upstream with SS encryption
        std::vector<uint8_t> plaintext(data.length());
        data.copyOut(0, data.length(), plaintext.data());
        data.drain(data.length());
        
        auto encrypted = shadowsocks::Session::encode_payload(*encryptor_, plaintext);
        
        Buffer::OwnedImpl send_buf;
        send_buf.add(encrypted.data(), encrypted.size());
        upstream_connection_->write(send_buf, end_stream);
        
        bytes_sent_ += encrypted.size();
        config_->stats->bytes_sent_.add(encrypted.size());
        
        return Network::FilterStatus::StopIteration;
    }
    
    // Accumulate data for SOCKS5 handshake parsing
    pending_data_.move(data);
    processData(pending_data_);
    
    return Network::FilterStatus::StopIteration;
}

Network::FilterStatus SsFilter::onWrite(Buffer::Instance& /*data*/, bool /*end_stream*/) {
    return Network::FilterStatus::Continue;
}

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
    std::vector<uint8_t> raw_data(data.length());
    data.copyOut(0, data.length(), raw_data.data());
    
    socks5::MethodSelectionRequest request;
    auto [result, consumed] = socks5::Parser::parse_method_selection(raw_data, request);
    
    if (result == socks5::ParseResult::Incomplete) {
        return;
    }
    
    if (result == socks5::ParseResult::Invalid) {
        closeWithError(socks5::Reply::GeneralFailure);
        return;
    }
    
    data.drain(consumed);
    
    // Select NO_AUTH or USERNAME_PASSWORD based on config
    socks5::AuthMethod selected = socks5::AuthMethod::NoAcceptable;
    
    for (auto method : request.methods) {
        if (!config_->auth_required && method == socks5::AuthMethod::NoAuth) {
            selected = method;
            break;
        }
        if (config_->auth_required && method == socks5::AuthMethod::UsernamePassword) {
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
        read_callbacks_->connection().close(Network::ConnectionCloseType::FlushWrite);
        state_ = State::Error;
        return;
    }
    
    socks_session_.set_selected_method(selected);
    state_ = (selected == socks5::AuthMethod::NoAuth) 
             ? State::AwaitingRequest 
             : State::AwaitingAuth;
    
    if (data.length() > 0) {
        processData(data);
    }
}

void SsFilter::handleAuthentication(Buffer::Instance& data) {
    std::vector<uint8_t> raw_data(data.length());
    data.copyOut(0, data.length(), raw_data.data());
    
    socks5::AuthRequest request;
    auto [result, consumed] = socks5::Parser::parse_auth_request(raw_data, request);
    
    if (result == socks5::ParseResult::Incomplete) return;
    if (result == socks5::ParseResult::Invalid) {
        closeWithError(socks5::Reply::GeneralFailure);
        return;
    }
    
    data.drain(consumed);
    
    // TODO: Implement actual authentication
    bool authenticated = true;
    
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
        read_callbacks_->connection().close(Network::ConnectionCloseType::FlushWrite);
        state_ = State::Error;
    }
}

void SsFilter::handleRequest(Buffer::Instance& data) {
    std::vector<uint8_t> raw_data(data.length());
    data.copyOut(0, data.length(), raw_data.data());
    
    socks5::Request request;
    auto [result, consumed] = socks5::Parser::parse_request(raw_data, request);
    
    if (result == socks5::ParseResult::Incomplete) return;
    if (result == socks5::ParseResult::Invalid) {
        closeWithError(socks5::Reply::GeneralFailure);
        return;
    }
    
    data.drain(consumed);
    socks_session_.set_request(request);
    
    // Extract target
    std::visit([this](const auto& addr) {
        using T = std::decay_t<decltype(addr)>;
        if constexpr (std::is_same_v<T, socks5::DomainName>) {
            target_host_ = addr.name;
            target_is_domain_ = true;
        } else {
            target_host_ = addr.to_string();
            target_is_domain_ = false;
        }
    }, request.destination);
    target_port_ = request.port;
    
    ENVOY_LOG(info, "SOCKS5-SS: CONNECT to {}:{}", target_host_, target_port_);
    
    if (request.command != socks5::Command::Connect) {
        closeWithError(socks5::Reply::CommandNotSupported);
        return;
    }
    
    state_ = State::ConnectingUpstream;
    connectToSsServer();
}

void SsFilter::connectToSsServer() {
    // Select SS server from cluster
    selected_server_ = config_->cluster->select_server();
    
    if (!selected_server_) {
        ENVOY_LOG(error, "SOCKS5-SS: no healthy servers available");
        closeWithError(socks5::Reply::NetworkUnreachable);
        return;
    }
    
    ENVOY_LOG(debug, "SOCKS5-SS: selected server {} ({}:{})", 
              selected_server_->tag, selected_server_->host, selected_server_->port);
    
    connect_start_ = std::chrono::steady_clock::now();
    
    // Create upstream connection to SS server
    auto address = std::make_shared<Network::Address::Ipv4Instance>(
        selected_server_->host, selected_server_->port);
    
    upstream_connection_ = read_callbacks_->connection().dispatcher().createClientConnection(
        address,
        Network::Address::InstanceConstSharedPtr{},
        std::make_unique<Network::RawBufferSocket>(),
        nullptr,
        nullptr);
    
    // Set up callbacks for upstream
    upstream_connection_->addConnectionCallbacks(*this);
    upstream_connection_->connect();
}

void SsFilter::onUpstreamConnected() {
    auto elapsed = std::chrono::steady_clock::now() - connect_start_;
    auto latency_ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    
    config_->stats->upstream_latency_ms_.recordValue(latency_ms);
    config_->stats->upstream_connect_success_.inc();
    
    ENVOY_LOG(debug, "SOCKS5-SS: upstream connected in {}ms", latency_ms);
    
    // Create encryptor with salt
    auto [salt, enc] = selected_server_->session->create_encryptor();
    client_salt_ = std::move(salt);
    encryptor_ = std::move(enc);
    
    // Encode target address
    auto target_addr = shadowsocks::Session::encode_address(
        target_host_, target_port_, target_is_domain_);
    
    // First SS packet: salt + encrypted(target_address)
    auto encrypted_addr = shadowsocks::Session::encode_payload(*encryptor_, target_addr);
    
    Buffer::OwnedImpl send_buf;
    send_buf.add(client_salt_.data(), client_salt_.size());
    send_buf.add(encrypted_addr.data(), encrypted_addr.size());
    upstream_connection_->write(send_buf, false);
    
    bytes_sent_ += client_salt_.size() + encrypted_addr.size();
    salt_sent_ = true;
    
    // Send SOCKS5 success reply
    sendSocksReply(socks5::Reply::Succeeded);
    state_ = State::Connected;
    config_->stats->connections_success_.inc();
    
    // Forward any pending data
    if (pending_data_.length() > 0) {
        std::vector<uint8_t> plaintext(pending_data_.length());
        pending_data_.copyOut(0, pending_data_.length(), plaintext.data());
        pending_data_.drain(pending_data_.length());
        
        auto encrypted = shadowsocks::Session::encode_payload(*encryptor_, plaintext);
        
        Buffer::OwnedImpl fwd_buf;
        fwd_buf.add(encrypted.data(), encrypted.size());
        upstream_connection_->write(fwd_buf, false);
        
        bytes_sent_ += encrypted.size();
    }
}

void SsFilter::onUpstreamData(Buffer::Instance& data) {
    std::vector<uint8_t> raw_data(data.length());
    data.copyOut(0, data.length(), raw_data.data());
    data.drain(data.length());
    
    bytes_received_ += raw_data.size();
    config_->stats->bytes_received_.add(raw_data.size());
    
    size_t offset = 0;
    
    // First response contains salt
    if (!received_salt_) {
        size_t salt_size = selected_server_->session->salt_size();
        if (raw_data.size() < salt_size) {
            ENVOY_LOG(warn, "SOCKS5-SS: incomplete salt received");
            return;
        }
        
        std::vector<uint8_t> server_salt(raw_data.begin(), raw_data.begin() + salt_size);
        decryptor_ = selected_server_->session->create_decryptor(server_salt);
        received_salt_ = true;
        offset = salt_size;
    }
    
    // Decrypt remaining data
    if (offset < raw_data.size()) {
        std::vector<uint8_t> encrypted(raw_data.begin() + offset, raw_data.end());
        
        // AEAD chunk: length(2) + tag(16) + payload + tag(16)
        if (encrypted.size() >= 2 + 16) {
            try {
                // Decrypt length
                std::vector<uint8_t> len_chunk(encrypted.begin(), encrypted.begin() + 2 + 16);
                auto len_dec = decryptor_->decrypt(len_chunk);
                size_t payload_len = (len_dec[0] << 8) | len_dec[1];
                
                size_t payload_start = 2 + 16;
                if (encrypted.size() >= payload_start + payload_len + 16) {
                    std::vector<uint8_t> payload_chunk(
                        encrypted.begin() + payload_start,
                        encrypted.begin() + payload_start + payload_len + 16);
                    
                    auto plaintext = decryptor_->decrypt(payload_chunk);
                    
                    Buffer::OwnedImpl client_buf;
                    client_buf.add(plaintext.data(), plaintext.size());
                    read_callbacks_->connection().write(client_buf, false);
                }
            } catch (const std::exception& e) {
                ENVOY_LOG(warn, "SOCKS5-SS: decryption failed: {}", e.what());
            }
        }
    }
}

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
    read_callbacks_->connection().close(Network::ConnectionCloseType::FlushWrite);
    state_ = State::Error;
}

void SsFilter::onEvent(Network::ConnectionEvent event) {
    if (event == Network::ConnectionEvent::Connected) {
        onUpstreamConnected();
    } else if (event == Network::ConnectionEvent::RemoteClose ||
               event == Network::ConnectionEvent::LocalClose) {
        if (state_ == State::ConnectingUpstream) {
            config_->stats->upstream_connect_failed_.inc();
            closeWithError(socks5::Reply::ConnectionRefused);
        }
        cleanup();
    }
}

// ============================================================================
// ConfigManager Implementation
// ============================================================================

ConfigManager::ConfigManager(Event::Dispatcher& dispatcher,
                             SsFilterConfigSharedPtr config,
                             const std::string& config_path)
    : dispatcher_(dispatcher), config_(config), config_path_(config_path) {
    
    // Initial load
    loadServersFromFile(config_path);
    
    // Start health checks
    config_->cluster->start_health_checks(
        [this](const shadowsocks::ServerConfig& server, uint64_t& latency) {
            return checkServerHealth(server, latency);
        });
    
    // Start reload timer
    reload_timer_ = dispatcher_.createTimer([this]() {
        onReloadTimer();
    });
    reload_timer_->enableTimer(config_->config_reload_interval);
    
    ENVOY_LOG(info, "ConfigManager: loaded {} servers from {}", 
              config_->cluster->server_count(), config_path);
}

ConfigManager::~ConfigManager() {
    config_->cluster->stop_health_checks();
    if (reload_timer_) {
        reload_timer_->disableTimer();
    }
}

void ConfigManager::reload() {
    loadServersFromFile(config_path_);
}

std::shared_ptr<shadowsocks::Cluster> ConfigManager::cluster() const {
    return config_->cluster;
}

void ConfigManager::onReloadTimer() {
    // Check if file was modified
    struct stat st;
    if (stat(config_path_.c_str(), &st) == 0) {
        auto modified = std::chrono::system_clock::from_time_t(st.st_mtime);
        if (modified > last_modified_) {
            ENVOY_LOG(info, "ConfigManager: config file changed, reloading");
            loadServersFromFile(config_path_);
            last_modified_ = modified;
        }
    }
    
    // Update healthy servers gauge
    auto stats = config_->cluster->get_stats();
    config_->stats->healthy_servers_.set(stats.healthy_servers);
    
    // Re-arm timer
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
    
    // Create new cluster
    shadowsocks::Cluster::Config cluster_config;
    cluster_config.lb_policy = config_->lb_policy;
    cluster_config.health_check_interval = config_->health_check_interval;
    
    auto new_cluster = std::make_shared<shadowsocks::Cluster>(cluster_config);
    
    for (auto& server : servers) {
        new_cluster->add_server(std::move(server));
    }
    
    // Atomic swap (old cluster will be destroyed when no connections reference it)
    std::atomic_store(&config_->cluster, new_cluster);
    
    ENVOY_LOG(info, "ConfigManager: loaded {} servers", servers.size());
}

bool ConfigManager::checkServerHealth(const shadowsocks::ServerConfig& server, 
                                       uint64_t& latency) {
    // Simple TCP connect test with timeout
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;
    
    // Set non-blocking
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(server.port);
    inet_pton(AF_INET, server.host.c_str(), &addr.sin_addr);
    
    auto start = std::chrono::steady_clock::now();
    connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
    
    struct pollfd pfd = {sock, POLLOUT, 0};
    int ret = poll(&pfd, 1, 5000); // 5 second timeout
    
    close(sock);
    
    if (ret > 0 && (pfd.revents & POLLOUT)) {
        auto elapsed = std::chrono::steady_clock::now() - start;
        latency = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
        return true;
    }
    
    return false;
}

} // namespace Socks5Ss
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
