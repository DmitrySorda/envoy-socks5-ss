#pragma once

/// @file socks5_filter.h
/// @brief Envoy Network Filter for SOCKS5 protocol

#include <string>
#include <memory>

#include "envoy/network/filter.h"
#include "envoy/network/connection.h"
#include "envoy/buffer/buffer.h"
#include "envoy/upstream/cluster_manager.h"

#include "source/common/common/logger.h"
#include "source/common/buffer/buffer_impl.h"
#include "source/common/network/utility.h"

#include "socks5/socks5.hpp"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace Socks5 {

/// Filter configuration
struct Socks5FilterConfig {
    bool auth_required = false;
    std::string stat_prefix = "socks5";
    // TODO: Add user credentials map
};

using Socks5FilterConfigSharedPtr = std::shared_ptr<Socks5FilterConfig>;

/// SOCKS5 Network Filter
/// 
/// This filter implements a SOCKS5 proxy server that accepts incoming
/// SOCKS5 connections and proxies them to upstream clusters.
class Socks5Filter : public Network::Filter,
                     public Network::ConnectionCallbacks,
                     Logger::Loggable<Logger::Id::filter> {
public:
    explicit Socks5Filter(Socks5FilterConfigSharedPtr config,
                          Upstream::ClusterManager& cluster_manager);
    ~Socks5Filter() override = default;

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
    /// Process data based on current state
    void processData(Buffer::Instance& data);
    
    /// Handle method selection request
    void handleMethodSelection(Buffer::Instance& data);
    
    /// Handle authentication request
    void handleAuthentication(Buffer::Instance& data);
    
    /// Handle SOCKS5 request
    void handleRequest(Buffer::Instance& data);
    
    /// Create upstream connection to target
    void connectUpstream();
    
    /// Send reply to client
    void sendReply(socks5::Reply reply);
    
    /// Send error and close connection
    void sendErrorAndClose(socks5::Reply reply);
    
    Socks5FilterConfigSharedPtr config_;
    Upstream::ClusterManager& cluster_manager_;
    Network::ReadFilterCallbacks* read_callbacks_{};
    
    socks5::Session session_;
    Buffer::OwnedImpl pending_data_;
    
    // Upstream connection (for proxying)
    Network::ClientConnectionPtr upstream_connection_;
    bool upstream_connected_{false};
};

} // namespace Socks5
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
