/// @file socks5_filter.cc
/// @brief Envoy SOCKS5 Network Filter implementation

#include "src/filter/socks5_filter.h"

#include "envoy/network/connection.h"
#include "source/common/network/address_impl.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace Socks5 {

Socks5Filter::Socks5Filter(Socks5FilterConfigSharedPtr config,
                           Upstream::ClusterManager& cluster_manager)
    : config_(std::move(config)),
      cluster_manager_(cluster_manager),
      session_() {
    ENVOY_LOG(debug, "SOCKS5 filter created");
}

Network::FilterStatus Socks5Filter::onNewConnection() {
    ENVOY_LOG(debug, "SOCKS5: new connection");
    read_callbacks_->connection().addConnectionCallbacks(*this);
    return Network::FilterStatus::Continue;
}

void Socks5Filter::initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) {
    read_callbacks_ = &callbacks;
}

Network::FilterStatus Socks5Filter::onData(Buffer::Instance& data, bool end_stream) {
    ENVOY_LOG(trace, "SOCKS5: received {} bytes, end_stream={}", data.length(), end_stream);
    
    if (session_.state() == socks5::State::Connected) {
        // Already connected, forward data to upstream
        if (upstream_connection_ && upstream_connected_) {
            upstream_connection_->write(data, end_stream);
            data.drain(data.length());
        }
        return Network::FilterStatus::StopIteration;
    }
    
    // Accumulate data for parsing
    pending_data_.move(data);
    processData(pending_data_);
    
    return Network::FilterStatus::StopIteration;
}

Network::FilterStatus Socks5Filter::onWrite(Buffer::Instance& /*data*/, bool /*end_stream*/) {
    return Network::FilterStatus::Continue;
}

void Socks5Filter::processData(Buffer::Instance& data) {
    switch (session_.state()) {
        case socks5::State::AwaitingMethods:
            handleMethodSelection(data);
            break;
            
        case socks5::State::AwaitingAuth:
            handleAuthentication(data);
            break;
            
        case socks5::State::AwaitingRequest:
            handleRequest(data);
            break;
            
        case socks5::State::Connected:
        case socks5::State::Initial:
        case socks5::State::Error:
            break;
    }
}

void Socks5Filter::handleMethodSelection(Buffer::Instance& data) {
    // Convert Envoy buffer to vector for parser
    std::vector<uint8_t> raw_data(data.length());
    data.copyOut(0, data.length(), raw_data.data());
    
    socks5::MethodSelectionRequest request;
    auto [result, consumed] = socks5::Parser::parse_method_selection(raw_data, request);
    
    if (result == socks5::ParseResult::Incomplete) {
        ENVOY_LOG(trace, "SOCKS5: need more data for method selection");
        return;
    }
    
    if (result == socks5::ParseResult::Invalid) {
        ENVOY_LOG(warn, "SOCKS5: invalid method selection request");
        sendErrorAndClose(socks5::Reply::GeneralFailure);
        return;
    }
    
    data.drain(consumed);
    ENVOY_LOG(debug, "SOCKS5: client offered {} auth methods", request.methods.size());
    
    // Select authentication method
    socks5::AuthMethod selected = socks5::AuthMethod::NoAcceptable;
    
    if (config_->auth_required) {
        // Check if client supports username/password
        for (auto method : request.methods) {
            if (method == socks5::AuthMethod::UsernamePassword) {
                selected = method;
                break;
            }
        }
    } else {
        // Prefer no auth
        for (auto method : request.methods) {
            if (method == socks5::AuthMethod::NoAuth) {
                selected = method;
                break;
            }
        }
    }
    
    // Send method selection response
    socks5::MethodSelectionResponse response;
    response.method = selected;
    auto serialized = response.serialize();
    
    Buffer::OwnedImpl reply_buffer;
    reply_buffer.add(serialized.data(), serialized.size());
    read_callbacks_->connection().write(reply_buffer, false);
    
    if (selected == socks5::AuthMethod::NoAcceptable) {
        ENVOY_LOG(warn, "SOCKS5: no acceptable auth method");
        read_callbacks_->connection().close(Network::ConnectionCloseType::NoFlush);
        session_.set_state(socks5::State::Error);
        return;
    }
    
    session_.set_selected_method(selected);
    
    if (selected == socks5::AuthMethod::NoAuth) {
        session_.set_state(socks5::State::AwaitingRequest);
        ENVOY_LOG(debug, "SOCKS5: no auth required, awaiting request");
    } else {
        session_.set_state(socks5::State::AwaitingAuth);
        ENVOY_LOG(debug, "SOCKS5: awaiting authentication");
    }
    
    // Process remaining data if any
    if (data.length() > 0) {
        processData(data);
    }
}

void Socks5Filter::handleAuthentication(Buffer::Instance& data) {
    std::vector<uint8_t> raw_data(data.length());
    data.copyOut(0, data.length(), raw_data.data());
    
    socks5::AuthRequest request;
    auto [result, consumed] = socks5::Parser::parse_auth_request(raw_data, request);
    
    if (result == socks5::ParseResult::Incomplete) {
        return;
    }
    
    if (result == socks5::ParseResult::Invalid) {
        sendErrorAndClose(socks5::Reply::GeneralFailure);
        return;
    }
    
    data.drain(consumed);
    ENVOY_LOG(debug, "SOCKS5: auth request from user '{}'", request.username);
    
    // TODO: Implement actual authentication
    bool authenticated = true; // Placeholder
    
    socks5::AuthResponse response;
    response.status = authenticated ? 0x00 : 0x01;
    auto serialized = response.serialize();
    
    Buffer::OwnedImpl reply_buffer;
    reply_buffer.add(serialized.data(), serialized.size());
    read_callbacks_->connection().write(reply_buffer, false);
    
    if (authenticated) {
        session_.set_state(socks5::State::AwaitingRequest);
    } else {
        ENVOY_LOG(warn, "SOCKS5: authentication failed for user '{}'", request.username);
        read_callbacks_->connection().close(Network::ConnectionCloseType::NoFlush);
        session_.set_state(socks5::State::Error);
    }
}

void Socks5Filter::handleRequest(Buffer::Instance& data) {
    std::vector<uint8_t> raw_data(data.length());
    data.copyOut(0, data.length(), raw_data.data());
    
    socks5::Request request;
    auto [result, consumed] = socks5::Parser::parse_request(raw_data, request);
    
    if (result == socks5::ParseResult::Incomplete) {
        return;
    }
    
    if (result == socks5::ParseResult::Invalid) {
        sendErrorAndClose(socks5::Reply::GeneralFailure);
        return;
    }
    
    data.drain(consumed);
    session_.set_request(request);
    
    std::string dest_str = socks5::address_to_string(request.destination);
    ENVOY_LOG(info, "SOCKS5: {} to {}:{}", 
              request.command == socks5::Command::Connect ? "CONNECT" :
              request.command == socks5::Command::Bind ? "BIND" : "UDP_ASSOCIATE",
              dest_str, request.port);
    
    if (request.command != socks5::Command::Connect) {
        ENVOY_LOG(warn, "SOCKS5: unsupported command");
        sendErrorAndClose(socks5::Reply::CommandNotSupported);
        return;
    }
    
    // Establish upstream connection
    connectUpstream();
}

void Socks5Filter::connectUpstream() {
    const auto& request = session_.request();
    std::string dest = socks5::address_to_string(request.destination);
    
    // Create address based on destination type
    Network::Address::InstanceConstSharedPtr upstream_address;
    
    try {
        std::visit([&](const auto& addr) {
            using T = std::decay_t<decltype(addr)>;
            if constexpr (std::is_same_v<T, socks5::IPv4Address>) {
                upstream_address = std::make_shared<Network::Address::Ipv4Instance>(
                    addr.to_string(), request.port);
            } else if constexpr (std::is_same_v<T, socks5::IPv6Address>) {
                upstream_address = std::make_shared<Network::Address::Ipv6Instance>(
                    addr.to_string(), request.port);
            } else if constexpr (std::is_same_v<T, socks5::DomainName>) {
                // For domain names, we need DNS resolution
                // This is simplified - real impl would use async resolver
                upstream_address = Network::Utility::resolveUrl(
                    fmt::format("tcp://{}:{}", addr.name, request.port));
            }
        }, request.destination);
    } catch (const std::exception& e) {
        ENVOY_LOG(warn, "SOCKS5: failed to resolve address: {}", e.what());
        sendErrorAndClose(socks5::Reply::HostUnreachable);
        return;
    }
    
    ENVOY_LOG(debug, "SOCKS5: connecting to upstream {}", upstream_address->asString());
    
    // Create upstream connection
    upstream_connection_ = read_callbacks_->connection().dispatcher().createClientConnection(
        upstream_address,
        Network::Address::InstanceConstSharedPtr{},
        Network::Test::createRawBufferSocket(),
        nullptr,
        nullptr);
    
    // Set up upstream callbacks
    upstream_connection_->addConnectionCallbacks(*this);
    upstream_connection_->connect();
}

void Socks5Filter::sendReply(socks5::Reply reply) {
    socks5::ReplyMessage response;
    response.reply = reply;
    response.bind_address = socks5::IPv4Address{{0, 0, 0, 0}};
    response.bind_port = 0;
    
    auto serialized = response.serialize();
    
    Buffer::OwnedImpl reply_buffer;
    reply_buffer.add(serialized.data(), serialized.size());
    read_callbacks_->connection().write(reply_buffer, false);
}

void Socks5Filter::sendErrorAndClose(socks5::Reply reply) {
    sendReply(reply);
    read_callbacks_->connection().close(Network::ConnectionCloseType::FlushWrite);
    session_.set_state(socks5::State::Error);
}

void Socks5Filter::onEvent(Network::ConnectionEvent event) {
    if (event == Network::ConnectionEvent::Connected) {
        // Upstream connected successfully
        ENVOY_LOG(debug, "SOCKS5: upstream connected");
        upstream_connected_ = true;
        sendReply(socks5::Reply::Succeeded);
        session_.set_state(socks5::State::Connected);
        
        // Flush any pending data
        if (pending_data_.length() > 0) {
            upstream_connection_->write(pending_data_, false);
            pending_data_.drain(pending_data_.length());
        }
    } else if (event == Network::ConnectionEvent::RemoteClose ||
               event == Network::ConnectionEvent::LocalClose) {
        ENVOY_LOG(debug, "SOCKS5: connection closed");
        if (!upstream_connected_ && session_.state() == socks5::State::AwaitingRequest) {
            // Connection failed before we could connect
            sendErrorAndClose(socks5::Reply::ConnectionRefused);
        }
    }
}

} // namespace Socks5
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
