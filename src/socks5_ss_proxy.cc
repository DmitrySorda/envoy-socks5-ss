/// @file socks5_ss_proxy.cc
/// @brief Standalone SOCKS5 + Shadowsocks proxy server
/// @usage ./socks5_ss_proxy --listen 127.0.0.1:1080 --keys keys.json

#include <iostream>
#include <fstream>
#include <thread>
#include <atomic>
#include <csignal>
#include <cstring>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

#include "socks5/socks5.hpp"
#include "shadowsocks/shadowsocks.hpp"
#include "shadowsocks/ss_cluster.hpp"

namespace {

std::atomic<bool> g_running{true};

void signal_handler(int) {
    g_running = false;
}

class Connection {
public:
    Connection(int client_fd, shadowsocks::Cluster& cluster)
        : client_fd_(client_fd), cluster_(cluster) {}
    
    ~Connection() {
        if (client_fd_ >= 0) close(client_fd_);
        if (upstream_fd_ >= 0) close(upstream_fd_);
    }
    
    void handle() {
        try {
            // SOCKS5 handshake
            if (!doSocks5Handshake()) {
                return;
            }
            
            // Connect to SS server
            if (!connectToShadowsocks()) {
                sendSocks5Error(socks5::Reply::HostUnreachable);
                return;
            }
            
            // Send SOCKS5 success
            sendSocks5Success();
            
            // Relay data
            relay();
            
        } catch (const std::exception& e) {
            std::cerr << "Connection error: " << e.what() << std::endl;
        }
    }
    
private:
    bool doSocks5Handshake() {
        // Receive method selection
        std::vector<uint8_t> buf(256);
        ssize_t n = recv(client_fd_, buf.data(), buf.size(), 0);
        if (n <= 0) return false;
        
        socks5::MethodSelectionRequest methods;
        auto [result, consumed] = socks5::Parser::parse_method_selection(buf, methods);
        if (result != socks5::ParseResult::Complete) {
            std::cerr << "Failed to parse method selection" << std::endl;
            return false;
        }
        
        // Respond with NoAuth
        socks5::MethodSelectionResponse response;
        response.method = socks5::AuthMethod::NoAuth;
        auto response_data = response.serialize();
        send(client_fd_, response_data.data(), response_data.size(), 0);
        
        // Receive request (or use remaining data from first recv)
        std::vector<uint8_t> req_buf;
        if (consumed < static_cast<size_t>(n)) {
            // Request was already in first packet
            req_buf.assign(buf.begin() + consumed, buf.begin() + n);
        } else {
            req_buf.resize(256);
            n = recv(client_fd_, req_buf.data(), req_buf.size(), 0);
            if (n <= 0) return false;
            req_buf.resize(n);
        }
        
        auto [req_result, req_consumed] = socks5::Parser::parse_request(req_buf, request_);
        if (req_result != socks5::ParseResult::Complete) {
            std::cerr << "Failed to parse request" << std::endl;
            return false;
        }
        
        if (request_.command != socks5::Command::Connect) {
            sendSocks5Error(socks5::Reply::CommandNotSupported);
            return false;
        }
        
        // Extract target
        if (auto* domain = std::get_if<socks5::DomainName>(&request_.destination)) {
            target_host_ = domain->name;
        } else if (auto* ipv4 = std::get_if<socks5::IPv4Address>(&request_.destination)) {
            char addr_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, ipv4->octets.data(), addr_str, sizeof(addr_str));
            target_host_ = addr_str;
        } else if (auto* ipv6 = std::get_if<socks5::IPv6Address>(&request_.destination)) {
            char addr_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, ipv6->octets.data(), addr_str, sizeof(addr_str));
            target_host_ = addr_str;
        }
        target_port_ = request_.port;
        
        std::cout << "CONNECT " << target_host_ << ":" << target_port_ << std::endl;
        return true;
    }
    
    bool connectToShadowsocks() {
        // Select SS server from cluster
        server_ = cluster_.select_server();
        if (!server_) {
            std::cerr << "No healthy SS servers available" << std::endl;
            return false;
        }
        
        cluster_.acquire_connection(server_);
        
        // Connect to SS server
        struct addrinfo hints{}, *res;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        
        std::string port_str = std::to_string(server_->port);
        int rc = getaddrinfo(server_->host.c_str(), port_str.c_str(), &hints, &res);
        if (rc != 0) {
            std::cerr << "getaddrinfo failed: " << gai_strerror(rc) << std::endl;
            return false;
        }
        
        upstream_fd_ = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (upstream_fd_ < 0) {
            freeaddrinfo(res);
            return false;
        }
        
        if (connect(upstream_fd_, res->ai_addr, res->ai_addrlen) < 0) {
            std::cerr << "Failed to connect to SS server " << server_->host << ":" << server_->port << std::endl;
            freeaddrinfo(res);
            close(upstream_fd_);
            upstream_fd_ = -1;
            cluster_.release_connection(server_, false);
            return false;
        }
        freeaddrinfo(res);
        
        // Initialize encryption session
        if (server_->session) {
            auto [salt, cipher] = server_->session->create_encryptor();
            salt_ = std::move(salt);
            encryptor_ = std::move(cipher);
        } else {
            std::cerr << "Server session not initialized" << std::endl;
            return false;
        }
        
        // Send SS header with target address
        auto ss_header = shadowsocks::Session::encode_address_header(target_host_, target_port_);
        auto encrypted_header = shadowsocks::Session::encode_payload(*encryptor_, ss_header);
        
        // Prepend salt
        std::vector<uint8_t> first_packet;
        first_packet.insert(first_packet.end(), salt_.begin(), salt_.end());
        first_packet.insert(first_packet.end(), encrypted_header.begin(), encrypted_header.end());
        
        if (send(upstream_fd_, first_packet.data(), first_packet.size(), 0) < 0) {
            std::cerr << "Failed to send SS header" << std::endl;
            return false;
        }
        
        return true;
    }
    
    void sendSocks5Success() {
        socks5::ReplyMessage reply;
        reply.reply = socks5::Reply::Succeeded;
        reply.bind_address = socks5::IPv4Address{{0, 0, 0, 0}};
        reply.bind_port = 0;
        
        auto response = reply.serialize();
        send(client_fd_, response.data(), response.size(), 0);
    }
    
    void sendSocks5Error(socks5::Reply code) {
        socks5::ReplyMessage reply;
        reply.reply = code;
        reply.bind_address = socks5::IPv4Address{{0, 0, 0, 0}};
        reply.bind_port = 0;
        
        auto response = reply.serialize();
        send(client_fd_, response.data(), response.size(), 0);
    }
    
    void relay() {
        std::vector<uint8_t> buf(65536);
        struct pollfd fds[2];
        fds[0].fd = client_fd_;
        fds[0].events = POLLIN;
        fds[1].fd = upstream_fd_;
        fds[1].events = POLLIN;
        
        while (g_running) {
            int ret = poll(fds, 2, 1000);
            if (ret < 0) break;
            if (ret == 0) continue;
            
            // Client -> Upstream (encrypt)
            if (fds[0].revents & POLLIN) {
                ssize_t n = recv(client_fd_, buf.data(), buf.size(), 0);
                if (n <= 0) break;
                
                std::vector<uint8_t> data(buf.begin(), buf.begin() + n);
                auto encrypted = shadowsocks::Session::encode_payload(*encryptor_, data);
                
                if (send(upstream_fd_, encrypted.data(), encrypted.size(), 0) < 0) break;
            }
            
            // Upstream -> Client (decrypt)
            if (fds[1].revents & POLLIN) {
                ssize_t n = recv(upstream_fd_, buf.data(), buf.size(), 0);
                if (n <= 0) break;
                
                // Initialize decryptor on first response if needed
                if (!decryptor_) {
                    // First response contains salt
                    if (n < 32 + 2 + 16) {
                        std::cerr << "Response too short" << std::endl;
                        break;
                    }
                    std::vector<uint8_t> salt(buf.begin(), buf.begin() + 32);
                    decryptor_ = server_->session->create_decryptor(salt);
                    
                    // Decrypt rest
                    std::vector<uint8_t> encrypted(buf.begin() + 32, buf.begin() + n);
                    auto decrypted = shadowsocks::Session::decode_payloads(*decryptor_, encrypted);
                    
                    if (!decrypted.empty()) {
                        if (send(client_fd_, decrypted.data(), decrypted.size(), 0) < 0) break;
                    }
                } else {
                    std::vector<uint8_t> encrypted(buf.begin(), buf.begin() + n);
                    auto decrypted = shadowsocks::Session::decode_payloads(*decryptor_, encrypted);
                    
                    if (!decrypted.empty()) {
                        if (send(client_fd_, decrypted.data(), decrypted.size(), 0) < 0) break;
                    }
                }
            }
            
            // Check for errors
            if ((fds[0].revents & (POLLERR | POLLHUP)) || 
                (fds[1].revents & (POLLERR | POLLHUP))) {
                break;
            }
        }
        
        cluster_.release_connection(server_, true);
    }
    
    int client_fd_ = -1;
    int upstream_fd_ = -1;
    shadowsocks::Cluster& cluster_;
    shadowsocks::ServerConfig* server_ = nullptr;
    std::vector<uint8_t> salt_;
    std::unique_ptr<shadowsocks::AeadCipher> encryptor_;
    std::unique_ptr<shadowsocks::AeadCipher> decryptor_;
    socks5::Request request_;
    std::string target_host_;
    uint16_t target_port_ = 0;
};

class ProxyServer {
public:
    ProxyServer(const std::string& listen_addr, uint16_t listen_port, shadowsocks::Cluster& cluster)
        : cluster_(cluster), listen_port_(listen_port) {
        
        server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd_ < 0) {
            throw std::runtime_error("Failed to create socket");
        }
        
        int opt = 1;
        setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(listen_port);
        inet_pton(AF_INET, listen_addr.c_str(), &addr.sin_addr);
        
        if (bind(server_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(server_fd_);
            throw std::runtime_error("Failed to bind: " + std::string(strerror(errno)));
        }
        
        if (listen(server_fd_, 128) < 0) {
            close(server_fd_);
            throw std::runtime_error("Failed to listen");
        }
        
        std::cout << "SOCKS5-SS proxy listening on " << listen_addr << ":" << listen_port << std::endl;
    }
    
    ~ProxyServer() {
        if (server_fd_ >= 0) close(server_fd_);
    }
    
    void run() {
        while (g_running) {
            struct pollfd pfd{server_fd_, POLLIN, 0};
            if (poll(&pfd, 1, 1000) <= 0) continue;
            
            struct sockaddr_in client_addr{};
            socklen_t len = sizeof(client_addr);
            int client_fd = accept(server_fd_, (struct sockaddr*)&client_addr, &len);
            if (client_fd < 0) continue;
            
            // Handle in separate thread
            std::thread([this, client_fd]() {
                Connection conn(client_fd, cluster_);
                conn.handle();
            }).detach();
        }
    }
    
private:
    int server_fd_ = -1;
    shadowsocks::Cluster& cluster_;
    uint16_t listen_port_;
};

} // namespace

void print_usage(const char* prog) {
    std::cerr << "Usage: " << prog << " [options]\n"
              << "Options:\n"
              << "  --listen HOST:PORT   Listen address (default: 127.0.0.1:1080)\n"
              << "  --keys FILE          Path to keys.json\n"
              << "  --lb POLICY          Load balancing: round_robin, least_conn, random (default: round_robin)\n"
              << "  -h, --help           Show this help\n";
}

int main(int argc, char* argv[]) {
    std::string listen_host = "127.0.0.1";
    uint16_t listen_port = 1080;
    std::string keys_file = "keys.json";
    std::string lb_policy = "round_robin";
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--listen" && i + 1 < argc) {
            std::string addr = argv[++i];
            auto pos = addr.rfind(':');
            if (pos != std::string::npos) {
                listen_host = addr.substr(0, pos);
                listen_port = std::stoi(addr.substr(pos + 1));
            }
        } else if (arg == "--keys" && i + 1 < argc) {
            keys_file = argv[++i];
        } else if (arg == "--lb" && i + 1 < argc) {
            lb_policy = argv[++i];
        } else if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        }
    }
    
    // Setup signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    
    try {
        // Load cluster from keys.json
        shadowsocks::Cluster cluster;
        
        shadowsocks::LbPolicy policy = shadowsocks::LbPolicy::RoundRobin;
        if (lb_policy == "least_conn") policy = shadowsocks::LbPolicy::LeastConnections;
        else if (lb_policy == "random") policy = shadowsocks::LbPolicy::Random;
        
        cluster.load_from_keys_json(keys_file, policy);
        
        std::cout << "Loaded " << cluster.total_servers() << " SS servers from " << keys_file << std::endl;
        
        // Start proxy
        ProxyServer server(listen_host, listen_port, cluster);
        server.run();
        
        std::cout << "\nShutting down..." << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
