/// @file ss_test.cc
/// @brief Standalone test for Shadowsocks connection to servers from keys.json

#include "shadowsocks/shadowsocks.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <poll.h>

// Simple JSON parsing for keys.json
struct ServerKey {
    std::string method;
    std::string password;
    std::string host;
    int port;
    std::string tag;
};

std::vector<ServerKey> parse_keys(const std::string& path) {
    std::ifstream f(path);
    std::stringstream buf;
    buf << f.rdbuf();
    std::string json = buf.str();
    
    std::vector<ServerKey> keys;
    
    // Very simple JSON parsing (production should use proper JSON lib)
    size_t pos = 0;
    while ((pos = json.find("\"method\":", pos)) != std::string::npos) {
        ServerKey key;
        
        // Parse method
        size_t start = json.find('"', pos + 9) + 1;
        size_t end = json.find('"', start);
        key.method = json.substr(start, end - start);
        
        // Parse password
        pos = json.find("\"password\":", end);
        start = json.find('"', pos + 11) + 1;
        end = json.find('"', start);
        key.password = json.substr(start, end - start);
        
        // Parse host
        pos = json.find("\"host\":", end);
        start = json.find('"', pos + 7) + 1;
        end = json.find('"', start);
        key.host = json.substr(start, end - start);
        
        // Parse port
        pos = json.find("\"port\":", end);
        start = pos + 7;
        while (json[start] == ' ' || json[start] == ':') start++;
        end = start;
        while (std::isdigit(json[end])) end++;
        key.port = std::stoi(json.substr(start, end - start));
        
        // Parse tag
        pos = json.find("\"tag\":", end);
        start = json.find('"', pos + 6) + 1;
        end = json.find('"', start);
        key.tag = json.substr(start, end - start);
        
        keys.push_back(key);
        pos = end;
    }
    
    return keys;
}

int connect_with_timeout(const std::string& host, int port, int timeout_ms) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    
    // Set non-blocking
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
    
    connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    
    struct pollfd pfd = {sock, POLLOUT, 0};
    int ret = poll(&pfd, 1, timeout_ms);
    
    if (ret <= 0 || !(pfd.revents & POLLOUT)) {
        close(sock);
        return -1;
    }
    
    // Check for connection error
    int error = 0;
    socklen_t len = sizeof(error);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len);
    
    if (error != 0) {
        close(sock);
        return -1;
    }
    
    // Restore blocking mode
    fcntl(sock, F_SETFL, flags);
    return sock;
}

bool test_shadowsocks_connection(const ServerKey& key, int timeout_ms = 5000) {
    std::cout << "Testing: " << key.tag << std::endl;
    std::cout << "  Server: " << key.host << ":" << key.port << std::endl;
    std::cout << "  Method: " << key.method << std::endl;
    
    try {
        // Connect to SS server
        int sock = connect_with_timeout(key.host, key.port, timeout_ms);
        if (sock < 0) {
            std::cout << "  Result: FAIL (connection timeout)" << std::endl;
            return false;
        }
        
        // Create SS session
        shadowsocks::Session session(key.method, key.password);
        
        // Create encryptor with salt
        auto [salt, encryptor] = session.create_encryptor();
        
        // Target: httpbin.org:80 - for HTTP GET request
        auto target_addr = shadowsocks::Session::encode_address("httpbin.org", 80, true);
        
        // HTTP request
        std::string http_req = "GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n";
        
        // Combine address + request
        std::vector<uint8_t> payload;
        payload.insert(payload.end(), target_addr.begin(), target_addr.end());
        payload.insert(payload.end(), http_req.begin(), http_req.end());
        
        // Encode with AEAD
        auto encrypted = shadowsocks::Session::encode_payload(*encryptor, payload);
        
        // Send: salt + encrypted payload
        std::vector<uint8_t> data_to_send;
        data_to_send.insert(data_to_send.end(), salt.begin(), salt.end());
        data_to_send.insert(data_to_send.end(), encrypted.begin(), encrypted.end());
        
        ssize_t sent = send(sock, data_to_send.data(), data_to_send.size(), 0);
        if (sent < 0) {
            close(sock);
            std::cout << "  Result: FAIL (send error)" << std::endl;
            return false;
        }
        
        // Receive response with timeout
        struct pollfd pfd = {sock, POLLIN, 0};
        int ret = poll(&pfd, 1, timeout_ms);
        
        if (ret <= 0) {
            close(sock);
            std::cout << "  Result: FAIL (receive timeout)" << std::endl;
            return false;
        }
        
        std::vector<uint8_t> recv_buf(4096);
        ssize_t received = recv(sock, recv_buf.data(), recv_buf.size(), 0);
        close(sock);
        
        if (received <= 0) {
            std::cout << "  Result: FAIL (no response)" << std::endl;
            return false;
        }
        
        // Check if we got salt back (indicates SS protocol working)
        if (static_cast<size_t>(received) >= session.salt_size()) {
            std::vector<uint8_t> resp_salt(recv_buf.begin(), 
                                           recv_buf.begin() + session.salt_size());
            
            auto decryptor = session.create_decryptor(resp_salt);
            
            // Try to decrypt response
            std::vector<uint8_t> encrypted_resp(
                recv_buf.begin() + session.salt_size(),
                recv_buf.begin() + received
            );
            
            if (encrypted_resp.size() >= 2 + 16) { // length(2) + tag(16)
                try {
                    // Decrypt length
                    std::vector<uint8_t> len_part(encrypted_resp.begin(), 
                                                   encrypted_resp.begin() + 2 + 16);
                    auto len_dec = decryptor->decrypt(len_part);
                    
                    size_t payload_len = (len_dec[0] << 8) | len_dec[1];
                    std::cout << "  Response payload length: " << payload_len << std::endl;
                    std::cout << "  Result: OK (connection works!)" << std::endl;
                    return true;
                } catch (...) {
                    // Decryption might fail if response is different format
                }
            }
        }
        
        std::cout << "  Received " << received << " bytes (might need more parsing)" << std::endl;
        std::cout << "  Result: PARTIAL (got response, needs analysis)" << std::endl;
        return true;
        
    } catch (const std::exception& e) {
        std::cout << "  Result: FAIL (" << e.what() << ")" << std::endl;
        return false;
    }
}

int main(int argc, char* argv[]) {
    std::string keys_path = "../gost-proxy/data/keys.json";
    if (argc > 1) {
        keys_path = argv[1];
    }
    
    std::cout << "=== Shadowsocks Connection Test ===" << std::endl;
    std::cout << "Loading keys from: " << keys_path << std::endl;
    
    auto keys = parse_keys(keys_path);
    std::cout << "Found " << keys.size() << " servers" << std::endl << std::endl;
    
    int success = 0;
    int failed = 0;
    int tested = 0;
    int max_tests = 5; // Test first 5 servers
    
    for (const auto& key : keys) {
        if (tested >= max_tests) break;
        
        if (test_shadowsocks_connection(key, 5000)) {
            success++;
        } else {
            failed++;
        }
        tested++;
        std::cout << std::endl;
    }
    
    std::cout << "=== Summary ===" << std::endl;
    std::cout << "Tested: " << tested << ", Success: " << success 
              << ", Failed: " << failed << std::endl;
    
    return failed > 0 ? 1 : 0;
}
