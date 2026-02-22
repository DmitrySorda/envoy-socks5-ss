#pragma once

/// @file socks5.hpp
/// @brief Header-only SOCKS5 protocol implementation (RFC 1928, RFC 1929)
/// @author envoy-socks5-filter project
/// @license Apache 2.0

#include <cstdint>
#include <string>
#include <variant>
#include <vector>
#include <optional>
#include <array>
#include <stdexcept>
#include <unordered_map>
#include <algorithm>

namespace socks5 {

// ============================================================================
// Protocol Constants (RFC 1928)
// ============================================================================

constexpr uint8_t VERSION = 0x05;

/// Authentication methods
enum class AuthMethod : uint8_t {
    NoAuth = 0x00,
    GSSAPI = 0x01,
    UsernamePassword = 0x02,
    // 0x03-0x7F: IANA assigned
    // 0x80-0xFE: private methods
    NoAcceptable = 0xFF
};

/// Command types
enum class Command : uint8_t {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03
};

/// Address types
enum class AddressType : uint8_t {
    IPv4 = 0x01,
    DomainName = 0x03,
    IPv6 = 0x04
};

/// Reply codes
enum class Reply : uint8_t {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    ConnectionNotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08
};

// ============================================================================
// Address Types
// ============================================================================

struct IPv4Address {
    std::array<uint8_t, 4> octets;
    
    std::string to_string() const {
        return std::to_string(octets[0]) + "." +
               std::to_string(octets[1]) + "." +
               std::to_string(octets[2]) + "." +
               std::to_string(octets[3]);
    }
};

struct IPv6Address {
    std::array<uint8_t, 16> octets;
    
    std::string to_string() const {
        // Simplified IPv6 string representation
        std::string result;
        for (size_t i = 0; i < 16; i += 2) {
            if (i > 0) result += ":";
            char buf[8];
            snprintf(buf, sizeof(buf), "%02x%02x", octets[i], octets[i + 1]);
            result += buf;
        }
        return result;
    }
};

struct DomainName {
    std::string name;
    
    std::string to_string() const { return name; }
};

using Address = std::variant<IPv4Address, IPv6Address, DomainName>;

inline std::string address_to_string(const Address& addr) {
    return std::visit([](const auto& a) { return a.to_string(); }, addr);
}

// ============================================================================
// Protocol Messages
// ============================================================================

/// Client greeting (method selection request)
struct MethodSelectionRequest {
    uint8_t version = VERSION;
    std::vector<AuthMethod> methods;
    
    static constexpr size_t MIN_SIZE = 3; // version + nmethods + at_least_one_method
};

/// Server method selection response
struct MethodSelectionResponse {
    uint8_t version = VERSION;
    AuthMethod method = AuthMethod::NoAuth;
    
    static constexpr size_t SIZE = 2;
    
    std::array<uint8_t, SIZE> serialize() const {
        return {version, static_cast<uint8_t>(method)};
    }
};

/// Username/Password authentication request (RFC 1929)
struct AuthRequest {
    uint8_t version = 0x01; // Sub-negotiation version
    std::string username;
    std::string password;
};

/// Username/Password authentication response
struct AuthResponse {
    uint8_t version = 0x01;
    uint8_t status = 0x00; // 0x00 = success
    
    static constexpr size_t SIZE = 2;
    
    std::array<uint8_t, SIZE> serialize() const {
        return {version, status};
    }
};

/// SOCKS5 request
struct Request {
    uint8_t version = VERSION;
    Command command = Command::Connect;
    Address destination;
    uint16_t port = 0;
};

/// SOCKS5 reply
struct ReplyMessage {
    uint8_t version = VERSION;
    Reply reply = Reply::Succeeded;
    Address bind_address;
    uint16_t bind_port = 0;
    
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> data;
        data.reserve(22); // max size for IPv6
        
        data.push_back(version);
        data.push_back(static_cast<uint8_t>(reply));
        data.push_back(0x00); // reserved
        
        // Serialize address
        std::visit([&data](const auto& addr) {
            using T = std::decay_t<decltype(addr)>;
            if constexpr (std::is_same_v<T, IPv4Address>) {
                data.push_back(static_cast<uint8_t>(AddressType::IPv4));
                data.insert(data.end(), addr.octets.begin(), addr.octets.end());
            } else if constexpr (std::is_same_v<T, IPv6Address>) {
                data.push_back(static_cast<uint8_t>(AddressType::IPv6));
                data.insert(data.end(), addr.octets.begin(), addr.octets.end());
            } else if constexpr (std::is_same_v<T, DomainName>) {
                data.push_back(static_cast<uint8_t>(AddressType::DomainName));
                data.push_back(static_cast<uint8_t>(addr.name.size()));
                data.insert(data.end(), addr.name.begin(), addr.name.end());
            }
        }, bind_address);
        
        // Port (network byte order)
        data.push_back(static_cast<uint8_t>(bind_port >> 8));
        data.push_back(static_cast<uint8_t>(bind_port & 0xFF));
        
        return data;
    }
};

// ============================================================================
// Parser
// ============================================================================

enum class ParseResult {
    Complete,
    Incomplete,
    Invalid
};

class Parser {
public:
    /// Parse method selection request
    /// Returns (result, bytes_consumed)
    static std::pair<ParseResult, size_t> 
    parse_method_selection(const std::vector<uint8_t>& data, MethodSelectionRequest& out) {
        if (data.size() < 2) return {ParseResult::Incomplete, 0};
        
        if (data[0] != VERSION) return {ParseResult::Invalid, 0};
        
        uint8_t nmethods = data[1];
        size_t expected_size = 2 + nmethods;
        
        if (data.size() < expected_size) return {ParseResult::Incomplete, 0};
        
        out.version = data[0];
        out.methods.clear();
        out.methods.reserve(nmethods);
        
        for (size_t i = 0; i < nmethods; ++i) {
            out.methods.push_back(static_cast<AuthMethod>(data[2 + i]));
        }
        
        return {ParseResult::Complete, expected_size};
    }
    
    /// Parse username/password auth request
    static std::pair<ParseResult, size_t>
    parse_auth_request(const std::vector<uint8_t>& data, AuthRequest& out) {
        if (data.size() < 2) return {ParseResult::Incomplete, 0};
        
        if (data[0] != 0x01) return {ParseResult::Invalid, 0};
        
        uint8_t ulen = data[1];
        if (data.size() < 2 + ulen + 1) return {ParseResult::Incomplete, 0};
        
        uint8_t plen = data[2 + ulen];
        size_t expected_size = 3 + ulen + plen;
        
        if (data.size() < expected_size) return {ParseResult::Incomplete, 0};
        
        out.version = data[0];
        out.username = std::string(reinterpret_cast<const char*>(&data[2]), ulen);
        out.password = std::string(reinterpret_cast<const char*>(&data[3 + ulen]), plen);
        
        return {ParseResult::Complete, expected_size};
    }
    
    /// Parse SOCKS5 request
    static std::pair<ParseResult, size_t>
    parse_request(const std::vector<uint8_t>& data, Request& out) {
        if (data.size() < 7) return {ParseResult::Incomplete, 0}; // min: ver+cmd+rsv+atyp+port(2)+min_addr(1)
        
        if (data[0] != VERSION) return {ParseResult::Invalid, 0};
        
        out.version = data[0];
        out.command = static_cast<Command>(data[1]);
        // data[2] is reserved
        
        AddressType atyp = static_cast<AddressType>(data[3]);
        size_t addr_start = 4;
        size_t addr_len = 0;
        
        switch (atyp) {
            case AddressType::IPv4:
                addr_len = 4;
                if (data.size() < addr_start + addr_len + 2) 
                    return {ParseResult::Incomplete, 0};
                {
                    IPv4Address addr;
                    std::copy_n(&data[addr_start], 4, addr.octets.begin());
                    out.destination = addr;
                }
                break;
                
            case AddressType::IPv6:
                addr_len = 16;
                if (data.size() < addr_start + addr_len + 2) 
                    return {ParseResult::Incomplete, 0};
                {
                    IPv6Address addr;
                    std::copy_n(&data[addr_start], 16, addr.octets.begin());
                    out.destination = addr;
                }
                break;
                
            case AddressType::DomainName:
                if (data.size() < addr_start + 1) 
                    return {ParseResult::Incomplete, 0};
                addr_len = 1 + data[addr_start]; // length byte + domain
                if (data.size() < addr_start + addr_len + 2) 
                    return {ParseResult::Incomplete, 0};
                {
                    DomainName addr;
                    addr.name = std::string(
                        reinterpret_cast<const char*>(&data[addr_start + 1]),
                        data[addr_start]
                    );
                    out.destination = addr;
                }
                break;
                
            default:
                return {ParseResult::Invalid, 0};
        }
        
        size_t port_start = addr_start + addr_len;
        out.port = (static_cast<uint16_t>(data[port_start]) << 8) | data[port_start + 1];
        
        return {ParseResult::Complete, port_start + 2};
    }
};

// ============================================================================
// Authenticator
// ============================================================================

class Authenticator {
public:
    virtual ~Authenticator() = default;
    
    virtual bool authenticate(const std::string& username, 
                              const std::string& password) = 0;
};

/// No authentication required
class NoAuthenticator : public Authenticator {
public:
    bool authenticate(const std::string&, const std::string&) override {
        return true;
    }
};

/// Simple in-memory username/password authenticator
class SimpleAuthenticator : public Authenticator {
public:
    void add_user(const std::string& username, const std::string& password) {
        users_[username] = password;
    }
    
    bool authenticate(const std::string& username, 
                      const std::string& password) override {
        auto it = users_.find(username);
        return it != users_.end() && it->second == password;
    }
    
private:
    std::unordered_map<std::string, std::string> users_;
};

// ============================================================================
// State Machine
// ============================================================================

enum class State {
    Initial,
    AwaitingMethods,
    AwaitingAuth,
    AwaitingRequest,
    Connected,
    Error
};

/// SOCKS5 session state machine
class Session {
public:
    Session() : state_(State::AwaitingMethods) {}
    
    State state() const { return state_; }
    
    void set_state(State s) { state_ = s; }
    
    const Request& request() const { return request_; }
    void set_request(const Request& req) { request_ = req; }
    
    AuthMethod selected_method() const { return selected_method_; }
    void set_selected_method(AuthMethod m) { selected_method_ = m; }
    
private:
    State state_;
    Request request_;
    AuthMethod selected_method_ = AuthMethod::NoAuth;
};

} // namespace socks5
