/// @file socks5_test.cc
/// @brief Unit tests for SOCKS5 protocol library

#include "include/socks5/socks5.hpp"
#include "gtest/gtest.h"

namespace socks5 {
namespace {

class Socks5ParserTest : public ::testing::Test {
protected:
    void SetUp() override {}
};

TEST_F(Socks5ParserTest, ParseMethodSelectionNoAuth) {
    // Client sends: version=5, nmethods=1, methods=[NO_AUTH]
    std::vector<uint8_t> data = {0x05, 0x01, 0x00};
    
    MethodSelectionRequest request;
    auto [result, consumed] = Parser::parse_method_selection(data, request);
    
    EXPECT_EQ(result, ParseResult::Complete);
    EXPECT_EQ(consumed, 3u);
    EXPECT_EQ(request.version, VERSION);
    EXPECT_EQ(request.methods.size(), 1u);
    EXPECT_EQ(request.methods[0], AuthMethod::NoAuth);
}

TEST_F(Socks5ParserTest, ParseMethodSelectionMultipleMethods) {
    // Client sends: version=5, nmethods=3, methods=[NO_AUTH, GSSAPI, USERNAME_PASSWORD]
    std::vector<uint8_t> data = {0x05, 0x03, 0x00, 0x01, 0x02};
    
    MethodSelectionRequest request;
    auto [result, consumed] = Parser::parse_method_selection(data, request);
    
    EXPECT_EQ(result, ParseResult::Complete);
    EXPECT_EQ(consumed, 5u);
    EXPECT_EQ(request.methods.size(), 3u);
    EXPECT_EQ(request.methods[0], AuthMethod::NoAuth);
    EXPECT_EQ(request.methods[1], AuthMethod::GSSAPI);
    EXPECT_EQ(request.methods[2], AuthMethod::UsernamePassword);
}

TEST_F(Socks5ParserTest, ParseMethodSelectionIncomplete) {
    // Incomplete data
    std::vector<uint8_t> data = {0x05};
    
    MethodSelectionRequest request;
    auto [result, consumed] = Parser::parse_method_selection(data, request);
    
    EXPECT_EQ(result, ParseResult::Incomplete);
    EXPECT_EQ(consumed, 0u);
}

TEST_F(Socks5ParserTest, ParseMethodSelectionInvalidVersion) {
    // Wrong SOCKS version
    std::vector<uint8_t> data = {0x04, 0x01, 0x00};
    
    MethodSelectionRequest request;
    auto [result, consumed] = Parser::parse_method_selection(data, request);
    
    EXPECT_EQ(result, ParseResult::Invalid);
}

TEST_F(Socks5ParserTest, ParseAuthRequest) {
    // Auth request: version=1, ulen=4, user="test", plen=6, pass="secret"
    std::vector<uint8_t> data = {
        0x01,                         // version
        0x04, 't', 'e', 's', 't',      // username
        0x06, 's', 'e', 'c', 'r', 'e', 't'  // password
    };
    
    AuthRequest request;
    auto [result, consumed] = Parser::parse_auth_request(data, request);
    
    EXPECT_EQ(result, ParseResult::Complete);
    EXPECT_EQ(consumed, 13u);
    EXPECT_EQ(request.username, "test");
    EXPECT_EQ(request.password, "secret");
}

TEST_F(Socks5ParserTest, ParseRequestConnectIPv4) {
    // CONNECT to 192.168.1.1:8080
    std::vector<uint8_t> data = {
        0x05,                   // version
        0x01,                   // CONNECT
        0x00,                   // reserved
        0x01,                   // IPv4
        192, 168, 1, 1,         // address
        0x1F, 0x90              // port 8080
    };
    
    Request request;
    auto [result, consumed] = Parser::parse_request(data, request);
    
    EXPECT_EQ(result, ParseResult::Complete);
    EXPECT_EQ(consumed, 10u);
    EXPECT_EQ(request.command, Command::Connect);
    EXPECT_EQ(request.port, 8080);
    
    auto* ipv4 = std::get_if<IPv4Address>(&request.destination);
    ASSERT_NE(ipv4, nullptr);
    EXPECT_EQ(ipv4->to_string(), "192.168.1.1");
}

TEST_F(Socks5ParserTest, ParseRequestConnectDomain) {
    // CONNECT to example.com:443
    std::string domain = "example.com";
    std::vector<uint8_t> data = {
        0x05,                       // version
        0x01,                       // CONNECT
        0x00,                       // reserved
        0x03,                       // domain name
        static_cast<uint8_t>(domain.size())  // domain length
    };
    data.insert(data.end(), domain.begin(), domain.end());
    data.push_back(0x01);  // port 443 high byte
    data.push_back(0xBB);  // port 443 low byte
    
    Request request;
    auto [result, consumed] = Parser::parse_request(data, request);
    
    EXPECT_EQ(result, ParseResult::Complete);
    EXPECT_EQ(request.command, Command::Connect);
    EXPECT_EQ(request.port, 443);
    
    auto* dom = std::get_if<DomainName>(&request.destination);
    ASSERT_NE(dom, nullptr);
    EXPECT_EQ(dom->name, "example.com");
}

TEST_F(Socks5ParserTest, ParseRequestConnectIPv6) {
    // CONNECT to [2001:db8::1]:80
    std::vector<uint8_t> data = {
        0x05,                   // version
        0x01,                   // CONNECT
        0x00,                   // reserved
        0x04,                   // IPv6
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x50              // port 80
    };
    
    Request request;
    auto [result, consumed] = Parser::parse_request(data, request);
    
    EXPECT_EQ(result, ParseResult::Complete);
    EXPECT_EQ(consumed, 22u);
    EXPECT_EQ(request.command, Command::Connect);
    EXPECT_EQ(request.port, 80);
    
    auto* ipv6 = std::get_if<IPv6Address>(&request.destination);
    ASSERT_NE(ipv6, nullptr);
}

TEST_F(Socks5ParserTest, SerializeMethodSelectionResponse) {
    MethodSelectionResponse response;
    response.method = AuthMethod::NoAuth;
    
    auto serialized = response.serialize();
    
    EXPECT_EQ(serialized.size(), 2u);
    EXPECT_EQ(serialized[0], 0x05);  // version
    EXPECT_EQ(serialized[1], 0x00);  // NO_AUTH
}

TEST_F(Socks5ParserTest, SerializeReplySuccess) {
    ReplyMessage reply;
    reply.reply = Reply::Succeeded;
    reply.bind_address = IPv4Address{{127, 0, 0, 1}};
    reply.bind_port = 1080;
    
    auto serialized = reply.serialize();
    
    EXPECT_EQ(serialized.size(), 10u);
    EXPECT_EQ(serialized[0], 0x05);  // version
    EXPECT_EQ(serialized[1], 0x00);  // success
    EXPECT_EQ(serialized[2], 0x00);  // reserved
    EXPECT_EQ(serialized[3], 0x01);  // IPv4
    EXPECT_EQ(serialized[4], 127);   // address
    EXPECT_EQ(serialized[5], 0);
    EXPECT_EQ(serialized[6], 0);
    EXPECT_EQ(serialized[7], 1);
    EXPECT_EQ(serialized[8], 0x04);  // port high byte (1080 >> 8 = 4)
    EXPECT_EQ(serialized[9], 0x38);  // port low byte (1080 & 0xFF = 56)
}

TEST_F(Socks5ParserTest, AuthenticatorNoAuth) {
    NoAuthenticator auth;
    EXPECT_TRUE(auth.authenticate("any", "thing"));
}

TEST_F(Socks5ParserTest, AuthenticatorSimple) {
    SimpleAuthenticator auth;
    auth.add_user("admin", "secret");
    
    EXPECT_TRUE(auth.authenticate("admin", "secret"));
    EXPECT_FALSE(auth.authenticate("admin", "wrong"));
    EXPECT_FALSE(auth.authenticate("unknown", "secret"));
}

TEST_F(Socks5ParserTest, SessionStateMachine) {
    Session session;
    
    EXPECT_EQ(session.state(), State::AwaitingMethods);
    
    session.set_state(State::AwaitingRequest);
    EXPECT_EQ(session.state(), State::AwaitingRequest);
    
    Request req;
    req.command = Command::Connect;
    req.port = 80;
    session.set_request(req);
    
    EXPECT_EQ(session.request().port, 80);
}

} // namespace
} // namespace socks5
