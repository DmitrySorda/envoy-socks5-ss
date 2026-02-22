/// @file standalone_test.cc
/// @brief Simple compilation test for SOCKS5 library

#include "socks5/socks5.hpp"
#include <iostream>

int main() {
    std::cout << "=== SOCKS5 Library Standalone Test ===\n\n";
    
    // Test 1: Parse method selection
    {
        std::vector<uint8_t> data = {0x05, 0x01, 0x00};
        socks5::MethodSelectionRequest req;
        auto [result, consumed] = socks5::Parser::parse_method_selection(data, req);
        
        std::cout << "Method Selection Parse: " 
                  << (result == socks5::ParseResult::Complete ? "OK" : "FAIL") << "\n";
        std::cout << "  Version: " << (int)req.version << "\n";
        std::cout << "  Methods: " << req.methods.size() << "\n";
    }
    
    // Test 2: Parse CONNECT request to IPv4
    {
        std::vector<uint8_t> data = {
            0x05, 0x01, 0x00, 0x01,  // version, connect, reserved, ipv4
            192, 168, 1, 1,          // address
            0x1F, 0x90               // port 8080
        };
        socks5::Request req;
        auto [result, consumed] = socks5::Parser::parse_request(data, req);
        
        std::cout << "\nCONNECT Request Parse: " 
                  << (result == socks5::ParseResult::Complete ? "OK" : "FAIL") << "\n";
        std::cout << "  Destination: " << socks5::address_to_string(req.destination) << "\n";
        std::cout << "  Port: " << req.port << "\n";
    }
    
    // Test 3: Serialize reply
    {
        socks5::ReplyMessage reply;
        reply.reply = socks5::Reply::Succeeded;
        reply.bind_address = socks5::IPv4Address{{127, 0, 0, 1}};
        reply.bind_port = 1080;
        
        auto serialized = reply.serialize();
        
        std::cout << "\nReply Serialization: " 
                  << (serialized.size() == 10 ? "OK" : "FAIL") << "\n";
        std::cout << "  Size: " << serialized.size() << " bytes\n";
    }
    
    // Test 4: Authenticator
    {
        socks5::SimpleAuthenticator auth;
        auth.add_user("admin", "secret123");
        
        bool ok = auth.authenticate("admin", "secret123");
        bool fail = auth.authenticate("admin", "wrong");
        
        std::cout << "\nAuthenticator: " 
                  << (ok && !fail ? "OK" : "FAIL") << "\n";
    }
    
    // Test 5: Session state machine
    {
        socks5::Session session;
        std::cout << "\nSession State Machine: ";
        
        bool ok = true;
        ok &= (session.state() == socks5::State::AwaitingMethods);
        
        session.set_state(socks5::State::AwaitingRequest);
        ok &= (session.state() == socks5::State::AwaitingRequest);
        
        session.set_state(socks5::State::Connected);
        ok &= (session.state() == socks5::State::Connected);
        
        std::cout << (ok ? "OK" : "FAIL") << "\n";
    }
    
    std::cout << "\n=== All tests completed ===\n";
    return 0;
}
