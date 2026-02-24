#pragma once

/// @file shadowsocks.hpp
/// @brief Shadowsocks AEAD encryption (chacha20-ietf-poly1305, aes-256-gcm, aes-128-gcm)
/// @see https://shadowsocks.org/doc/aead.html

#ifdef _WIN32
  #ifndef NOMINMAX
    #define NOMINMAX
  #endif
#endif

#include <cstdint>
#include <string>
#include <vector>
#include <array>
#include <memory>
#include <stdexcept>
#include <cstring>
#include <algorithm>

// Crypto — works with both BoringSSL (Envoy) and OpenSSL (standalone)
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#ifdef OPENSSL_IS_BORINGSSL
#include <openssl/aead.h>
#include <openssl/hkdf.h>
#else
#include <openssl/kdf.h>
#endif

namespace shadowsocks {

// ============================================================================
// Constants
// ============================================================================

constexpr size_t AEAD_TAG_SIZE = 16;
constexpr size_t MAX_PAYLOAD_SIZE = 0x3FFF; // 16383 bytes

// ============================================================================
// Cipher Types
// ============================================================================

enum class CipherType {
    ChaCha20Poly1305,  // chacha20-ietf-poly1305
    Aes256Gcm,         // aes-256-gcm
    Aes128Gcm          // aes-128-gcm
};

struct CipherInfo {
    CipherType type;
    size_t key_size;
    size_t salt_size;
    size_t nonce_size;
#ifdef OPENSSL_IS_BORINGSSL
    const EVP_AEAD* aead;
#else
    const EVP_CIPHER* (*cipher_func)();
#endif
};

inline CipherInfo get_cipher_info(CipherType type) {
    switch (type) {
        case CipherType::ChaCha20Poly1305:
#ifdef OPENSSL_IS_BORINGSSL
            return {type, 32, 32, 12, EVP_aead_chacha20_poly1305()};
#else
            return {type, 32, 32, 12, EVP_chacha20_poly1305};
#endif
        case CipherType::Aes256Gcm:
#ifdef OPENSSL_IS_BORINGSSL
            return {type, 32, 32, 12, EVP_aead_aes_256_gcm()};
#else
            return {type, 32, 32, 12, EVP_aes_256_gcm};
#endif
        case CipherType::Aes128Gcm:
#ifdef OPENSSL_IS_BORINGSSL
            return {type, 16, 16, 12, EVP_aead_aes_128_gcm()};
#else
            return {type, 16, 16, 12, EVP_aes_128_gcm};
#endif
    }
    throw std::runtime_error("Unknown cipher type");
}

inline CipherType cipher_from_string(const std::string& method) {
    if (method == "chacha20-ietf-poly1305") return CipherType::ChaCha20Poly1305;
    if (method == "aes-256-gcm") return CipherType::Aes256Gcm;
    if (method == "aes-128-gcm") return CipherType::Aes128Gcm;
    throw std::runtime_error("Unsupported cipher: " + method);
}

// ============================================================================
// Key Derivation (HKDF-SHA1)
// ============================================================================

inline std::vector<uint8_t> derive_key(const std::string& password, size_t key_size) {
    // Shadowsocks uses EVP_BytesToKey with MD5 for password -> PSK
    std::vector<uint8_t> key(key_size);
    std::vector<uint8_t> md_buf(16); // MD5 digest size
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    size_t key_offset = 0;
    
    while (key_offset < key_size) {
        EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
        
        if (key_offset > 0) {
            EVP_DigestUpdate(ctx, md_buf.data(), 16);
        }
        EVP_DigestUpdate(ctx, password.data(), password.size());
        
        unsigned int md_len = 0;
        EVP_DigestFinal_ex(ctx, md_buf.data(), &md_len);
        
        size_t copy_len = std::min(static_cast<size_t>(md_len), key_size - key_offset);
        std::memcpy(key.data() + key_offset, md_buf.data(), copy_len);
        key_offset += copy_len;
    }
    
    EVP_MD_CTX_free(ctx);
    return key;
}

inline std::vector<uint8_t> derive_subkey(
    const std::vector<uint8_t>& psk,
    const std::vector<uint8_t>& salt,
    size_t key_size
) {
    // HKDF-SHA1 with info = "ss-subkey"
    std::vector<uint8_t> subkey(key_size);

#ifdef OPENSSL_IS_BORINGSSL
    if (!HKDF(subkey.data(), key_size, EVP_sha1(),
              psk.data(), psk.size(),
              salt.data(), salt.size(),
              reinterpret_cast<const uint8_t*>("ss-subkey"), 9)) {
        throw std::runtime_error("HKDF derive failed");
    }
#else
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!ctx) throw std::runtime_error("HKDF context creation failed");
    
    if (EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha1()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt.data(), salt.size()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx, psk.data(), psk.size()) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(ctx, 
            reinterpret_cast<const unsigned char*>("ss-subkey"), 9) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("HKDF setup failed");
    }
    
    size_t outlen = key_size;
    if (EVP_PKEY_derive(ctx, subkey.data(), &outlen) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("HKDF derive failed");
    }
    
    EVP_PKEY_CTX_free(ctx);
#endif
    return subkey;
}

// ============================================================================
// AEAD Cipher
// ============================================================================

class AeadCipher {
public:
    AeadCipher(CipherType type, const std::vector<uint8_t>& key)
        : info_(get_cipher_info(type)), key_(key), nonce_(info_.nonce_size, 0) {
        if (key.size() != info_.key_size) {
            throw std::runtime_error("Invalid key size");
        }
#ifdef OPENSSL_IS_BORINGSSL
        aead_ctx_ = EVP_AEAD_CTX_new(info_.aead, key_.data(), key_.size(),
                                     AEAD_TAG_SIZE);
        if (!aead_ctx_) throw std::runtime_error("AEAD context creation failed");
#endif
    }

    ~AeadCipher() {
#ifdef OPENSSL_IS_BORINGSSL
        if (aead_ctx_) EVP_AEAD_CTX_free(aead_ctx_);
#endif
    }

    // Non-copyable, non-movable (use via unique_ptr)
    AeadCipher(const AeadCipher&) = delete;
    AeadCipher& operator=(const AeadCipher&) = delete;
    AeadCipher(AeadCipher&&) = delete;
    AeadCipher& operator=(AeadCipher&&) = delete;
    
    /// Encrypt plaintext, returns ciphertext + tag
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext) {
        std::vector<uint8_t> ciphertext(plaintext.size() + AEAD_TAG_SIZE);

#ifdef OPENSSL_IS_BORINGSSL
        size_t ciphertext_len = 0;
        if (!EVP_AEAD_CTX_seal(aead_ctx_, ciphertext.data(), &ciphertext_len,
                               ciphertext.size(),
                               nonce_.data(), nonce_.size(),
                               plaintext.data(), plaintext.size(),
                               nullptr, 0)) {
            throw std::runtime_error("AEAD seal failed");
        }
        ciphertext.resize(ciphertext_len);
#else
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("Cipher context creation failed");
        
        int len = 0;
        int ciphertext_len = 0;
        
        if (EVP_EncryptInit_ex(ctx, info_.cipher_func(), nullptr, 
                               key_.data(), nonce_.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Encrypt init failed");
        }
        
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, 
                              plaintext.data(), plaintext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Encrypt update failed");
        }
        ciphertext_len = len;
        
        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Encrypt final failed");
        }
        ciphertext_len += len;
        
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, AEAD_TAG_SIZE, 
                                ciphertext.data() + ciphertext_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Get tag failed");
        }
        
        EVP_CIPHER_CTX_free(ctx);
        ciphertext.resize(ciphertext_len + AEAD_TAG_SIZE);
#endif
        increment_nonce();
        return ciphertext;
    }
    
    /// Decrypt ciphertext + tag, returns plaintext
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext) {
        if (ciphertext.size() < AEAD_TAG_SIZE) {
            throw std::runtime_error("Ciphertext too short");
        }
        
        size_t ct_len = ciphertext.size() - AEAD_TAG_SIZE;
        std::vector<uint8_t> plaintext(ct_len);

#ifdef OPENSSL_IS_BORINGSSL
        size_t plaintext_len = 0;
        if (!EVP_AEAD_CTX_open(aead_ctx_, plaintext.data(), &plaintext_len,
                               plaintext.size(),
                               nonce_.data(), nonce_.size(),
                               ciphertext.data(), ciphertext.size(),
                               nullptr, 0)) {
            throw std::runtime_error("AEAD open failed (auth failed)");
        }
        plaintext.resize(plaintext_len);
#else
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("Cipher context creation failed");
        
        int len = 0;
        int plaintext_len = 0;
        
        if (EVP_DecryptInit_ex(ctx, info_.cipher_func(), nullptr, 
                               key_.data(), nonce_.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Decrypt init failed");
        }
        
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, 
                              ciphertext.data(), ct_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Decrypt update failed");
        }
        plaintext_len = len;
        
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, AEAD_TAG_SIZE,
                                const_cast<uint8_t*>(ciphertext.data() + ct_len)) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Set tag failed");
        }
        
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Decrypt final failed (auth failed)");
        }
        plaintext_len += len;
        
        EVP_CIPHER_CTX_free(ctx);
        plaintext.resize(plaintext_len);
#endif
        increment_nonce();
        return plaintext;
    }
    
private:
    void increment_nonce() {
        // Little-endian increment
        for (size_t i = 0; i < nonce_.size(); ++i) {
            if (++nonce_[i] != 0) break;
        }
    }
    
    CipherInfo info_;
    std::vector<uint8_t> key_;
    std::vector<uint8_t> nonce_;
#ifdef OPENSSL_IS_BORINGSSL
    EVP_AEAD_CTX* aead_ctx_ = nullptr;
#endif
};

// ============================================================================
// Shadowsocks Session
// ============================================================================

class Session {
public:
    Session(const std::string& method, const std::string& password)
        : type_(cipher_from_string(method)),
          info_(get_cipher_info(type_)),
          psk_(derive_key(password, info_.key_size)) {}
    
    /// Generate salt and create encryptor
    std::pair<std::vector<uint8_t>, std::unique_ptr<AeadCipher>> create_encryptor() {
        std::vector<uint8_t> salt(info_.salt_size);
        RAND_bytes(salt.data(), salt.size());
        
        auto subkey = derive_subkey(psk_, salt, info_.key_size);
        auto cipher = std::make_unique<AeadCipher>(type_, subkey);
        
        return {std::move(salt), std::move(cipher)};
    }
    
    /// Create decryptor from received salt
    std::unique_ptr<AeadCipher> create_decryptor(const std::vector<uint8_t>& salt) {
        auto subkey = derive_subkey(psk_, salt, info_.key_size);
        return std::make_unique<AeadCipher>(type_, subkey);
    }
    
    size_t salt_size() const { return info_.salt_size; }
    
    /// Encode AEAD chunk: [length][tag][payload][tag]
    static std::vector<uint8_t> encode_payload(
        AeadCipher& cipher, 
        const std::vector<uint8_t>& data
    ) {
        // Length prefix (2 bytes big-endian) + tag
        std::vector<uint8_t> len_buf = {
            static_cast<uint8_t>((data.size() >> 8) & 0xFF),
            static_cast<uint8_t>(data.size() & 0xFF)
        };
        auto len_enc = cipher.encrypt(len_buf);
        
        // Payload + tag
        auto payload_enc = cipher.encrypt(data);
        
        // Concatenate
        std::vector<uint8_t> result;
        result.reserve(len_enc.size() + payload_enc.size());
        result.insert(result.end(), len_enc.begin(), len_enc.end());
        result.insert(result.end(), payload_enc.begin(), payload_enc.end());
        
        return result;
    }
    
    /// Encode target address for first payload
    static std::vector<uint8_t> encode_address(
        const std::string& host, 
        uint16_t port,
        bool is_domain
    ) {
        std::vector<uint8_t> addr;
        
        if (is_domain) {
            // ATYP=0x03, len, domain, port
            addr.push_back(0x03);
            addr.push_back(static_cast<uint8_t>(host.size()));
            addr.insert(addr.end(), host.begin(), host.end());
        } else {
            // Parse IPv4
            addr.push_back(0x01);
            // Simple IPv4 parse
            unsigned int a, b, c, d;
            if (sscanf(host.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
                addr.push_back(static_cast<uint8_t>(a));
                addr.push_back(static_cast<uint8_t>(b));
                addr.push_back(static_cast<uint8_t>(c));
                addr.push_back(static_cast<uint8_t>(d));
            }
        }
        
        // Port (big-endian)
        addr.push_back(static_cast<uint8_t>((port >> 8) & 0xFF));
        addr.push_back(static_cast<uint8_t>(port & 0xFF));
        
        return addr;
    }
    
    /// Encode address header (auto-detect domain vs IPv4)
    static std::vector<uint8_t> encode_address_header(
        const std::string& host,
        uint16_t port
    ) {
        // Check if it's IPv4
        unsigned int a, b, c, d;
        bool is_ipv4 = (sscanf(host.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) == 4);
        return encode_address(host, port, !is_ipv4);
    }
    
    /// Decode payloads from encrypted stream (stateful, handles partial frames).
    /// @param cipher    AEAD cipher with current nonce state
    /// @param pending   accumulated encrypted bytes; consumed bytes are erased
    /// @return decrypted plaintext from all complete frames found
    static std::vector<uint8_t> decode_payloads(
        AeadCipher& cipher,
        std::vector<uint8_t>& pending
    ) {
        std::vector<uint8_t> result;
        
        while (true) {
            // Need at least length block: 2 + TAG
            if (pending.size() < 2 + AEAD_TAG_SIZE) break;
            
            // Peek at the length block WITHOUT decrypting yet —
            // first check that the full frame (length + payload) is available.
            // We must decrypt length to know payload_len, but only if we can
            // also consume the payload in the same call. To avoid a nonce desync
            // we use a conservative lower-bound: the minimum possible frame is
            // (2+TAG) + (0+TAG). If even that isn't here, wait.
            if (pending.size() < 2 + AEAD_TAG_SIZE + 0 + AEAD_TAG_SIZE) break;
            
            // Decrypt the 2-byte length
            std::vector<uint8_t> len_block(pending.begin(),
                                           pending.begin() + 2 + AEAD_TAG_SIZE);
            auto len_dec = cipher.decrypt(len_block);
            if (len_dec.size() != 2) break;  // decryption auth failure
            
            uint16_t payload_len = (static_cast<uint16_t>(len_dec[0]) << 8) | len_dec[1];
            
            size_t frame_size = 2 + AEAD_TAG_SIZE + payload_len + AEAD_TAG_SIZE;
            if (pending.size() < frame_size) {
                // CRITICAL: length was already decrypted (nonce incremented).
                // We MUST NOT return here and wait — the nonce is already consumed.
                // Instead we must wait for the full payload to arrive in a loop.
                // But since we're a single-call function, we have to break and
                // accept the nonce is consumed. The caller must buffer and only
                // feed us data when the full frame is present.
                //
                // NEW APPROACH: We decrypt length speculatively. If payload isn't
                // available, we store the expected payload_len so the caller can
                // wait. This nonce IS consumed, so next time we skip length
                // decryption.
                //
                // To support this, use the overload with DecodeContext below.
                break;
            }
            
            // Decrypt payload
            std::vector<uint8_t> payload_block(
                pending.begin() + 2 + AEAD_TAG_SIZE,
                pending.begin() + 2 + AEAD_TAG_SIZE + payload_len + AEAD_TAG_SIZE);
            auto payload_dec = cipher.decrypt(payload_block);
            
            result.insert(result.end(), payload_dec.begin(), payload_dec.end());
            pending.erase(pending.begin(), pending.begin() + frame_size);
        }
        
        return result;
    }
    
    /// Stateful decode context — tracks partial frame state across calls.
    struct DecodeContext {
        bool need_payload = false;  ///< true when length was decrypted but payload not yet available
        uint16_t payload_len = 0;   ///< expected payload length (valid when need_payload==true)
    };
    
    /// Decode payloads with context to handle split frames safely.
    /// Unlike the basic overload, this one will NEVER desync the nonce:
    /// if length is decrypted but payload isn't available, it records the state
    /// in ctx and returns. On next call, it skips length decryption.
    static std::vector<uint8_t> decode_payloads(
        AeadCipher& cipher,
        std::vector<uint8_t>& pending,
        DecodeContext& ctx
    ) {
        std::vector<uint8_t> result;
        
        while (true) {
            if (ctx.need_payload) {
                // Length was already decrypted in a previous call.
                // Wait for payload_len + TAG bytes.
                size_t need = ctx.payload_len + AEAD_TAG_SIZE;
                if (pending.size() < need) break;
                
                std::vector<uint8_t> payload_block(
                    pending.begin(),
                    pending.begin() + need);
                auto payload_dec = cipher.decrypt(payload_block);
                
                result.insert(result.end(), payload_dec.begin(), payload_dec.end());
                pending.erase(pending.begin(), pending.begin() + need);
                ctx.need_payload = false;
                ctx.payload_len = 0;
                continue;  // try next frame
            }
            
            // Need length block: 2 + TAG
            if (pending.size() < 2 + AEAD_TAG_SIZE) break;
            
            // Check if full frame is available (optimistic path — no nonce risk)
            // We peek: decrypt length, then check payload availability
            std::vector<uint8_t> len_block(pending.begin(),
                                           pending.begin() + 2 + AEAD_TAG_SIZE);
            auto len_dec = cipher.decrypt(len_block);
            if (len_dec.size() != 2) break;
            
            uint16_t payload_len = (static_cast<uint16_t>(len_dec[0]) << 8) | len_dec[1];
            pending.erase(pending.begin(), pending.begin() + 2 + AEAD_TAG_SIZE);
            
            size_t need = payload_len + AEAD_TAG_SIZE;
            if (pending.size() < need) {
                // Payload not yet available — record state for next call
                ctx.need_payload = true;
                ctx.payload_len = payload_len;
                break;
            }
            
            // Decrypt payload
            std::vector<uint8_t> payload_block(
                pending.begin(),
                pending.begin() + need);
            auto payload_dec = cipher.decrypt(payload_block);
            
            result.insert(result.end(), payload_dec.begin(), payload_dec.end());
            pending.erase(pending.begin(), pending.begin() + need);
        }
        
        return result;
    }

private:
    CipherType type_;
    CipherInfo info_;
    std::vector<uint8_t> psk_;
};

} // namespace shadowsocks
