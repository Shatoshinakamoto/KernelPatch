#include "OTPGenerator.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <stdexcept>
#include <algorithm>

OTPGenerator::OTPGenerator() {
}

OTPGenerator::~OTPGenerator() {
    // Securely zero out the secret from memory
    if (!secret_.empty()) {
        secureZero(secret_.data(), secret_.size());
    }
}

std::string OTPGenerator::generateSecret(size_t length) {
    secret_ = generateRandomBytes(length);
    return base32Encode(secret_);
}

void OTPGenerator::setSecret(const std::string& secret) {
    // Assume secret is base32 encoded
    secret_ = base32Decode(secret);
}

std::string OTPGenerator::generateOTP() {
    if (secret_.empty()) {
        throw std::runtime_error("No secret key set");
    }

    uint64_t timeStep = getTimeStep();
    
    // Convert time step to bytes (big-endian)
    std::vector<uint8_t> timeBytes(8);
    for (int i = 7; i >= 0; i--) {
        timeBytes[i] = timeStep & 0xFF;
        timeStep >>= 8;
    }
    
    // Generate HMAC-SHA1
    std::vector<uint8_t> hash = hmacSha1(secret_, timeBytes);
    
    // Dynamic truncation
    int offset = hash[hash.size() - 1] & 0x0F;
    uint32_t code = ((hash[offset] & 0x7F) << 24) |
                    ((hash[offset + 1] & 0xFF) << 16) |
                    ((hash[offset + 2] & 0xFF) << 8) |
                    (hash[offset + 3] & 0xFF);
    
    // Generate 6-digit code
    code = code % 1000000;
    
    std::ostringstream oss;
    oss << std::setfill('0') << std::setw(6) << code;
    return oss.str();
}

bool OTPGenerator::verifyOTP(const std::string& code, int windowSize) {
    if (secret_.empty()) {
        throw std::runtime_error("No secret key set");
    }
    
    uint64_t currentTimeStep = getTimeStep();
    
    // Check current and adjacent time windows
    for (int i = -windowSize; i <= windowSize; i++) {
        uint64_t timeStep = currentTimeStep + i;
        
        std::vector<uint8_t> timeBytes(8);
        for (int j = 7; j >= 0; j--) {
            timeBytes[j] = timeStep & 0xFF;
            timeStep >>= 8;
        }
        
        std::vector<uint8_t> hash = hmacSha1(secret_, timeBytes);
        
        int offset = hash[hash.size() - 1] & 0x0F;
        uint32_t generatedCode = ((hash[offset] & 0x7F) << 24) |
                                 ((hash[offset + 1] & 0xFF) << 16) |
                                 ((hash[offset + 2] & 0xFF) << 8) |
                                 (hash[offset + 3] & 0xFF);
        
        generatedCode = generatedCode % 1000000;
        
        std::ostringstream oss;
        oss << std::setfill('0') << std::setw(6) << generatedCode;
        
        if (oss.str() == code) {
            return true;
        }
    }
    
    return false;
}

std::string OTPGenerator::getOTPAuthURI(const std::string& accountName, const std::string& issuer) {
    if (secret_.empty()) {
        throw std::runtime_error("No secret key set");
    }
    
    std::string base32Secret = base32Encode(secret_);
    std::ostringstream uri;
    uri << "otpauth://totp/" << issuer << ":" << accountName 
        << "?secret=" << base32Secret 
        << "&issuer=" << issuer
        << "&algorithm=SHA1&digits=6&period=30";
    
    return uri.str();
}

std::string OTPGenerator::getManualEntryKey() {
    if (secret_.empty()) {
        throw std::runtime_error("No secret key set");
    }
    return base32Encode(secret_);
}

bool OTPGenerator::saveToFile(const std::string& filename, const std::string& password) {
    if (secret_.empty()) {
        return false;
    }
    
    try {
        std::vector<uint8_t> encrypted = tripleEncrypt(secret_, password);
        
        std::ofstream file(filename, std::ios::binary);
        if (!file) {
            return false;
        }
        
        file.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
        file.close();
        
        return true;
    } catch (...) {
        return false;
    }
}

bool OTPGenerator::loadFromFile(const std::string& filename, const std::string& password) {
    try {
        std::ifstream file(filename, std::ios::binary);
        if (!file) {
            return false;
        }
        
        std::vector<uint8_t> encrypted((std::istreambuf_iterator<char>(file)),
                                       std::istreambuf_iterator<char>());
        file.close();
        
        secret_ = tripleDecrypt(encrypted, password);
        
        return !secret_.empty();
    } catch (...) {
        return false;
    }
}

// Triple-layer AES encryption (AES within AES within AES)
std::vector<uint8_t> OTPGenerator::tripleEncrypt(const std::vector<uint8_t>& data, const std::string& password) {
    // Generate three different salts
    std::vector<uint8_t> salt1 = generateRandomBytes(16);
    std::vector<uint8_t> salt2 = generateRandomBytes(16);
    std::vector<uint8_t> salt3 = generateRandomBytes(16);
    
    // Derive three different keys
    std::vector<uint8_t> key1 = deriveKey(password, salt1, 100000);
    std::vector<uint8_t> key2 = deriveKey(password, salt2, 100000);
    std::vector<uint8_t> key3 = deriveKey(password, salt3, 100000);
    
    // Generate three IVs
    std::vector<uint8_t> iv1 = generateRandomBytes(16);
    std::vector<uint8_t> iv2 = generateRandomBytes(16);
    std::vector<uint8_t> iv3 = generateRandomBytes(16);
    
    // Layer 1 encryption
    std::vector<uint8_t> encrypted1 = aesEncrypt(data, key1, iv1);
    
    // Layer 2 encryption
    std::vector<uint8_t> encrypted2 = aesEncrypt(encrypted1, key2, iv2);
    
    // Layer 3 encryption
    std::vector<uint8_t> encrypted3 = aesEncrypt(encrypted2, key3, iv3);
    
    // Combine: salt1 + salt2 + salt3 + iv1 + iv2 + iv3 + encrypted3
    std::vector<uint8_t> result;
    result.insert(result.end(), salt1.begin(), salt1.end());
    result.insert(result.end(), salt2.begin(), salt2.end());
    result.insert(result.end(), salt3.begin(), salt3.end());
    result.insert(result.end(), iv1.begin(), iv1.end());
    result.insert(result.end(), iv2.begin(), iv2.end());
    result.insert(result.end(), iv3.begin(), iv3.end());
    result.insert(result.end(), encrypted3.begin(), encrypted3.end());
    
    return result;
}

std::vector<uint8_t> OTPGenerator::tripleDecrypt(const std::vector<uint8_t>& data, const std::string& password) {
    if (data.size() < 96) { // 3*16 (salts) + 3*16 (IVs)
        throw std::runtime_error("Invalid encrypted data");
    }
    
    // Extract salts and IVs
    std::vector<uint8_t> salt1(data.begin(), data.begin() + 16);
    std::vector<uint8_t> salt2(data.begin() + 16, data.begin() + 32);
    std::vector<uint8_t> salt3(data.begin() + 32, data.begin() + 48);
    std::vector<uint8_t> iv1(data.begin() + 48, data.begin() + 64);
    std::vector<uint8_t> iv2(data.begin() + 64, data.begin() + 80);
    std::vector<uint8_t> iv3(data.begin() + 80, data.begin() + 96);
    std::vector<uint8_t> encrypted3(data.begin() + 96, data.end());
    
    // Derive keys
    std::vector<uint8_t> key1 = deriveKey(password, salt1, 100000);
    std::vector<uint8_t> key2 = deriveKey(password, salt2, 100000);
    std::vector<uint8_t> key3 = deriveKey(password, salt3, 100000);
    
    // Layer 3 decryption
    std::vector<uint8_t> decrypted2 = aesDecrypt(encrypted3, key3, iv3);
    
    // Layer 2 decryption
    std::vector<uint8_t> decrypted1 = aesDecrypt(decrypted2, key2, iv2);
    
    // Layer 1 decryption
    std::vector<uint8_t> decrypted = aesDecrypt(decrypted1, key1, iv1);
    
    return decrypted;
}

std::vector<uint8_t> OTPGenerator::aesEncrypt(const std::vector<uint8_t>& data, 
                                              const std::vector<uint8_t>& key, 
                                              const std::vector<uint8_t>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize encryption");
    }
    
    std::vector<uint8_t> encrypted(data.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int len = 0;
    int ciphertext_len = 0;
    
    if (EVP_EncryptUpdate(ctx, encrypted.data(), &len, data.data(), data.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption failed");
    }
    ciphertext_len = len;
    
    if (EVP_EncryptFinal_ex(ctx, encrypted.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption finalization failed");
    }
    ciphertext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    encrypted.resize(ciphertext_len);
    return encrypted;
}

std::vector<uint8_t> OTPGenerator::aesDecrypt(const std::vector<uint8_t>& data, 
                                              const std::vector<uint8_t>& key, 
                                              const std::vector<uint8_t>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize decryption");
    }
    
    std::vector<uint8_t> decrypted(data.size());
    int len = 0;
    int plaintext_len = 0;
    
    if (EVP_DecryptUpdate(ctx, decrypted.data(), &len, data.data(), data.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption failed");
    }
    plaintext_len = len;
    
    if (EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption finalization failed");
    }
    plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    decrypted.resize(plaintext_len);
    return decrypted;
}

std::vector<uint8_t> OTPGenerator::deriveKey(const std::string& password, 
                                             const std::vector<uint8_t>& salt, 
                                             int iteration) {
    std::vector<uint8_t> key(32); // 256 bits
    
    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                          salt.data(), salt.size(),
                          iteration,
                          EVP_sha256(),
                          key.size(), key.data()) != 1) {
        throw std::runtime_error("Key derivation failed");
    }
    
    return key;
}

std::vector<uint8_t> OTPGenerator::hmacSha1(const std::vector<uint8_t>& key, 
                                            const std::vector<uint8_t>& data) {
    unsigned int len = SHA_DIGEST_LENGTH;
    std::vector<uint8_t> result(len);
    
    HMAC(EVP_sha1(), key.data(), key.size(), data.data(), data.size(), result.data(), &len);
    
    return result;
}

std::string OTPGenerator::base32Encode(const std::vector<uint8_t>& data) {
    static const char* base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string result;
    
    int buffer = 0;
    int bitsLeft = 0;
    
    for (uint8_t byte : data) {
        buffer = (buffer << 8) | byte;
        bitsLeft += 8;
        
        while (bitsLeft >= 5) {
            result += base32Chars[(buffer >> (bitsLeft - 5)) & 0x1F];
            bitsLeft -= 5;
        }
    }
    
    if (bitsLeft > 0) {
        result += base32Chars[(buffer << (5 - bitsLeft)) & 0x1F];
    }
    
    // Add padding
    while (result.length() % 8 != 0) {
        result += '=';
    }
    
    return result;
}

std::vector<uint8_t> OTPGenerator::base32Decode(const std::string& encoded) {
    std::vector<uint8_t> result;
    int buffer = 0;
    int bitsLeft = 0;
    
    for (char c : encoded) {
        if (c == '=') break;
        
        int value;
        if (c >= 'A' && c <= 'Z') {
            value = c - 'A';
        } else if (c >= '2' && c <= '7') {
            value = c - '2' + 26;
        } else {
            continue; // Skip invalid characters
        }
        
        buffer = (buffer << 5) | value;
        bitsLeft += 5;
        
        if (bitsLeft >= 8) {
            result.push_back((buffer >> (bitsLeft - 8)) & 0xFF);
            bitsLeft -= 8;
        }
    }
    
    return result;
}

uint64_t OTPGenerator::getTimeStep(int timeStepSeconds) {
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
    return seconds / timeStepSeconds;
}

void OTPGenerator::secureZero(void* ptr, size_t size) {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (size--) {
        *p++ = 0;
    }
}

std::vector<uint8_t> OTPGenerator::generateRandomBytes(size_t length) {
    std::vector<uint8_t> bytes(length);
    if (RAND_bytes(bytes.data(), length) != 1) {
        throw std::runtime_error("Failed to generate random bytes");
    }
    return bytes;
}
