#ifndef OTP_GENERATOR_H
#define OTP_GENERATOR_H

#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <chrono>

class OTPGenerator {
public:
    OTPGenerator();
    ~OTPGenerator();

    // Generate new OTP secret
    std::string generateSecret(size_t length = 32);
    
    // Set existing secret (for loading from file)
    void setSecret(const std::string& secret);
    
    // Generate current OTP code
    std::string generateOTP();
    
    // Verify an OTP code
    bool verifyOTP(const std::string& code, int windowSize = 1);
    
    // Get the otpauth:// URI for QR code
    std::string getOTPAuthURI(const std::string& accountName, const std::string& issuer = "OTPApp");
    
    // Get manual entry key (base32 encoded secret)
    std::string getManualEntryKey();
    
    // Save encrypted secret to file
    bool saveToFile(const std::string& filename, const std::string& password);
    
    // Load encrypted secret from file
    bool loadFromFile(const std::string& filename, const std::string& password);
    
    // Check if secret is loaded
    bool hasSecret() const { return !secret_.empty(); }

private:
    // Triple-layer AES encryption
    std::vector<uint8_t> tripleEncrypt(const std::vector<uint8_t>& data, const std::string& password);
    std::vector<uint8_t> tripleDecrypt(const std::vector<uint8_t>& data, const std::string& password);
    
    // Single AES encryption/decryption
    std::vector<uint8_t> aesEncrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv);
    std::vector<uint8_t> aesDecrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv);
    
    // Key derivation
    std::vector<uint8_t> deriveKey(const std::string& password, const std::vector<uint8_t>& salt, int iteration);
    
    // HMAC-SHA1 for TOTP
    std::vector<uint8_t> hmacSha1(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data);
    
    // Base32 encoding/decoding
    std::string base32Encode(const std::vector<uint8_t>& data);
    std::vector<uint8_t> base32Decode(const std::string& encoded);
    
    // Get current time step
    uint64_t getTimeStep(int timeStepSeconds = 30);
    
    // Secure memory cleanup
    void secureZero(void* ptr, size_t size);
    
    // The secret key (stored in memory)
    std::vector<uint8_t> secret_;
    
    // Random number generation
    std::vector<uint8_t> generateRandomBytes(size_t length);
};

#endif // OTP_GENERATOR_H
