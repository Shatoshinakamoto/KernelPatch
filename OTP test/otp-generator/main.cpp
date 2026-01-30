#include <iostream>
#include <string>
#include <getopt.h>
#include <unistd.h>
#include <termios.h>
#include "OTPGenerator.h"
#include "QRGenerator.h"

// Function to read password without echoing
std::string getPassword(const std::string& prompt) {
    std::cout << prompt;
    std::cout.flush();
    
    struct termios oldSettings, newSettings;
    tcgetattr(STDIN_FILENO, &oldSettings);
    newSettings = oldSettings;
    newSettings.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newSettings);
    
    std::string password;
    std::getline(std::cin, password);
    
    tcsetattr(STDIN_FILENO, TCSANOW, &oldSettings);
    std::cout << std::endl;
    
    return password;
}

void printUsage(const char* programName) {
    std::cout << "OTP Generator - Secure Time-based One-Time Password Generator\n\n";
    std::cout << "Usage: " << programName << " [OPTIONS]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -g, --generate <name>     Generate new OTP secret for account name\n";
    std::cout << "  -i, --issuer <issuer>     Set issuer name (default: OTPApp)\n";
    std::cout << "  -l, --load <file>         Load existing OTP secret from file\n";
    std::cout << "  -s, --show                Display current OTP code\n";
    std::cout << "  -v, --verify <code>       Verify an OTP code\n";
    std::cout << "  -q, --qr <file>           Save QR code to file (PNG)\n";
    std::cout << "  -d, --display             Display QR code in window\n";
    std::cout << "  -m, --manual              Show manual entry key\n";
    std::cout << "  -w, --watch               Watch mode - continuously display OTP\n";
    std::cout << "  -h, --help                Show this help message\n\n";
    std::cout << "Examples:\n";
    std::cout << "  # Generate new OTP for Gmail account\n";
    std::cout << "  " << programName << " -g myemail@gmail.com -i Google -q qr.png -m\n\n";
    std::cout << "  # Load existing OTP and show current code\n";
    std::cout << "  " << programName << " -l otp.dat -s\n\n";
    std::cout << "  # Verify a code\n";
    std::cout << "  " << programName << " -l otp.dat -v 123456\n\n";
    std::cout << "  # Watch mode (continuous updates)\n";
    std::cout << "  " << programName << " -l otp.dat -w\n";
}

int main(int argc, char* argv[]) {
    std::string accountName;
    std::string issuer = "OTPApp";
    std::string loadFile;
    std::string verifyCode;
    std::string qrFile;
    bool showCode = false;
    bool displayQR = false;
    bool showManual = false;
    bool watchMode = false;

    static struct option long_options[] = {
        {"generate", required_argument, 0, 'g'},
        {"issuer",   required_argument, 0, 'i'},
        {"load",     required_argument, 0, 'l'},
        {"show",     no_argument,       0, 's'},
        {"verify",   required_argument, 0, 'v'},
        {"qr",       required_argument, 0, 'q'},
        {"display",  no_argument,       0, 'd'},
        {"manual",   no_argument,       0, 'm'},
        {"watch",    no_argument,       0, 'w'},
        {"help",     no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "g:i:l:sv:q:dmwh", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'g':
                accountName = optarg;
                break;
            case 'i':
                issuer = optarg;
                break;
            case 'l':
                loadFile = optarg;
                break;
            case 's':
                showCode = true;
                break;
            case 'v':
                verifyCode = optarg;
                break;
            case 'q':
                qrFile = optarg;
                break;
            case 'd':
                displayQR = true;
                break;
            case 'm':
                showManual = true;
                break;
            case 'w':
                watchMode = true;
                break;
            case 'h':
                printUsage(argv[0]);
                return 0;
            default:
                printUsage(argv[0]);
                return 1;
        }
    }

    try {
        OTPGenerator otp;

        // Generate new OTP secret
        if (!accountName.empty()) {
            std::cout << "=== Generating New OTP Secret ===\n";
            std::string secret = otp.generateSecret();
            
            std::cout << "\nSecret generated successfully!\n";
            std::cout << "Account: " << accountName << "\n";
            std::cout << "Issuer: " << issuer << "\n\n";

            // Show manual entry key
            if (showManual || qrFile.empty()) {
                std::string manualKey = otp.getManualEntryKey();
                std::cout << "Manual Entry Key (Base32):\n";
                std::cout << "  " << manualKey << "\n\n";
                std::cout << "Enter this key in your authenticator app if QR scan fails.\n\n";
            }

            // Generate QR code
            std::string uri = otp.getOTPAuthURI(accountName, issuer);
            
            if (!qrFile.empty()) {
                if (QRGenerator::generateQRCode(uri, qrFile)) {
                    std::cout << "QR code saved to: " << qrFile << "\n";
                } else {
                    std::cerr << "Failed to save QR code\n";
                }
            }

            if (displayQR) {
                std::cout << "Displaying QR code...\n";
                QRGenerator::displayQRCode(uri);
            }

            // Save to file
            std::string password = getPassword("Enter password to encrypt and save secret: ");
            std::string saveFile = accountName + ".otp";
            
            if (otp.saveToFile(saveFile, password)) {
                std::cout << "Secret saved to: " << saveFile << "\n";
                std::cout << "\nKeep this file and password safe!\n";
            } else {
                std::cerr << "Failed to save secret\n";
                return 1;
            }

            // Show first code
            std::cout << "\nCurrent OTP Code: " << otp.generateOTP() << "\n";
        }
        // Load existing OTP
        else if (!loadFile.empty()) {
            std::string password = getPassword("Enter password to decrypt: ");
            
            if (!otp.loadFromFile(loadFile, password)) {
                std::cerr << "Failed to load OTP secret. Check password and file.\n";
                return 1;
            }
            
            std::cout << "OTP secret loaded successfully!\n\n";

            // Show manual key
            if (showManual) {
                std::cout << "Manual Entry Key: " << otp.getManualEntryKey() << "\n\n";
            }

            // Verify code
            if (!verifyCode.empty()) {
                if (otp.verifyOTP(verifyCode)) {
                    std::cout << "✓ Code " << verifyCode << " is VALID\n";
                } else {
                    std::cout << "✗ Code " << verifyCode << " is INVALID\n";
                }
            }

            // Show current code
            if (showCode && !watchMode) {
                std::cout << "Current OTP Code: " << otp.generateOTP() << "\n";
            }

            // Watch mode - continuously display OTP
            if (watchMode) {
                std::cout << "=== Watch Mode (Press Ctrl+C to exit) ===\n\n";
                std::string lastCode;
                
                while (true) {
                    std::string currentCode = otp.generateOTP();
                    
                    if (currentCode != lastCode) {
                        auto now = std::chrono::system_clock::now();
                        auto time = std::chrono::system_clock::to_time_t(now);
                        auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
                            now.time_since_epoch()).count();
                        int remaining = 30 - (seconds % 30);
                        
                        std::cout << "\r" << std::flush;
                        std::cout << "Current Code: " << currentCode 
                                  << "  (valid for " << remaining << "s)  " << std::flush;
                        
                        lastCode = currentCode;
                    }
                    
                    sleep(1);
                }
            }

            // Generate QR for existing secret
            if (!qrFile.empty() || displayQR) {
                std::string accountPrompt;
                std::cout << "Enter account name for QR code: ";
                std::getline(std::cin, accountPrompt);
                
                std::string issuerPrompt;
                std::cout << "Enter issuer name (or press Enter for default): ";
                std::getline(std::cin, issuerPrompt);
                if (!issuerPrompt.empty()) {
                    issuer = issuerPrompt;
                }
                
                std::string uri = otp.getOTPAuthURI(accountPrompt.empty() ? "Account" : accountPrompt, issuer);
                
                if (!qrFile.empty()) {
                    if (QRGenerator::generateQRCode(uri, qrFile)) {
                        std::cout << "QR code saved to: " << qrFile << "\n";
                    }
                }
                
                if (displayQR) {
                    QRGenerator::displayQRCode(uri);
                }
            }
        }
        else {
            printUsage(argv[0]);
            return 1;
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
