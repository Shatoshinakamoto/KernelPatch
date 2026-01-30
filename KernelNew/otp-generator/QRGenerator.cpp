#include "QRGenerator.h"
#include <iostream>
#include <fstream>

void QRGenerator::printInstructions(const std::string& data) {
    std::cout << "\n╔════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  QR CODE GENERATION (OpenCV not available)                ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════╝\n\n";
    std::cout << "To generate a QR code, you can:\n\n";
    std::cout << "1. Visit: https://www.qr-code-generator.com/\n";
    std::cout << "2. Select 'Text' or 'URL'\n";
    std::cout << "3. Paste the following URI:\n\n";
    std::cout << "   " << data << "\n\n";
    std::cout << "4. Generate and download the QR code\n";
    std::cout << "5. Scan with your authenticator app\n\n";
    std::cout << "Or use an online service like:\n";
    std::cout << "  - https://qr.io/\n";
    std::cout << "  - https://www.the-qrcode-generator.com/\n\n";
}

bool QRGenerator::generateQRCode(const std::string& data, const std::string& filename, int size) {
    std::cout << "\n[INFO] QR code would be saved to: " << filename << "\n";
    std::cout << "[INFO] Size: " << size << "x" << size << " pixels\n";
    
    // Save the URI to a text file
    std::ofstream file(filename + ".txt");
    if (file) {
        file << "OTP Auth URI:\n" << data << "\n\n";
        file << "To generate QR code:\n";
        file << "1. Visit https://www.qr-code-generator.com/\n";
        file << "2. Select 'Text' and paste the URI above\n";
        file << "3. Generate and download the QR code\n";
        file.close();
        std::cout << "[INFO] URI saved to: " << filename << ".txt\n";
    }
    
    printInstructions(data);
    
    return true;
}

void QRGenerator::displayQRCode(const std::string& data, int size) {
    std::cout << "\n[INFO] Display size: " << size << "x" << size << " pixels\n";
    printInstructions(data);
}
