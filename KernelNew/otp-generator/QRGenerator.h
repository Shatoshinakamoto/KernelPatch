#ifndef QR_GENERATOR_H
#define QR_GENERATOR_H

#include <string>

class QRGenerator {
public:
    // Generate QR code message (without OpenCV, provides instructions)
    static bool generateQRCode(const std::string& data, const std::string& filename, int size = 400);
    
    // Display QR code information
    static void displayQRCode(const std::string& data, int size = 400);
    
private:
    static void printInstructions(const std::string& data);
};

#endif // QR_GENERATOR_H
