# OTP Generator - Secure Time-based One-Time Password System

A professional C++ command-line application for generating Time-based One-Time Passwords (TOTP) with multi-layer encryption, QR code generation, and full support for Google Authenticator and Microsoft Authenticator.

## Features

### Core Functionality
- **TOTP Generation**: Industry-standard RFC 6238 implementation
- **QR Code Generation**: Visual QR codes for easy authenticator setup
- **Manual Entry Support**: Base32-encoded keys for manual input
- **Code Verification**: Test and validate OTP codes
- **Watch Mode**: Real-time OTP display with countdown timer

### Security Features
- **Triple-Layer AES Encryption**: AES-256 within AES-256 within AES-256
- **Secure Key Derivation**: PBKDF2 with 100,000 iterations per layer
- **Memory Protection**: Secure memory wiping on cleanup
- **No Plaintext Storage**: Secrets never stored unencrypted
- **Password-Protected Files**: All saved data is encrypted

### Compatibility
- ✓ Google Authenticator
- ✓ Microsoft Authenticator
- ✓ Any RFC 6238 compliant authenticator app

## Requirements

### System Requirements
- Ubuntu 20.04 or later (or compatible Linux distribution)
- CMake 3.10+
- GCC/G++ compiler with C++17 support

### Dependencies
- OpenCV (for QR code generation)
- OpenSSL (for encryption and HMAC)

## Installation

### Quick Build (Recommended)
```bash
# Navigate to the project directory
cd otp-generator

# Build using Make
make

# The executable will be: ./otp
```

### Alternative: CMake Build
If you have OpenCV and OpenSSL development packages installed:
```bash
mkdir build
cd build
cmake ..
make -j$(nproc)

# The executable will be: build/bin/otp
```

### System Requirements
- **Operating System**: Ubuntu 20.04+ or compatible Linux distribution
- **Compiler**: GCC/G++ with C++17 support
- **Libraries**: OpenSSL 3.0+ (runtime libraries included in Ubuntu)

### Optional Dependencies
- **OpenCV**: For visual QR code generation (the app works without it)

## Usage

### Generate New OTP

Generate a new OTP secret and save it with encryption:

```bash
./otp -g myemail@gmail.com -i Google -q qrcode.png -m
```

This will:
1. Generate a secure random secret
2. Display the manual entry key
3. Provide instructions for creating a QR code
4. Encrypt and save the secret to `myemail@gmail.com.otp`
5. Show the first OTP code

### Load and Display Current Code

```bash
./otp -l myemail@gmail.com.otp -s
```

### Watch Mode (Live Updates)

Continuously display the current OTP with a countdown timer:

```bash
./otp -l myemail@gmail.com.otp -w
```

Press Ctrl+C to exit watch mode.

### Verify an OTP Code

Test if a code is valid:

```bash
./otp -l myemail@gmail.com.otp -v 123456
```

### Show Manual Entry Key

```bash
./otp -l myemail@gmail.com.otp -m
```

## Command-Line Options

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-g <name>` | `--generate` | Generate new OTP secret for account |
| `-i <issuer>` | `--issuer` | Set issuer name (default: OTPApp) |
| `-l <file>` | `--load` | Load existing OTP secret from file |
| `-s` | `--show` | Display current OTP code |
| `-v <code>` | `--verify` | Verify an OTP code |
| `-q <file>` | `--qr` | Save QR code to PNG file |
| `-d` | `--display` | Display QR code in window |
| `-m` | `--manual` | Show manual entry key (Base32) |
| `-w` | `--watch` | Watch mode - continuous OTP display |
| `-h` | `--help` | Show help message |

## Examples

### Setup for Gmail
```bash
# Generate OTP for Gmail account
./otp -g john.doe@gmail.com -i Google -m

# Follow the instructions to create a QR code or use the manual key
# Save the password you used - you'll need it to access the OTP later
```

### Setup for Microsoft Account
```bash
# Generate OTP for Microsoft account
./otp -g john.doe@outlook.com -i Microsoft -m
```

### Daily Usage
```bash
# Quick code lookup
./otp -l john.doe@gmail.com.otp -s

# Monitor codes in real-time
./otp -l john.doe@gmail.com.otp -w
```

### Testing and Verification
```bash
# Verify a code from your authenticator app
./otp -l john.doe@gmail.com.otp -v 847291

# Output: ✓ Code 847291 is VALID
```

## Security Architecture

### Triple-Layer Encryption
The application implements a robust security model:

1. **Layer 1**: AES-256-CBC with unique salt and IV
2. **Layer 2**: AES-256-CBC with unique salt and IV
3. **Layer 3**: AES-256-CBC with unique salt and IV

Each layer uses PBKDF2 key derivation with 100,000 iterations and SHA-256.

### Memory Security
- Secrets are zeroed from memory after use
- No plaintext secrets in memory longer than necessary
- Volatile memory writes prevent compiler optimization

### File Security
Encrypted files contain:
- 3 random salts (16 bytes each)
- 3 random IVs (16 bytes each)
- Triple-encrypted secret data

Total overhead: 96 bytes + encrypted data

## How It Works

### TOTP Algorithm
1. Current Unix timestamp ÷ 30 seconds = time step
2. HMAC-SHA1(secret, time_step) = hash
3. Dynamic truncation of hash = 6-digit code

### QR Code Format
```
otpauth://totp/Issuer:Account?secret=BASE32SECRET&issuer=Issuer&algorithm=SHA1&digits=6&period=30
```

### File Format
```
[16 bytes salt1][16 bytes salt2][16 bytes salt3]
[16 bytes iv1][16 bytes iv2][16 bytes iv3]
[encrypted data (3 layers of AES)]
```

## Troubleshooting

### Build Issues

**Make not found:**
```bash
apt-get install make g++
```

**Compilation errors:**
Make sure you have a C++17 compatible compiler:
```bash
g++ --version  # Should be 7.0 or later
```

### Runtime Issues

**Wrong password:**
- Make sure you're using the same password you used when generating
- Passwords are case-sensitive

**Code not working:**
- Ensure your system clock is synchronized
- Check that you're using the correct OTP file
- Verify the code hasn't expired (30-second window)

**QR code generation:**
- This version provides URI and instructions for online QR generation
- Visit the suggested websites to create QR codes from the provided URI
- Alternatively, use the manual entry key

## File Structure

```
otp-generator/
├── main.cpp              # Command-line interface
├── OTPGenerator.h        # OTP generator header
├── OTPGenerator.cpp      # OTP implementation
├── QRGenerator.h         # QR code generator header
├── QRGenerator.cpp       # QR code implementation
├── CMakeLists.txt        # CMake build configuration
├── build.sh              # Build automation script
└── README.md             # This file
```

## Best Practices

1. **Password Security**
   - Use strong, unique passwords for each OTP file
   - Never share your OTP files or passwords
   - Store passwords in a password manager

2. **Backup Strategy**
   - Keep encrypted .otp files backed up securely
   - Store QR codes in a secure location as backup
   - Consider printing manual entry keys

3. **Usage Tips**
   - Use watch mode for frequent OTP entry
   - Verify codes before relying on them
   - Keep your system clock synchronized

## Technical Specifications

- **Algorithm**: TOTP (Time-based One-Time Password)
- **Hash Function**: HMAC-SHA1
- **Code Length**: 6 digits
- **Time Step**: 30 seconds
- **Encryption**: AES-256-CBC (3 layers)
- **Key Derivation**: PBKDF2-HMAC-SHA256 (100,000 iterations)
- **Encoding**: Base32 (RFC 4648)
- **Standard**: RFC 6238

## License

This project is provided as-is for educational and personal use.

## Security Notice

While this application implements strong security measures:
- Always use strong passwords
- Keep your system secure and updated
- Monitor for unauthorized access
- Use at your own risk

## Contributing

Feel free to submit issues, feature requests, or improvements.

## Support

For issues or questions:
1. Check the troubleshooting section
2. Review command-line help: `./build/bin/otp --help`
3. Ensure all dependencies are installed
