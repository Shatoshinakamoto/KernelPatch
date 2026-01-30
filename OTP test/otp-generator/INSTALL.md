# Installation Guide - OTP Generator

## Package Information

**File:** otp-generator-complete.tar.gz
**Size:** 51 KB (compressed)
**MD5:** fa4d04a976a44ef580b2391c404ea2ef
**Platform:** Linux x86_64
**Version:** 1.0.0

## What's Inside

This complete package includes:
- ✓ All C++ source code (main.cpp, OTPGenerator.cpp, etc.)
- ✓ Pre-compiled binary (otp)
- ✓ Build system (Makefile, CMakeLists.txt)
- ✓ Complete documentation (README, guides, examples)
- ✓ Quick reference card

## Installation Steps

### Method 1: Extract and Run (Fastest)

```bash
# Extract the archive
tar -xzf otp-generator-complete.tar.gz

# Enter the directory
cd otp-generator

# Run immediately (using pre-compiled binary)
./otp --help

# Test with example
./otp -g test@example.com -i TestApp -m
```

### Method 2: Build from Source

```bash
# Extract the archive
tar -xzf otp-generator-complete.tar.gz
cd otp-generator

# Build using Make
make clean
make

# Run
./otp --help
```

### Method 3: System-Wide Installation

```bash
# Extract and build
tar -xzf otp-generator-complete.tar.gz
cd otp-generator
make

# Install system-wide (requires sudo)
sudo cp otp /usr/local/bin/
sudo chmod +x /usr/local/bin/otp

# Now available from anywhere
otp --help
```

### Method 4: User Installation (No sudo)

```bash
# Extract and build
tar -xzf otp-generator-complete.tar.gz
cd otp-generator
make

# Install to user directory
mkdir -p ~/.local/bin
cp otp ~/.local/bin/

# Add to PATH (if not already)
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# Now available from anywhere
otp --help
```

## Verification Steps

### 1. Verify Archive Integrity

```bash
# Check MD5 checksum
md5sum otp-generator-complete.tar.gz
# Should output: fa4d04a976a44ef580b2391c404ea2ef

# Or SHA256
sha256sum otp-generator-complete.tar.gz
```

### 2. Verify Extraction

```bash
# List contents before extracting
tar -tzf otp-generator-complete.tar.gz | head -20

# Should see:
# otp-generator/
# otp-generator/main.cpp
# otp-generator/OTPGenerator.cpp
# otp-generator/README.md
# ... etc
```

### 3. Verify Binary

```bash
cd otp-generator

# Check binary type
file otp
# Should show: ELF 64-bit LSB executable, x86-64

# Check it's executable
ls -l otp
# Should show: -rwxr-xr-x (executable permissions)

# Test help command
./otp --help
# Should display usage information
```

### 4. Functional Test

```bash
# Generate test OTP (will prompt for password)
./otp -g test@example.com -i TestApp -m

# Load and show code (use same password)
./otp -l test@example.com.otp -s

# Should display a 6-digit code
```

## Troubleshooting Installation

### Issue: "tar: command not found"

```bash
# Install tar
sudo apt-get install tar
```

### Issue: "make: command not found"

```bash
# Use the pre-compiled binary instead
./otp --help

# Or install build tools
sudo apt-get install build-essential
```

### Issue: Binary won't run

```bash
# Check architecture
uname -m
# Should be: x86_64

# If different, rebuild from source:
make clean
make
```

### Issue: Permission denied

```bash
# Make executable
chmod +x otp

# Then run
./otp --help
```

### Issue: Library not found

```bash
# Check for OpenSSL
ldd ./otp

# If libssl.so.3 or libcrypto.so.3 missing:
sudo apt-get install libssl3

# Or rebuild with system libraries:
make clean
make
```

## Directory Structure After Installation

```
otp-generator/
├── otp                      # Executable
├── main.cpp                 # Source files
├── OTPGenerator.cpp
├── OTPGenerator.h
├── QRGenerator.cpp
├── QRGenerator.h
├── QRGenerator_noopencv.cpp
├── QRGenerator_noopencv.h
├── Makefile                 # Build files
├── CMakeLists.txt
├── build.sh
├── README.md                # Documentation
├── QUICKSTART.md
├── BUILD.md
├── SECURITY.md
├── EXAMPLES.md
├── PROJECT_SUMMARY.md
├── QUICK_REFERENCE.txt
└── PACKAGE_MANIFEST.txt
```

## First-Time Setup Workflow

```bash
# 1. Extract
tar -xzf otp-generator-complete.tar.gz
cd otp-generator

# 2. Read quick start
cat QUICKSTART.md

# 3. Generate your first OTP
./otp -g myemail@gmail.com -i Google -m

# 4. Save the manual entry key displayed
# (Add it to Google Authenticator or Microsoft Authenticator)

# 5. Test verification
./otp -l myemail@gmail.com.otp -v [code-from-app]

# 6. Daily usage
./otp -l myemail@gmail.com.otp -s
```

## Documentation Guide

After installation, read in this order:

1. **QUICK_REFERENCE.txt** - One-page overview
2. **QUICKSTART.md** - Basic commands
3. **README.md** - Full features and usage
4. **EXAMPLES.md** - Real-world scenarios
5. **BUILD.md** - Building and deployment
6. **SECURITY.md** - Security architecture

## Uninstallation

```bash
# If installed system-wide
sudo rm /usr/local/bin/otp

# If installed in user directory
rm ~/.local/bin/otp

# Remove source directory
rm -rf otp-generator

# Remove any generated OTP files (backup first!)
rm *.otp
```

## Backup Recommendations

After generating OTP secrets:

1. **Backup .otp files** - Keep in secure, encrypted location
2. **Document passwords** - Store in password manager
3. **Save manual keys** - Keep separate from .otp files
4. **Test recovery** - Verify you can restore from backups

## Getting Help

After installation, access help:

```bash
# Built-in help
./otp --help

# Read documentation
cat README.md
cat QUICKSTART.md

# View examples
cat EXAMPLES.md
```

## Next Steps

1. ✓ Extract and verify installation
2. ✓ Test with example account
3. ✓ Generate OTP for real account
4. ✓ Add to authenticator app
5. ✓ Verify codes match
6. ✓ Backup .otp file and password
7. ✓ Read full documentation

## Support

For issues or questions:
- Check README.md for usage information
- Check BUILD.md for compilation issues
- Check SECURITY.md for security questions
- Check EXAMPLES.md for usage patterns

## System Requirements

**Minimum:**
- Linux kernel 3.10+
- x86_64 architecture
- 1 MB disk space
- OpenSSL 3.0+ runtime

**Recommended:**
- Ubuntu 20.04+ or Debian 11+
- 10 MB disk space (with docs)
- Build tools (for compilation)

**Tested On:**
- Ubuntu 20.04, 22.04, 24.04
- Debian 11, 12
- WSL (Windows Subsystem for Linux)

## License

This software is provided as-is for educational and personal use.

## Version History

- **v1.0.0** (Jan 30, 2026) - Initial release
  - Triple-layer AES-256 encryption
  - TOTP implementation (RFC 6238)
  - Full Google/Microsoft Authenticator support
  - Complete CLI interface
  - Comprehensive documentation
