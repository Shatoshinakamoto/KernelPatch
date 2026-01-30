# Build and Deployment Guide

## Building the Application

### Method 1: Using Make (Recommended)

The simplest way to build:

```bash
cd otp-generator
make
```

This will:
1. Detect available libraries
2. Compile all source files
3. Link with OpenSSL
4. Create the `otp` executable

### Method 2: Using CMake

If you have OpenCV and full development packages:

```bash
mkdir build
cd build
cmake ..
make
```

### Method 3: Manual Compilation

```bash
g++ -std=c++17 -Wall -Wextra -O2 -I/usr/include/node \
    main.cpp OTPGenerator.cpp QRGenerator_noopencv.cpp \
    -o otp \
    -L/usr/lib/x86_64-linux-gnu \
    -l:libssl.so.3 -l:libcrypto.so.3
```

## Build Requirements

### Minimum Requirements
- **GCC/G++**: Version 7.0+ (C++17 support)
- **OpenSSL**: Runtime libraries (libssl.so.3, libcrypto.so.3)
- **Make**: For automated building

### Optional Requirements
- **OpenCV**: For image-based QR code generation
- **CMake**: For CMake-based builds

### Checking Your System

```bash
# Check GCC version
g++ --version

# Check for OpenSSL libraries
ls /usr/lib/x86_64-linux-gnu/libssl* /usr/lib/x86_64-linux-gnu/libcrypto*

# Check for Make
make --version
```

## Build Output

After successful compilation:
```
Building without OpenCV - QR codes will show URI only
Compiling main.cpp...
Compiling OTPGenerator.cpp...
Compiling QRGenerator_noopencv.cpp...
Linking otp...
Build complete! Executable: ./otp
```

The executable `otp` will be in the current directory.

## Testing the Build

### 1. Test Help Command
```bash
./otp --help
```

Expected output: Usage information and examples

### 2. Generate Test OTP
```bash
./otp -g test@example.com -i TestApp -m
```

You'll be prompted for a password. This creates:
- `test@example.com.otp` (encrypted secret file)
- Displays manual entry key
- Shows first OTP code

### 3. Load and Verify
```bash
# Show current code
./otp -l test@example.com.otp -s

# Test verification
./otp -l test@example.com.otp -v <code-from-above>
```

## Deployment

### Single User Installation

```bash
# Build the application
make

# Move to user's bin directory
mkdir -p ~/.local/bin
cp otp ~/.local/bin/

# Add to PATH if needed
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# Now you can run from anywhere
otp --help
```

### System-Wide Installation

```bash
# Build the application
make

# Install system-wide (requires root)
sudo cp otp /usr/local/bin/
sudo chmod +x /usr/local/bin/otp

# Now available to all users
otp --help
```

### WSL (Windows Subsystem for Linux)

The application works perfectly in WSL:

```bash
# In WSL terminal
cd /mnt/c/Users/YourName/otp-generator  # or wherever you placed it
make
./otp --help
```

## Cleaning Build Artifacts

```bash
# Remove compiled objects and executable
make clean

# Remove all generated files including test OTP files
rm -f *.o otp *.otp
```

## Troubleshooting Builds

### "command not found: make"
```bash
sudo apt-get update
sudo apt-get install build-essential
```

### "openssl/evp.h: No such file or directory"
The Makefile includes `/usr/include/node` which contains OpenSSL headers from Node.js.
If this fails, install OpenSSL development headers:
```bash
sudo apt-get install libssl-dev
```

### "cannot find -lssl"
The system has OpenSSL but not the development symlinks.
The Makefile uses direct library names (`libssl.so.3`) to work around this.

### "undefined reference to OpenCV"
If OpenCV functions fail, use the non-OpenCV version:
```bash
cp QRGenerator_noopencv.h QRGenerator.h
cp QRGenerator_noopencv.cpp QRGenerator.cpp
make clean
make
```

## Advanced Build Options

### Debug Build
```bash
make CXXFLAGS="-std=c++17 -g -O0 -I/usr/include/node"
```

### With Extra Warnings
```bash
make CXXFLAGS="-std=c++17 -Wall -Wextra -Wpedantic -O2 -I/usr/include/node"
```

### Static Linking (for portability)
```bash
g++ -std=c++17 -static -I/usr/include/node \
    main.cpp OTPGenerator.cpp QRGenerator_noopencv.cpp \
    -o otp-static \
    /usr/lib/x86_64-linux-gnu/libssl.a \
    /usr/lib/x86_64-linux-gnu/libcrypto.a \
    -lpthread -ldl
```

## Build for Distribution

To create a redistributable package:

```bash
# Clean build
make clean
make

# Create distribution directory
mkdir -p otp-generator-dist
cp otp README.md QUICKSTART.md otp-generator-dist/

# Create tarball
tar -czf otp-generator-linux-x64.tar.gz otp-generator-dist/

# Or create a self-extracting installer
cat > install.sh << 'EOF'
#!/bin/bash
echo "Installing OTP Generator..."
mkdir -p ~/.local/bin
cp otp ~/.local/bin/
chmod +x ~/.local/bin/otp
echo "Installation complete!"
echo "Run: otp --help"
EOF

chmod +x install.sh
```

## Security Notes

### Build Security
- Compiler flags include `-fstack-protector-strong` for stack protection
- Optimization level `-O2` balances performance and debugging
- No debug symbols in release builds

### Runtime Security
- Secrets never stored in plaintext
- Triple-layer AES-256 encryption
- Secure memory wiping on cleanup
- PBKDF2 with 100,000 iterations

## Platform-Specific Notes

### Ubuntu 20.04+
Works out of the box with:
```bash
make
```

### Ubuntu 18.04
May need to update GCC:
```bash
sudo add-apt-repository ppa:ubuntu-toolchain-r/test
sudo apt-get update
sudo apt-get install gcc-9 g++-9
export CXX=g++-9
make
```

### Debian 11+
Same as Ubuntu 20.04+

### Arch Linux
```bash
pacman -S base-devel openssl
make
```

### Alpine Linux
```bash
apk add build-base openssl-dev
make
```
