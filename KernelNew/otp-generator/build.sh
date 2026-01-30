#!/bin/bash

echo "=== OTP Generator Build Script ==="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if required packages are installed
echo "Checking dependencies..."

check_package() {
    if dpkg -l | grep -q "^ii  $1"; then
        echo -e "${GREEN}✓${NC} $1 is installed"
        return 0
    else
        echo -e "${RED}✗${NC} $1 is not installed"
        return 1
    fi
}

MISSING_DEPS=0

# Check for required packages
for pkg in cmake g++ libopencv-dev libssl-dev; do
    if ! check_package $pkg; then
        MISSING_DEPS=1
    fi
done

if [ $MISSING_DEPS -eq 1 ]; then
    echo ""
    echo -e "${YELLOW}Installing missing dependencies...${NC}"
    sudo apt-get update
    sudo apt-get install -y cmake g++ libopencv-dev libssl-dev
fi

echo ""
echo "Creating build directory..."
mkdir -p build
cd build

echo "Running CMake..."
cmake .. -DCMAKE_BUILD_TYPE=Release

if [ $? -ne 0 ]; then
    echo -e "${RED}CMake configuration failed!${NC}"
    exit 1
fi

echo ""
echo "Building project..."
make -j$(nproc)

if [ $? -ne 0 ]; then
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}=== Build Successful! ===${NC}"
echo ""
echo "Executable location: build/bin/otp"
echo ""
echo "To run the application:"
echo "  ./build/bin/otp --help"
echo ""
echo "Example usage:"
echo "  # Generate new OTP"
echo "  ./build/bin/otp -g myemail@gmail.com -i Google -q qrcode.png -m"
echo ""
echo "  # Show current code"
echo "  ./build/bin/otp -l myemail@gmail.com.otp -s"
echo ""
echo "  # Watch mode (live updates)"
echo "  ./build/bin/otp -l myemail@gmail.com.otp -w"
