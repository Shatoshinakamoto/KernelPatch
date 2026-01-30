#!/bin/bash
#
# secure_kernel_build.sh - Build and install a kernel with secure_sudo patch
#
# This script:
# 1. Downloads and builds a specific kernel version
# 2. Patches it with the secure_sudo module
# 3. Installs the new kernel
# 4. Sets up configuration directories and files

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration variables
KERNEL_VERSION="5.15.0"
WORKDIR="/tmp/secure_kernel_build"
MODULE_SRC="secure_sudo.c"
CONFIG_DIR="/etc/secure_sudo"
BUILD_DEPS=""
KERNEL_CONFIG_PATH=""
DISTRO=""

# Function to detect Linux distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
    elif [ -f /etc/lsb-release ]; then
        . /etc/lsb-release
        DISTRO=$DISTRIB_ID
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
    elif [ -f /etc/redhat-release ]; then
        DISTRO="rhel"
    else
        echo -e "${RED}Unable to detect Linux distribution${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}Detected distribution: ${DISTRO}${NC}"
}

# Function for logging info messages
info() {
    echo -e "${GREEN}[INFO] $1${NC}"
}

# Function for logging warning messages
warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

# Function for logging error messages
error() {
    echo -e "${RED}[ERROR] $1${NC}"
    exit 1
}

# Function to install dependencies based on distribution
install_dependencies() {
    info "Installing build dependencies"
    
    case "$DISTRO" in
        "ubuntu"|"debian")
            BUILD_DEPS="build-essential libncurses-dev libssl-dev libelf-dev bison flex bc"
            apt-get update
            apt-get install -y $BUILD_DEPS
            ;;
        "fedora"|"rhel"|"centos")
            BUILD_DEPS="gcc make ncurses-devel openssl-devel elfutils-libelf-devel bison flex bc"
            if [ "$DISTRO" = "fedora" ]; then
                dnf install -y $BUILD_DEPS
            else
                yum install -y $BUILD_DEPS
            fi
            ;;
        "arch"|"manjaro")
            BUILD_DEPS="base-devel ncurses openssl libelf bison flex bc"
            pacman -Sy --noconfirm $BUILD_DEPS
            ;;
        "opensuse"|"suse")
            BUILD_DEPS="gcc make ncurses-devel openssl-devel libelf-devel bison flex bc"
            zypper install -y $BUILD_DEPS
            ;;
        *)
            error "Unsupported distribution: $DISTRO"
            ;;
    esac
    
    info "Dependencies installed successfully"
}

# Function to download kernel source
download_kernel() {
    info "Downloading Linux kernel $KERNEL_VERSION"
    
    mkdir -p "$WORKDIR"
    cd "$WORKDIR"
    
    # Download kernel source
    if [ ! -f "linux-$KERNEL_VERSION.tar.xz" ]; then
        wget "https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-$KERNEL_VERSION.tar.xz" || \
        error "Failed to download kernel source"
    fi
    
    # Extract kernel source
    if [ ! -d "linux-$KERNEL_VERSION" ]; then
        tar -xf "linux-$KERNEL_VERSION.tar.xz" || \
        error "Failed to extract kernel source"
    fi
    
    info "Kernel source downloaded and extracted"
}

# Function to prepare kernel configuration
prepare_kernel_config() {
    info "Preparing kernel configuration"
    
    cd "$WORKDIR/linux-$KERNEL_VERSION"
    
    # Determine current kernel config
    if [ -f "/boot/config-$(uname -r)" ]; then
        cp "/boot/config-$(uname -r)" .config
    else
        case "$DISTRO" in
            "ubuntu"|"debian")
                make defconfig
                ;;
            "fedora"|"rhel"|"centos")
                make defconfig
                ;;
            "arch"|"manjaro")
                make defconfig
                ;;
            "opensuse"|"suse")
                make defconfig
                ;;
            *)
                error "Could not determine kernel configuration"
                ;;
        esac
    fi
    
    # Enable module support and other necessary options
    sed -i 's/# CONFIG_MODULES is not set/CONFIG_MODULES=y/' .config 2>/dev/null || true
    sed -i 's/# CONFIG_MODULE_UNLOAD is not set/CONFIG_MODULE_UNLOAD=y/' .config 2>/dev/null || true
    sed -i 's/# CONFIG_SECURITY is not set/CONFIG_SECURITY=y/' .config 2>/dev/null || true
    
    # Update configuration
    yes "" | make oldconfig
    
    info "Kernel configuration prepared"
}

# Function to create and add secure_sudo module
add_secure_module() {
    info "Adding secure_sudo module to kernel"
    
    cd "$WORKDIR/linux-$KERNEL_VERSION"
    
    # Create directory for our module
    mkdir -p "security/secure_sudo"
    
    # Copy module source
    cp "$MODULE_SRC" "security/secure_sudo/secure_sudo.c"
    
    # Create Makefile for the module
    cat > "security/secure_sudo/Makefile" << EOF
obj-y += secure_sudo.o
EOF
    
    # Update security Makefile
    if ! grep -q "secure_sudo" "security/Makefile"; then
        echo "obj-y += secure_sudo/" >> "security/Makefile"
    fi
    
    # Modify security initialization to include our module
    if ! grep -q "secure_sudo_init" "security/security.c"; then
        # This is a simplified example - in a real scenario, you'd need to 
        # properly integrate with the LSM framework
        sed -i '/^int __init security_init(void)/a \\textern int secure_sudo_init(void);\n\tsecure_sudo_init();' "security/security.c"
    fi
    
    info "Secure module added to kernel"
}

# Function to build the kernel
build_kernel() {
    info "Building kernel (this may take a while)"
    
    cd "$WORKDIR/linux-$KERNEL_VERSION"
    
    # Set number of build threads based on CPU cores
    THREADS=$(nproc)
    
    # Build the kernel and modules
    make -j$THREADS || error "Kernel build failed"
    make modules -j$THREADS || error "Module build failed"
    
    info "Kernel build completed successfully"
}

# Function to install the kernel
install_kernel() {
    info "Installing kernel"
    
    cd "$WORKDIR/linux-$KERNEL_VERSION"
    
    # Install modules
    make modules_install || error "Failed to install modules"
    
    # Install kernel (distro-specific)
    case "$DISTRO" in
        "ubuntu"|"debian")
            make install || error "Failed to install kernel"
            update-grub || warn "Failed to update GRUB, you may need to do this manually"
            ;;
        "fedora"|"rhel"|"centos")
            make install || error "Failed to install kernel"
            if command -v grub2-mkconfig &> /dev/null; then
                grub2-mkconfig -o /boot/grub2/grub.cfg || warn "Failed to update GRUB, you may need to do this manually"
            else
                warn "GRUB update command not found, you may need to update your bootloader manually"
            fi
            ;;
        "arch"|"manjaro")
            make install || error "Failed to install kernel"
            if command -v grub-mkconfig &> /dev/null; then
                grub-mkconfig -o /boot/grub/grub.cfg || warn "Failed to update GRUB, you may need to do this manually"
            else
                warn "GRUB update command not found, you may need to update your bootloader manually"
            fi
            ;;
        "opensuse"|"suse")
            make install || error "Failed to install kernel"
            if command -v update-bootloader &> /dev/null; then
                update-bootloader || warn "Failed to update bootloader, you may need to do this manually"
            else
                warn "Bootloader update command not found, you may need to update your bootloader manually"
            fi
            ;;
        *)
            error "Unsupported distribution for kernel installation"
            ;;
    esac
    
    info "Kernel installed successfully"
}

# Function to setup configuration
setup_config() {
    info "Setting up configuration"
    
    # Create configuration directory
    mkdir -p "$CONFIG_DIR"
    
    # Create default blacklist configuration
    cat > "$CONFIG_DIR/blacklist.conf" << EOF
# Secure Sudo Blacklist Configuration
# List of commands that non-sudo users are not allowed to execute
# One command per line, comments start with #

# System control commands
systemctl
service
init
telinit
poweroff
reboot
shutdown

# Network control commands
ifconfig
ip
route
iptables
ufw

# Process control commands
kill
pkill
killall

# Package management
apt
apt-get
dpkg
snap
dnf
yum
zypper
pacman

# User management
useradd
usermod
userdel
groupadd
groupmod
groupdel
passwd

# Hardware control
hdparm
flashrom
nvflash
EOF
    
    # Set proper permissions
    chmod 600 "$CONFIG_DIR/blacklist.conf"
    chown root:root "$CONFIG_DIR/blacklist.conf"
    
    info "Configuration setup complete"
}

# Main function
main() {
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        error "This script must be run as root"
    fi
    
    # Check if source file exists
    if [ ! -f "$MODULE_SRC" ]; then
        error "Module source file not found: $MODULE_SRC"
    fi
    
    # Detect distribution
    detect_distro
    
    # Install dependencies
    install_dependencies
    
    # Download kernel source
    download_kernel
    
    # Prepare kernel config
    prepare_kernel_config
    
    # Add secure module to kernel
    add_secure_module
    
    # Build kernel
    build_kernel
    
    # Install kernel
    install_kernel
    
    # Setup configuration
    setup_config
    
    info "Secure kernel installation completed successfully"
    info "Please reboot your system to use the new kernel"
}

# Run main function
main
