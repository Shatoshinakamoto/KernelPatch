# Non Sudo Kernel Patch a Security Based Kernel Module

A Linux kernel security enhancement that restricts privileged operations to sudo users, preventing unauthorized access to critical system functions.

## Overview

This project provides a kernel-level security enhancement that prevents non-sudo users from performing various privileged operations. The module works by hooking into key kernel functions and verifying sudo privileges before allowing sensitive operations to proceed.

## Coming soon
Plans to include proper Encrypted Kernel Module install scripts for supported Distros.
Along with included into ansibly yaml for faster playbook deployments.
Keeping below for educational purposes using safing portmaster or firewall rules is sufficient within the existing Distros of linux alone no need to patch network calls.
https://safing.io/ or iptables or ufw.


## Potential Features
Include a Encrypted Install of the module via bash script and ansible yml
Release a seperate NodeJS PheonixBox Executable Kernel Patch as well for release to tamper proof and harden security for other open source distros.


### Key Features

- **Prevents UID/GID changes**: Non-sudo users cannot change their user or group IDs
- **Blocks hardware flashing**: Prevents unauthorized GPU and motherboard firmware flashing
- **Command blacklisting**: Configurable blacklist to prevent execution of privileged commands
- **Path restrictions**: Restricts non-sudo users to their home directories
- **Multi-distribution support**: Works across major Linux distributions

## Contents

This repository contains three main files:

1. `secure_kernel_build.sh` - Script to build and install the kernel with the secure_sudo patch
2. `secure_sudo.c` - The kernel module source code implementing the security features
3. `secure_kernel_deploy.yml` - Ansible playbook for deploying the patch across multiple systems

## Security Benefits

- Prevents privilege escalation attacks
- Blocks unauthorized hardware modifications
- Limits the impact of compromised user accounts
- Provides defense-in-depth by implementing security at the kernel level
- Configurable to match your security requirements

## Installation

### Prerequisites

- Root access to your Linux system
- Build tools for kernel compilation
- Sufficient disk space for kernel build (~10GB recommended)

### Detailed Installation Steps

#### Manual Installation (Single System)

1. Clone this repository:

```bash
git clone https://github.com/Sakimottonakatoshi/Non-Sudo-Kernel-Patch.git
cd Non-Sudo-Kernel-Patch
```

2. Make the build script executable:

```bash
chmod +x secure_kernel_build.sh
```

3. Execute the build script as root:

```bash
sudo ./secure_kernel_build.sh
```

4. The script will:
   - Detect your Linux distribution
   - Install necessary dependencies
   - Download the kernel source (version 5.15.0)
   - Apply the secure_sudo patch
   - Build and install the kernel
   - Set up configuration directories

5. After completion, reboot your system to apply the changes:

```bash
sudo reboot
```

6. Verify the installation:

```bash
# Check if the module is loaded
lsmod | grep secure_sudo

# Verify the sysfs interface exists
ls -la /sys/kernel/secure_sudo/
```

#### Deployment with Ansible (Multiple Systems)

1. Ensure Ansible is installed on your control machine:

```bash
# For Debian/Ubuntu
sudo apt update && sudo apt install ansible

# For RHEL/CentOS/Fedora
sudo dnf install ansible
```

2. Create an inventory file listing your target hosts:

```bash
# Example inventory file named 'hosts'
[servers]
server1.example.com
server2.example.com
192.168.1.10

[workstations]
workstation1.example.com
workstation2.example.com
```

3. Run the deployment playbook:

```bash
ansible-playbook -i hosts secure_kernel_deploy.yml
```

4. To run the playbook with additional options:

```bash
# To provide SSH password for the hosts
ansible-playbook -i hosts secure_kernel_deploy.yml --ask-pass

# To provide sudo password
ansible-playbook -i hosts secure_kernel_deploy.yml --ask-become-pass

# To run on specific hosts only
ansible-playbook -i hosts secure_kernel_deploy.yml --limit "server1.example.com"
```

#### Manual Kernel Module Installation (Advanced Users)

For users who want to install just the module without rebuilding the entire kernel:

1. Ensure you have kernel headers installed:

```bash
# For Debian/Ubuntu
sudo apt install linux-headers-$(uname -r)

# For RHEL/CentOS/Fedora
sudo dnf install kernel-devel
```

2. Compile the module directly:

```bash
# Create a simple Makefile
echo 'obj-m += secure_sudo.o' > Makefile
echo 'all:' >> Makefile
echo '	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules' >> Makefile
echo 'clean:' >> Makefile
echo '	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean' >> Makefile

# Build the module
make

# Install the module
sudo insmod secure_sudo.ko
```

3. Set up the configuration directory:

```bash
sudo mkdir -p /etc/secure_sudo
sudo cp blacklist.conf /etc/secure_sudo/
sudo chmod 600 /etc/secure_sudo/blacklist.conf
```

4. To load the module at boot time:

```bash
sudo cp secure_sudo.ko /lib/modules/$(uname -r)/kernel/security/
sudo depmod -a
sudo echo "secure_sudo" >> /etc/modules
```

## Configuration

### Blacklist Configuration

The module uses a blacklist configuration file located at `/etc/secure_sudo/blacklist.conf` to determine which commands non-sudo users are not allowed to execute.

To modify the blacklist:

1. Edit the configuration file:

```bash
sudo nano /etc/secure_sudo/blacklist.conf
```

2. Add or remove commands as needed (one per line)
3. Reload the blacklist:

```bash
echo 1 | sudo tee /sys/kernel/secure_sudo/reload
```

### Distribution-Specific Notes

The build script and Ansible playbook will automatically detect your Linux distribution and apply the appropriate build options. Currently supported distributions include:

- Ubuntu/Debian
- RHEL/CentOS/Fedora
- Arch/Manjaro
- openSUSE/SUSE

## Technical Details

### Kernel Integration

The secure_sudo module integrates with the Linux Security Module (LSM) framework to hook into key kernel functions:

- `path_permission` - For filesystem access control
- `task_fix_setuid` - For controlling UID/GID changes
- `bprm_check_security` - For checking command execution against blacklist

### Module Components

- **Security hooks**: Intercepts key kernel operations
- **Privilege verification**: Checks if users have sudo privileges
- **Blacklist management**: Loads and checks against the command blacklist
- **Path validation**: Ensures file access stays within permitted directories

## Warning and Compatibility

**⚠️ WARNING:** This module modifies your system kernel. Make sure to:

1. Backup important data before installation
2. Have an alternative boot option available
3. Test thoroughly in a non-production environment first

**Known compatibility issues:**
- May conflict with other security modules using the same LSM hooks
- Kernel version specific (designed for kernel 5.15.0)
- Some applications with setuid functionality may be affected

## Troubleshooting

### Common Issues

1. **Installation fails with build errors**
   - Ensure all dependencies are installed
   - Check kernel headers match your current kernel version

2. **System fails to boot after installation**
   - Boot with previous kernel version (select from GRUB menu)
   - Check kernel logs for errors: `journalctl -k`

3. **Legitimate commands are blocked**
   - Modify the blacklist configuration to allow necessary commands
   - Ensure proper sudo access for users who need privileged operations

### Logs and Debugging

The module logs security events to the kernel log, which can be viewed with:

```bash
dmesg | grep secure_sudo
```

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues to suggest improvements or report bugs.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

While the code will be Licensed by GPL-V3 while being further protected by the License I plan to include to ensure no one can revert to the lesser to take ownership by further protecting with a GPL-V3 license on this repository finalized.

## Author of this Repository 

- Johnathan Edward Brown ( Hand fixed Ansible Yaml Syntax which waz incorrectly generated by Anthropic outputs )

## Alpha & Beta Tested By ( Reach out to Repository owners Contact email https://github.com/Sakimottonakatoshi be verified as Alpha Testers for this. )
- Johnathan Edward Brown ( Alpha & Beta Ubuntu Distro Tested and Approved! )
- 

## Acknowledgments
- Anthropic for the generated base design template.
- Kernel-Security-Team
- The Linux kernel security community
- Contributors to the Linux Security Module framework

### Disclaimer
- The author nor the acknowledged community or the Kernel-Security-Team shall not be held liable for anything  simple as that case and point.

### Additional
I Sincerely Apologize to anyone this kernel patch has harmed by being made public. Not meant to claim credit or ownership of the contents or making of this kernel patch only in the process of helping debug and make production and easy to deploy.
