# Usage Examples and Workflows

## Complete Workflows

### Workflow 1: Setting up Gmail 2FA

**Step 1: Generate OTP Secret**
```bash
./otp -g john.doe@gmail.com -i Google -m
```

Output:
```
=== Generating New OTP Secret ===

Secret generated successfully!
Account: john.doe@gmail.com
Issuer: Google

Manual Entry Key (Base32):
  JBSWY3DPEHPK3PXP

Enter this key in your authenticator app if QR scan fails.

Enter password to encrypt and save secret: [enter password]
Secret saved to: john.doe@gmail.com.otp

Keep this file and password safe!

Current OTP Code: 123456
```

**Step 2: Add to Google Authenticator**

1. Open Google Authenticator app
2. Tap "+" to add account
3. Choose "Enter a setup key"
4. Enter:
   - Account: john.doe@gmail.com
   - Key: JBSWY3DPEHPK3PXP
   - Type: Time-based
5. Tap "Add"

**Step 3: Verify It Works**
```bash
./otp -l john.doe@gmail.com.otp -s
# Compare with Google Authenticator app
```

**Step 4: Test on Gmail**
1. Go to Gmail 2FA settings
2. Enter the OTP code from Google Authenticator
3. Complete setup

**Step 5: Daily Use**
```bash
# Quick lookup when needed
./otp -l john.doe@gmail.com.otp -s

# Or watch mode for multiple logins
./otp -l john.doe@gmail.com.otp -w
```

---

### Workflow 2: Microsoft Account Setup

```bash
# Generate
./otp -g user@outlook.com -i Microsoft -m

# Add to Microsoft Authenticator
# Use the manual entry key displayed

# Verify
./otp -l user@outlook.com.otp -v [code-from-app]

# Daily use
./otp -l user@outlook.com.otp -s
```

---

### Workflow 3: Multiple Accounts

**Setup multiple accounts:**
```bash
# Work email
./otp -g work@company.com -i Company -m

# Personal Gmail
./otp -g personal@gmail.com -i Google -m

# Banking
./otp -g user@bank.com -i MyBank -m

# GitHub
./otp -g username -i GitHub -m
```

**Create a helper script for quick access:**
```bash
#!/bin/bash
# otp-menu.sh

echo "Select account:"
echo "1) Work Email"
echo "2) Personal Gmail"
echo "3) Bank"
echo "4) GitHub"
read -p "Choice: " choice

case $choice in
    1) ./otp -l work@company.com.otp -s ;;
    2) ./otp -l personal@gmail.com.otp -s ;;
    3) ./otp -l user@bank.com.otp -s ;;
    4) ./otp -l username.otp -s ;;
esac
```

---

## Command Reference with Examples

### Generate New OTP

**Basic generation:**
```bash
./otp -g account@service.com -i ServiceName -m
```

**With custom issuer:**
```bash
./otp -g myemail@example.com -i "My Company" -m
```

**For username-based services:**
```bash
./otp -g myusername -i GitHub -m
```

---

### Show Current Code

**Single lookup:**
```bash
./otp -l account.otp -s
```

**With manual key:**
```bash
./otp -l account.otp -s -m
```

**Multiple accounts quickly:**
```bash
for file in *.otp; do
    echo "=== $file ==="
    echo "password" | ./otp -l "$file" -s
done
```

---

### Watch Mode

**Basic watch:**
```bash
./otp -l account.otp -w
```

Example output:
```
=== Watch Mode (Press Ctrl+C to exit) ===

Current Code: 123456  (valid for 23s)
Current Code: 123456  (valid for 22s)
Current Code: 123456  (valid for 21s)
...
Current Code: 789012  (valid for 30s)  [New code!]
```

**Watch multiple accounts (requires tmux or screen):**
```bash
# Terminal 1
./otp -l work@company.com.otp -w

# Terminal 2
./otp -l personal@gmail.com.otp -w
```

---

### Verify Codes

**Verify current code:**
```bash
./otp -l account.otp -v 123456
```

**Automated verification:**
```bash
#!/bin/bash
CODE=$(echo "password" | ./otp -l account.otp -s | grep "Current OTP" | awk '{print $4}')
echo "password" | ./otp -l account.otp -v "$CODE"
```

**Test synchronization:**
```bash
# Get code from app
echo "Enter code from authenticator app:"
read APP_CODE

# Verify it matches
./otp -l account.otp -v "$APP_CODE"
```

---

### Get Manual Entry Key

**Show key for existing OTP:**
```bash
./otp -l account.otp -m
```

**Save key to file for backup:**
```bash
echo "password" | ./otp -l account.otp -m > backup-key.txt
```

---

## Advanced Usage

### Automation Scripts

**Auto-fill OTP (with xdotool):**
```bash
#!/bin/bash
# auto-otp.sh
CODE=$(echo "your_password" | ./otp -l account.otp -s | grep "Current" | awk '{print $4}')
xdotool type "$CODE"
```

**OTP to clipboard:**
```bash
#!/bin/bash
# otp-clipboard.sh
CODE=$(echo "your_password" | ./otp -l $1 -s | grep "Current" | awk '{print $4}')
echo -n "$CODE" | xclip -selection clipboard
echo "OTP code copied to clipboard!"
```

Usage:
```bash
./otp-clipboard.sh work@company.com.otp
```

---

### Backup and Restore

**Backup all OTP files:**
```bash
#!/bin/bash
# backup-otp.sh

BACKUP_DIR="$HOME/otp-backup-$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Copy encrypted files
cp *.otp "$BACKUP_DIR/"

# Create encrypted archive
tar -czf - "$BACKUP_DIR" | \
    openssl enc -aes-256-cbc -salt -pbkdf2 -out otp-backup.tar.gz.enc

# Securely delete temporary backup
shred -vfz -n 3 "$BACKUP_DIR"/*.otp
rmdir "$BACKUP_DIR"

echo "Backup saved to: otp-backup.tar.gz.enc"
```

**Restore from backup:**
```bash
#!/bin/bash
# restore-otp.sh

openssl enc -d -aes-256-cbc -pbkdf2 -in otp-backup.tar.gz.enc | \
    tar -xzf -

echo "Backup restored!"
```

---

### Integration with Password Managers

**KeePassXC:**
1. Create entry for OTP file
2. Attach .otp file to entry
3. Store password in entry
4. Add custom command:
   ```
   /path/to/otp -l {ATTACHMENT} -s
   ```

**Pass (password-store):**
```bash
#!/bin/bash
# Add to password store
pass insert otp/work@company.com

# Helper script
pass show otp/work@company.com | ./otp -l work@company.com.otp -s
```

---

### Cron Jobs for Monitoring

**Check OTP synchronization:**
```bash
# crontab entry
0 */6 * * * /path/to/check-otp-sync.sh

# check-otp-sync.sh
#!/bin/bash
for file in /path/to/otps/*.otp; do
    if ! echo "password" | ./otp -l "$file" -s > /dev/null 2>&1; then
        echo "WARNING: Failed to access $file" | mail -s "OTP Error" admin@example.com
    fi
done
```

---

## Real-World Scenarios

### Scenario 1: Lost Phone

**Problem:** Lost phone with Google Authenticator

**Solution:**
```bash
# You still have the .otp files!
./otp -l gmail.otp -s
# Use this code to log in

# Set up new phone:
./otp -l gmail.otp -m
# Enter this key in new Google Authenticator
```

---

### Scenario 2: New Computer Setup

**Old computer (backup):**
```bash
# Create backup of all OTP files
tar -czf otp-backup.tar.gz *.otp
# Transfer otp-backup.tar.gz to new computer
```

**New computer (restore):**
```bash
# Extract backup
tar -xzf otp-backup.tar.gz

# Test each one
./otp -l gmail.otp -s
./otp -l work.otp -s
```

---

### Scenario 3: Sharing Access (Team Account)

**Setup (by admin):**
```bash
# Generate OTP
./otp -g team@company.com -i Company -m

# Share these securely:
# 1. The .otp file (via encrypted channel)
# 2. The password (via separate channel)
# 3. The manual key (as backup, via third channel)
```

**Usage (by team member):**
```bash
# Copy received .otp file
# Enter password when prompted
./otp -l team@company.com.otp -s
```

---

### Scenario 4: Audit Trail

**Log all OTP usage:**
```bash
#!/bin/bash
# otp-logged.sh

ACCOUNT=$1
LOGFILE="$HOME/.otp-usage.log"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Accessing $ACCOUNT" >> "$LOGFILE"

./otp -l "$ACCOUNT" -s

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Code displayed for $ACCOUNT" >> "$LOGFILE"
```

**Review logs:**
```bash
cat ~/.otp-usage.log
```

---

## Troubleshooting Examples

### Problem: Codes Don't Match

**Check time synchronization:**
```bash
# Check system time
date

# Sync time (if needed)
sudo ntpdate pool.ntp.org
# or
sudo systemctl restart systemd-timesyncd
```

**Verify with multiple time windows:**
```bash
# Current code
./otp -l account.otp -s

# Try verification with larger window
# (modify verifyOTP in code to use windowSize=2)
```

---

### Problem: Password Forgotten

Unfortunately, passwords cannot be recovered due to encryption.

**Solutions:**
1. **If you have backup of manual key:**
   ```bash
   # Create new OTP file
   ./otp -g account@service.com -i Service -m
   # Set the secret manually (requires code modification)
   ```

2. **Best practice - prevent this:**
   - Store passwords in password manager
   - Keep backup of manual keys separately
   - Document which password goes with which file

---

## Tips and Tricks

### Quick Access Alias

Add to `~/.bashrc`:
```bash
alias otp-work='echo "password" | /path/to/otp -l work@company.com.otp -s'
alias otp-gmail='echo "password" | /path/to/otp -l gmail.otp -s'

# Usage:
otp-work
otp-gmail
```

### Function for Easy Management

```bash
# Add to ~/.bashrc
otp() {
    local file="$HOME/.otp-files/$1.otp"
    if [ ! -f "$file" ]; then
        echo "Unknown account: $1"
        echo "Available accounts:"
        ls -1 "$HOME/.otp-files/" | sed 's/.otp$//'
        return 1
    fi
    /path/to/otp -l "$file" -s
}

# Usage:
otp work
otp gmail
otp github
```

### Desktop Notification

```bash
#!/bin/bash
# otp-notify.sh
CODE=$(echo "password" | ./otp -l $1 -s | grep "Current" | awk '{print $4}')
notify-send "OTP Code" "$CODE" -t 30000
```

### Integration with dmenu/rofi

```bash
#!/bin/bash
# otp-dmenu.sh
SELECTION=$(ls *.otp | sed 's/.otp$//' | dmenu -p "Select OTP:")
CODE=$(echo "password" | ./otp -l "$SELECTION.otp" -s | grep "Current" | awk '{print $4}')
echo -n "$CODE" | xclip -selection clipboard
notify-send "OTP" "Code copied to clipboard"
```

---

## Security Best Practices in Use

1. **Never store passwords in scripts** - use password manager or prompt
2. **Clear terminal history** after entering passwords
3. **Use watch mode** instead of repeatedly entering password
4. **Backup .otp files** regularly and securely
5. **Test recovery procedure** before disaster strikes
6. **Keep manual keys** in separate secure location
7. **Use unique passwords** for each .otp file
8. **Verify codes work** immediately after setup

---

## Getting Help

Common command patterns:

```bash
# Show help
./otp --help

# Generate with verbose output
./otp -g account -i Issuer -m

# Show current code (most common)
./otp -l file.otp -s

# Watch mode (continuous)
./otp -l file.otp -w

# Verify specific code
./otp -l file.otp -v 123456

# Get manual key for backup
./otp -l file.otp -m
```
