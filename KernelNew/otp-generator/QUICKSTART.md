# Quick Reference Guide

## Common Commands

### First Time Setup
```bash
# Build the application
./build.sh

# Generate OTP for Google account
./build/bin/otp -g myemail@gmail.com -i Google -q qr.png -m
```

### Daily Usage
```bash
# Show current code
./build/bin/otp -l myemail@gmail.com.otp -s

# Watch mode (live updates)
./build/bin/otp -l myemail@gmail.com.otp -w
```

### Testing
```bash
# Verify a code
./build/bin/otp -l myemail@gmail.com.otp -v 123456
```

## Workflow

1. **Generate**: Create OTP secret with QR code
   ```bash
   ./build/bin/otp -g account@example.com -i ServiceName -q output.png -m
   ```

2. **Scan**: Use authenticator app to scan QR code or enter manual key

3. **Verify**: Test that it works
   ```bash
   ./build/bin/otp -l account@example.com.otp -v CODE_FROM_APP
   ```

4. **Use**: Get codes when needed
   ```bash
   ./build/bin/otp -l account@example.com.otp -s
   ```

## Tips

- **Password**: You'll be prompted for a password when generating/loading
- **Files**: OTP secrets are saved as `account.otp` by default
- **Backup**: Keep your .otp files and QR codes safe
- **Security**: Use strong, unique passwords for each OTP file

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Build fails | Run `sudo apt-get install cmake g++ libopencv-dev libssl-dev` |
| Wrong password | Passwords are case-sensitive, try again |
| Code invalid | Check system time is correct |
| QR won't scan | Use manual entry key instead |
