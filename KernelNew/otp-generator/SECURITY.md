# Security Documentation

## Overview

This OTP generator implements multiple layers of security to protect your time-based one-time password secrets. This document explains the security architecture, threat model, and best practices.

## Security Features

### 1. Triple-Layer AES Encryption

The application uses a unique triple-layer encryption system:

```
Plaintext Secret
    ↓ [AES-256-CBC with Key1]
Encrypted Layer 1
    ↓ [AES-256-CBC with Key2]
Encrypted Layer 2
    ↓ [AES-256-CBC with Key3]
Final Encrypted Data
```

**Why Three Layers?**
- Defense in depth: Multiple independent encryption layers
- Each layer uses unique keys derived from the same password
- Different salts and IVs for each layer
- Protects against potential weaknesses in any single encryption layer

### 2. Key Derivation Function (KDF)

Each encryption layer uses PBKDF2-HMAC-SHA256:

```
Password + Salt → PBKDF2(100,000 iterations) → 256-bit Key
```

**Parameters:**
- Algorithm: PBKDF2-HMAC-SHA256
- Iterations: 100,000 per layer (300,000 total)
- Salt size: 16 bytes (128 bits) per layer
- Output key size: 32 bytes (256 bits) per layer

**Why 100,000 iterations?**
- OWASP recommends 310,000+ for PBKDF2-HMAC-SHA256
- We use 100,000 per layer × 3 layers = 300,000 equivalent iterations
- Balances security with reasonable unlock time
- Makes brute-force attacks computationally expensive

### 3. Initialization Vectors (IVs)

Each encryption layer uses a unique, randomly generated IV:

- Size: 16 bytes (128 bits)
- Generation: OpenSSL's RAND_bytes() (cryptographically secure)
- Usage: Never reused, stored with encrypted data

### 4. Random Number Generation

All random data (secrets, salts, IVs) uses OpenSSL's cryptographically secure RNG:

```cpp
RAND_bytes(buffer, length)
```

This uses the operating system's entropy sources:
- `/dev/urandom` on Linux
- Hardware RNG if available
- Properly seeded from multiple entropy sources

### 5. Memory Security

**Secure Zeroing:**
```cpp
void secureZero(void* ptr, size_t size) {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (size--) {
        *p++ = 0;
    }
}
```

- `volatile` prevents compiler optimization from removing the zeroing
- Called in destructor to clear secrets from memory
- Applies to all sensitive data before deallocation

**Memory Handling:**
- Secrets stored in `std::vector<uint8_t>` (automatically cleared)
- No plaintext secrets written to disk
- Minimal time in memory (only during active use)

### 6. TOTP Algorithm (RFC 6238)

Standard time-based one-time password implementation:

```
Time = Current Unix Timestamp / 30 seconds
Message = Time as 8-byte big-endian
Hash = HMAC-SHA1(Secret, Message)
Code = Dynamic Truncation(Hash) % 1,000,000
```

**Security Properties:**
- 30-second time window
- 6-digit codes (1 million possibilities)
- HMAC-SHA1 prevents forgery
- Time synchronization required

## File Format

Encrypted `.otp` files contain:

```
[Byte 0-15]    Salt 1 (16 bytes)
[Byte 16-31]   Salt 2 (16 bytes)
[Byte 32-47]   Salt 3 (16 bytes)
[Byte 48-63]   IV 1 (16 bytes)
[Byte 64-79]   IV 2 (16 bytes)
[Byte 80-95]   IV 3 (16 bytes)
[Byte 96+]     Triple-encrypted secret
```

**Properties:**
- Fixed 96-byte header
- All salts and IVs are unique and random
- No metadata stored (account name, issuer not in file)
- File size varies based on secret length + padding

## Threat Model

### What We Protect Against

✓ **File Theft:** Encrypted files are useless without password
✓ **Weak Passwords:** PBKDF2 makes brute-force expensive
✓ **Memory Dumps:** Secrets zeroed from memory when done
✓ **Cryptographic Weakness:** Triple-layer protects against single-layer breaks
✓ **Dictionary Attacks:** High iteration count increases attack cost
✓ **Known Plaintext:** Unique IVs and salts per file

### What We Don't Protect Against

✗ **Keylogging:** If password is captured during entry
✗ **Screen Capture:** OTP codes visible on screen
✗ **Malware:** Malicious software with system access
✗ **Physical Access:** Unencrypted codes shown during use
✗ **Social Engineering:** User voluntarily revealing passwords/codes

## Attack Resistance

### Brute Force Attack Analysis

**Assumptions:**
- Attacker has encrypted .otp file
- Attacker knows the algorithm (Kerckhoffs's principle)
- Attacker does not have the password

**Attack Cost:**

For a password with:
- 8 characters (lowercase + uppercase + numbers + symbols)
- Character space: ~94 characters
- Possible combinations: 94^8 ≈ 6.1 × 10^15

With triple-layer PBKDF2 (300,000 equivalent iterations):
- Time per attempt: ~0.3 seconds (modern CPU)
- Total time: 6.1 × 10^15 × 0.3s ≈ 58 million years

**Conclusion:** Properly chosen passwords (12+ characters) make brute force infeasible.

### Side-Channel Resistance

**Timing Attacks:**
- HMAC operations are constant-time
- Password verification uses constant-time comparison

**Power Analysis:**
- Not applicable (software implementation)
- Would require physical access to hardware during decryption

## Best Practices

### Password Selection

**Good Passwords:**
```
- "Tr0p1cal!Sunset#2024$Rain"    (27 chars, mixed)
- "correct-horse-battery-staple"  (28 chars, memorable)
- "MyD0g@t3$1x#Tr3ats!Daily"     (24 chars, personal)
```

**Bad Passwords:**
```
- "password123"     (too common)
- "12345678"        (too simple)
- "qwerty"          (dictionary word)
- "admin"           (default-like)
```

**Password Requirements:**
- Minimum 12 characters (recommended)
- Mix of uppercase, lowercase, numbers, symbols
- Not in any dictionary or common password list
- Unique per OTP file

### File Storage

**Secure:**
```
✓ Encrypted disk (LUKS, FileVault, BitLocker)
✓ Password manager with file attachment support
✓ Encrypted cloud storage (with separate password)
✓ USB drive in secure location
```

**Insecure:**
```
✗ Email attachments
✗ Public cloud storage (Dropbox, Google Drive without encryption)
✗ Shared network drives
✗ Temporary directories (/tmp)
```

### Backup Strategy

1. **Primary:** Keep .otp file on encrypted disk
2. **Secondary:** Store in password manager
3. **Tertiary:** Keep manual entry key in safe location
4. **Emergency:** Printed QR code in locked drawer

### Operational Security

**Do:**
- Use strong, unique passwords for each .otp file
- Keep passwords in a password manager
- Verify OTP codes work before relying on them
- Keep system clock synchronized (NTP)
- Store backup of .otp files securely
- Clear terminal history if it contains passwords

**Don't:**
- Store passwords in plaintext
- Share .otp files or passwords
- Use the same password for multiple OTP files
- Store passwords in the same location as .otp files
- Enter passwords on untrusted systems
- Leave terminal window open showing OTP codes

## Compliance and Standards

### Standards Implemented

- **RFC 6238:** TOTP (Time-Based One-Time Password Algorithm)
- **RFC 4226:** HOTP (HMAC-Based One-Time Password)
- **RFC 4648:** Base32 Encoding
- **FIPS 180-4:** SHA-1 and SHA-256
- **FIPS 198-1:** HMAC

### Cryptographic Recommendations

Following NIST SP 800-132 (Password-Based Key Derivation):
- ✓ Use of PBKDF2
- ✓ Minimum 10,000 iterations (we use 100,000)
- ✓ Unique salt per key derivation
- ✓ Sufficient salt length (128 bits)

Following OWASP guidelines:
- ✓ AES-256 for encryption
- ✓ CBC mode with proper IV handling
- ✓ Secure random number generation
- ✓ Password hashing with high iteration count

## Known Limitations

1. **Password Entry:** Password visible briefly during entry (mitigated by quick clearance)
2. **OTP Display:** Codes visible on screen (inherent to OTP usage)
3. **Time Dependency:** Requires accurate system clock
4. **No Hardware Security Module:** Uses software crypto only
5. **Single-Factor:** OTP secret alone authenticates (password is second factor for file)

## Security Audit

Last reviewed: January 2026

**Cryptographic Components:**
- ✓ OpenSSL 3.0+ (industry standard)
- ✓ Well-tested algorithms (AES, SHA, HMAC)
- ✓ No custom crypto implementations

**Code Security:**
- ✓ Stack protection enabled (-fstack-protector-strong)
- ✓ Compiler warnings enabled and addressed
- ✓ Memory safety (RAII, std::vector)
- ✓ No buffer overflows identified

## Incident Response

If you suspect compromise:

1. **Immediate:** Generate new OTP secret with new password
2. **Update:** Change passwords on all services using compromised OTP
3. **Revoke:** Disable old OTP credentials
4. **Verify:** Check account access logs for unauthorized access
5. **Review:** Analyze how compromise occurred

## Reporting Security Issues

Security is taken seriously. If you discover a vulnerability:

1. **Do not** publicly disclose until verified and patched
2. Document the issue with reproduction steps
3. Assess the severity and potential impact
4. Report through appropriate channels
5. Allow reasonable time for fixes

## Future Enhancements

Planned security improvements:

- [ ] Hardware security module (HSM) support
- [ ] FIDO2/WebAuthn integration
- [ ] Encrypted memory regions (mlock)
- [ ] Secure enclave usage on supported platforms
- [ ] Quantum-resistant algorithms (post-quantum crypto)
- [ ] Multi-party computation for shared secrets

## Conclusion

This OTP generator provides strong security through:
- Industry-standard algorithms
- Defense in depth (triple-layer encryption)
- Secure defaults
- Proper memory handling

However, security is only as strong as:
- Password selection
- Operational security
- System security
- Physical security

Use strong passwords, follow best practices, and keep your system secure.
