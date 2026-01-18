
# OTP rotating password for sudo users support 
Needs to include a command line setup to allow setting up a rotating password for a sudo user account using OTP and allow using Authenticator apps to scan the qr code or the manual entry code numbers to synchronize Authenticator apps with the current passphrase numbers which rotate and allow setting up a password design along with securely hold it in runtime in a private field to prevent gaining access to the OTP key being used to rotate the password in runetime
Needs to include a optional prefix password to extend the length of the password like lets say user wants there password to whale then the password would be whale$otpcode where $otpcode would be the numbers that rotate based on time.
Needs to include a command line setup to allow resetting password or disable the rotating OTP password functionality.
Needs to securely save the prefix using a encrypted manner to allow decrypting on reboots to gain access to it if there is a prefix so its not in a plain txt cfg file this cfg file unencrypted should be held in a private field in runtime as well to securely hold it in runtime of the kernel patch.
Only sudo users should be able to execute these commands to ensure its a secure addition to the kernel

# Needs to blacklist the following command to prevent tpm clearing
echo 5 | sudo tee /sys/class/tpm/tpm0/ppi/request

# Needs a Cooldown
Cooldown function on to many failed attempts to give the correct password for a user from a sudo account to set the sudo user in a stalled state to prevent access in the event a malicious actor attempts to bruteforce the password to find it out.
Maybe Even find a way to detect what process was trying to give the incorrect password and shut it down to prevent DOS attack vectors from this design being included

# Needs
To include logging of all unallowed accesses instead of just printing to the kernel to a log file system in this kernel patch to allow users to look back on malicious actions and calls to confirm they where happening.
Logging should include a date and time using the date and time of the kernel that is booted up in the log file
Should potentially include a configurable oldest logs automatically delete and be able to set how many days of log files should be held and kept to decrease potential Storage DOS attacks from this new function.
