
# OTP rotating password for sudo users support 
Needs to include a command line setup to allow setting up a rotating password for a sudo user account using OTP and allow using Authenticator apps to scan the qr code or the manual entry code numbers to synchronize Authenticator apps with the current passphrase numbers which rotate and allow setting up a password design along with securely hold it in runtime in a private field to prevent gaining access to the OTP key being used to rotate the password in runetime
Needs to include a optional prefix password to extend the length of the password like lets say user wants there password to whale then the password would be whale$otpcode where $otpcode would be the numbers that rotate based on time.
Needs to include a command line setup to allow resetting password or disable the rotating OTP password functionality.
Needs to securely save the prefix using a encrypted manner to allow decrypting on reboots to gain access to it if there is a prefix so its not in a plain txt cfg file this cfg file unencrypted should be held in a private field in runtime as well to securely hold it in runtime of the kernel patch.
Only sudo users should be able to execute these commands to ensure its a secure addition to the kernel
Should include a command line setup as well to allow displaying the QR image in the browser using the filesystem to load it up in the browser using file://
Should include a command line setup as well to allow displaying the manual entry code numbers to synchronize Authenticator apps with the current OTP code for generating the numbers!

# Needs to blacklist the following command to prevent tpm clearing
```shell
echo 5 | sudo tee /sys/class/tpm/tpm0/ppi/request
```

# Needs to include a Ram Spike detection system
Lets say utilizing a monitoring system to detect an abnormal RAM spike lets say a configurable max ram usage if it peaks pass the maxed allowed configured ram usage it should initiate the following command to drop caches in a class object which executes the command from a private field inside the class or function when the class object is spawned to wipe the ram securely and not allow the execution of this command 
```shell
echo 3 | sudo tee /proc/sys/vm/drop_caches
```
Or recreate however this is done in pure c++ code to do the exact thing in a secure manner that can work correctly with the configured max ram usage.

# Needs a Cooldown
Cooldown function on to many failed attempts to give the correct password for a user from a sudo account to set the sudo user in a stalled state to prevent access in the event a malicious actor attempts to bruteforce the password to find it out.
Maybe Even find a way to detect what process was trying to give the incorrect password and shut it down to prevent DOS attack vectors from this design being included.

# Needs
To include logging of all unallowed accesses instead of just printing to the kernel to a log file system in this kernel patch to allow users to look back on malicious actions and calls to confirm they where happening.
Logging should include a date and time using the date and time of the kernel that is booted up in the log file
Should potentially include a configurable oldest logs automatically delete and be able to set how many days of log files should be held and kept to decrease potential Storage DOS attacks from this new function.

# Restriction to network level access via configuration toggle to switch between being a monitoring computer, or a pure host computer.
- Due to growing concerns on server host computers of potential exploits being discovered via the monitoring attacks one would think purely preventing pcap and all network level sniffing libraries from being installed if a system is configured with a simple boolean value in a cfg to prevent this would greatly reduce attack surfaces.
These two should automate the iptable rules by detecting the subnets ranges for lan and the router network. And properly delete the rules when the configuration is changed.
- Along with potential to fully cut off external network access calls as well and restrict to lan
- Along with potential to fully cut off lan network access calls and restrict to public

# Preventions against the following attack surfaces
- Bring your own Vulnerable drivers attacks

# Potential Preventions to include
- Preventing Child processes from being spawned by NodeJS binaries unless specifically allowed in the configuration files
- Preventing Child processes from being spawned by NodeJS projects ones that arent compiled into a binary
- Restricting what processes can have access to filesystem spaces like tmp directory which may purposely unbundled malicious binaries unless specifically allowed in the configuration files

# TimeVault Mode
- This would allow one to put the entire Operating system in TimeVault lockdown mode
- By Adding a command to the Operating system through the kernel patch to allow one to flip the switch only from sudo users.. Would allow the administrator to specifically specify what processes can be run on the system and any processes running thats not in the specified list would automatically be killed over and over and over again until they could be compressed and stored in a zip file for later debugging to understand why they kept trying to run.....
- By Adding a command which would toggle the ability to use snap, apt, yum, and any other package distribution downloading systems.... Should include a file change detection system on all folder spaces the moment a new file is added it will automatically wipe using a merkle tree and parent hash detection system..... Logs and records would have to be networked out in this OS so logs wouldnt be wiped during lockdown mode...


# Needs to include a encrypted kernel install
Should include in the yml scaffold way to automate installing the kernel using a encrypted method as well to allow the kernel patch to be encrypted to decrease attack surfaces and properly still apply as a kernel patch by making a secondary yml scaffold install along with a secondary shell script to install using a encrypted kernel install method utilizing the already existing install methods just restructuring them to properly do so
