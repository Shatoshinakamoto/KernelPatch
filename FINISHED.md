Need to include a bash script and cli for the kernels timevault which would allow scanning an entire directory for binary/executables and executable scripts and hashing and adding to the timevault whitelist along with a wipe timevault whitelist command ability only sudo users should be able to do this need to include ability to add single files at a time to the timevault whitelist as well from the cli as well

Need to go over admin_gid defaults to root-only until the installer sets the distro’s sudo/wheel GID — so sudo-group users count as non-sudo until configured. Fine as a safe default; flag it if you’d rather it auto-detect. and simplify this for users where it can detect all existing admin group ids at the time of installing the kernel and automatically detect them and use them in the installed kernel patch so including auto detect ability so when the kernel patch is installed all sudo-group users will properly count as sudo-group and not non-sudo

Should also include adding the scripts we are creating to help with the timevault whitelist as hardcoded cli into the kernel as well

Properly Document all potential commands added and included with the kernel with full explainations and documentations on it... under the docs folder

Properly Document all Configuration files and configuration options and settings.. under the docs folder

Include Full depth explainations and documentations for everything under the docs folder

Need to include cli built into the kernel for easy changing to configuration settings via cli so all things configurable in the kernel can be configured via the cli from the kernel

Include a command which is one time use which is a one-way lock switch. Once it's set, configs only changes after a reboot. TimeVault sets it automatically. Meaning the command cant be rexecuted to try and unlock the configs once executed it is fixed and locked until reboot.


Go over all of the source code with a NIST standard security analysis perspective and check for any potential vulnerabilities and work out a potential patch for it while at the same time double checking that new patch for potential security vulnerabilities as well with the same level of NIST standard for security requires along with utilizing public known CVE exploits and bugs to prevent from repeating similar cve vulnerabilities while also using the most Cyber security analysis perspective and dont leave any open holes behind.

BinaryVault function and option which can be disabled or enabled via the configuration and include updating the CLI to include such things as well the binary vault would make all binary files on the machine read only at the time of Boot Its dictated by the logic gate

Include Comments in the code fully explaining everything in detail step by step and what its doing and how its doing it securely

Did you run the oscap eval or could you? Show results Scan and patch all ongoing bugs and maintain STIG compliance , the n you can work around that , and extend the tools there too. If you can get it stig implememted and tested You have to be really precise in the architecture layout. Standard Technical Implementation Guideline - STIG, Military grade requirements.

Bluetooth disable and enable along with wifi enable and disable to only allow ethernet configuration options and commands to toggle config settings