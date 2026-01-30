# OTP Generator CLI

A C++ command-line application to generate OTP codes, output QR images, and support Google/Microsoft Authenticator. Features multi-layer encryption, secure storage, and CMake build system for Visual Studio Code.

## Features
- Generate OTP codes
- Output QR images and manual entry codes
- Command-line arguments for generation and verification
- Multi-layer (3x) encryption for secrets
- Secure in-memory and file storage
- CMake-based project for easy development/debugging in VS Code

## Build Instructions
1. Install CMake and a C++ compiler (e.g., MSVC, GCC, or Clang)
2. Open this folder in Visual Studio Code
3. Install the C++ and CMake extensions if prompted
4. Configure and build using the CMake extension or:
   ```
   mkdir build
   cd build
   cmake ..
   cmake --build .
   ```

## TODO
See TODO.md for planned features and implementation steps.
