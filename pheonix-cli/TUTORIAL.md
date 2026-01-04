# Pheonix Box CLI Tutorial (NPM Version)

Welcome to the Pheonix Box CLI tutorial. This guide will help you understand how to use the Pheonix Box CLI to manage and secure your files. Additionally, we will cover how to secure a binary and the root folder space of a Linux OS.

## Table of Contents
1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Basic Usage](#basic-usage)
4. [Configuration](#configuration)
5. [Securing a Binary](#securing-a-binary)
6. [Securing the Root Folder Space](#securing-the-root-folder-space)
7. [Conclusion](#conclusion)

## Introduction
The Pheonix Box CLI is a powerful tool for managing and securing files. Its encryption and hashing capabilities ensure the confidentiality and integrity of files, making it suitable for various security applications. The configurable settings, concurrency support, and state management features make it a versatile and efficient solution for file processing tasks.

## Installation
To install the Pheonix Box CLI via NPM, follow these steps:

1. Clone the repository:
    ```sh
    git clone https://github.com/john1234brown/pheonix-box.git
    cd Pheonix-Box-Cli
    ```

2. Install dependencies:
    ```sh
    npm install
    ```

3. Build the project:
    ```sh
    npm run webpack:npm
    ```

## Basic Usage
To start using the Pheonix Box CLI, you can use the following commands:

- Start the Pheonix process:
    ```sh
    ./pheonixBox start
    ```

- Display help:
    ```sh
    ./pheonixBox help
    ```

## Configuration
You can configure the Pheonix Box CLI using various commands. Here are some examples:

- Add a path to the configuration:
    ```sh
    ./pheonixBox config addPath /path/to/directory
    ```

- Set the number of threads:
    ```sh
    ./pheonixBox config setThreads 4
    ```

- Enable AES Key encryption:
    ```sh
    ./pheonixBox config setUseAesKey true
    ```

## Securing a Binary
To secure a binary using the Pheonix Box CLI, follow these steps:

1. Add the binary's directory to the configuration:
    ```sh
    ./pheonixBox config addPath /path/to/binary
    ```

2. Enable encryption and hashing:
    ```sh
    ./pheonixBox config setUseCeaserCipher true
    ./pheonixBox config setUseAesKey true
    ```

3. Start the Pheonix process to secure the binary:
    ```sh
    ./pheonixBox start
    ```

## Securing the Root Folder Space
To secure the root folder space specifically for securing the OS level binaries of a Linux OS, follow these steps:

1. Add the root directory to the configuration:
    ```sh
    sudo ./pheonixBox config addPath /
    ```

2. Exclude the home directory from the configuration to avoid affecting personal files:
    ```sh
    sudo ./pheonixBox config excludePath /home
    ```

3. Enable encryption and hashing:
    ```sh
    sudo ./pheonixBox config setUseCeaserCipher true
    sudo ./pheonixBox config setUseAesKey true
    ```

4. Start the Pheonix process to secure the root folder space:
    ```sh
    sudo ./pheonixBox start
    ```

**Note:** Be cautious when securing the root folder space as it may affect system files and operations.

## Conclusion
The Pheonix Box CLI is a versatile tool for managing and securing files. By following this tutorial, you can configure and use the CLI to secure your binaries and the root folder space of your Linux OS. For more detailed information, refer to the project's documentation and source code.

### New Additions

- **Concurrency Support**: You can now set the number of concurrent threads for file processing.
    ```sh
    ./pheonixBox config setThreads 4
    ```

- **State Management**: The CLI now supports state management to resume interrupted processes.
    ```sh
    ./pheonixBox state save
    ./pheonixBox state load
    ```

- **Enhanced Debugging**: Enable debugging to get detailed logs.
    ```sh
    ./pheonixBox config setDebug true
    ```

By following this updated guide, you can take full advantage of the new features and improvements in the Pheonix Box CLI.


## Pure Binary Usage for Different OS

The Pheonix Box CLI can also be used as a pure binary without relying on Node.js or NPM. Below are the steps to use the binary on different operating systems.

### Linux

1. Download the binary for Linux from the [releases page](https://github.com/john1234brown/pheonix-box/releases).

2. Make the binary executable:
    ```sh
    chmod +x pheonixBox-linux
    ```

3. Run the binary:
    ```sh
    ./pheonixBox-linux start
    ```

### macOS

1. Download the binary for macOS from the [releases page](https://github.com/john1234brown/pheonix-box/releases).

2. Make the binary executable:
    ```sh
    chmod +x pheonixBox-macos
    ```

3. Run the binary:
    ```sh
    ./pheonixBox-macos start
    ```

### Windows

1. Download the binary for Windows from the [releases page](https://github.com/john1234brown/pheonix-box/releases).

2. Run the binary:
    ```sh
    pheonixBox-windows.exe start
    ```

### Common Commands

Regardless of the operating system, you can use the following commands with the binary:

- Display help:
    ```sh
    ./pheonixBox help
    ```

- Add a path to the configuration:
    ```sh
    ./pheonixBox config addPath /path/to/directory
    ```

- Set the number of threads:
    ```sh
    ./pheonixBox config setThreads 4
    ```

- Enable AES Key encryption:
    ```sh
    ./pheonixBox config setUseAesKey true
    ```

By following these steps, you can use the Pheonix Box CLI as a standalone binary on various operating systems, making it a versatile tool for file management and security.