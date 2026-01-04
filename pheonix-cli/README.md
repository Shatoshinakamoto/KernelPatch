# Pheonix Box CLI
Pheonix Box CLI is a TypeScript project that is compiled, bundled with Webpack, and obfuscated into a binary. It provides a robust tamper-proof solution for managing and processing files with encryption and hashing capabilities.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [License](#license)

## Installation

To install the dependencies, run:

```bash
npm install
```

To build the project, run:

```bash
npm run build
```

To bundle the project with Webpack, run:

```bash
npm run webpack:bin
```

For development builds, use:

```bash
npm run dev:webpack
```

To compile the npm module CLI, run:

```bash
npm run webpack:npm
```

### Global Installation

You can also install the Pheonix Box CLI globally to use the npm CLI version:

```bash
npm install -g pheonix-box-cli
```

## Usage

To start the Pheonix Box CLI, run the following command:

```bash
node production-npm/pheonixBox.js
```

If you have installed the CLI globally, you can use:

```bash
pheonix-box-cli
```

## Configuration

The configuration is managed through the `Config` class. You can customize various settings such as paths, encryption keys, and debug options.

### Configuration File

The configuration is stored in a JSON file named `configurable.json`. Here is an example of what the configuration file might look like:

```json
{
    "paths": ["src", "dist"],
    "fileTypes": [".ts", ".js"],
    "fileRegexs": ["\\.test\\.ts$", "\\.spec\\.ts$"],
    "useFileTypes": true,
    "useFileRegexs": false,
    "useCeaserCipher": false,
    "useAesKey": true,
    "forkDelay": 1,
    "forkExecutionDelay": 1,
    "threads": 4,
    "whiteSpaceOffset": 2,
    "debug": true
}
```

### Configuration Options

- `paths`: An array of paths to include in the processing.
- `fileTypes`: An array of file extensions to include.
- `fileRegexs`: An array of regular expressions to match file names.
- `useFileTypes`: A boolean indicating whether to use file types for filtering.
- `useFileRegexs`: A boolean indicating whether to use regular expressions for filtering.
- `useCeaserCipher`: A boolean indicating whether to use Caesar Cipher for encryption.
- `useAesKey`: A boolean indicating whether to use AES encryption.
- `forkDelay`: A number indicating the delay between forks.
- `forkExecutionDelay`: A number indicating the delay between fork executions.
- `threads`: The number of threads to use for processing.
- `whiteSpaceOffset`: The number of spaces to use for indentation.
- `debug`: A boolean indicating whether to enable debug mode.

### Methods

The `Config` class provides several methods to manage the configuration:

- `addPath(path: string)`: Adds a new path to the configuration.
- `removePath(path: string)`: Removes a path from the configuration.
- `addFileType(fileType: string)`: Adds a new file type to the configuration.
- `removeFileType(fileType: string)`: Removes a file type from the configuration.
- `addFileRegex(regex: string)`: Adds a new file regex to the configuration.
- `removeFileRegex(regex: string)`: Removes a file regex from the configuration.
- `saveConfigP()`: Saves the current configuration to the file.

### Debugging

If you enable the `debug` option, the `Config` class will log messages to the console, which can help you troubleshoot issues with your configuration.

By following this guide, you can effectively manage and customize the configuration for the Pheonix Box CLI project.

## License

This project is licensed under the X11 License. See the [LICENSE](https://github.com/john1234brown/pheonix-box/blob/main/pheonix-cli/LICENSE) file for details.
