# Unit Test for Pheonix Box CLI

This document describes how to run a unit test with known debugging rootkits for the Linux OS root folder space using the Pheonix Box CLI. It also includes the setup instructions for the root folder space.

## Prerequisites

- Ensure you have Node.js and npm installed.
- Clone the Pheonix Box CLI repository.
- Navigate to the project directory.

```sh
git clone https://github.com/john1234brown/pheonix-box.git
cd Pheonix-Box-Cli
```

## Setup

1. **Install Dependencies**

    Install the necessary dependencies by running:

    ```sh
    npm install
    ```

2. **Configure Pheonix Box**

    Create a configuration file `configurable.json` in the root directory with the following content:

    ```json
    {
      "paths": ["/"],
      "fileTypes": ["*"],
      "fileRegexs": [".*"],
      "forkDelay": 1,
      "forkExecutionDelay": 1,
      "threads": 1,
      "useFileTypes": false,
      "useFileRegexs": false,
      "useCeaserCipher": false,
      "useAesKey": false,
      "debug": true,
      "whiteSpaceOffset": 0
    }
    ```

## Running the Unit Test

1. **Create a Test File**

    Create a test file `test/rootkitTest.js` with the following content:

    ```js
    const { exec } = require('child_process');
    const JohnsPheonixBox = require('../production/pheonixBox');

    describe('Rootkit Test', () => {
      it('should detect and handle rootkits in the root folder space', (done) => {
         const pheonixBox = new JohnsPheonixBox();
         pheonixBox.config.debug = true;

         // Simulate rootkit detection
         exec('ls /rootkit', (error, stdout, stderr) => {
            if (error) {
              console.error(`exec error: ${error}`);
              return done(error);
            }
            console.log(`stdout: ${stdout}`);
            console.error(`stderr: ${stderr}`);
            done();
         });
      });
    });
    ```

2. **Run the Test**

    Use a test runner like Mocha to run the test:

    ```sh
    npx mocha test/rootkitTest.js
    ```

## Conclusion

By following the steps above, you can set up and run a unit test to detect and handle rootkits in the Linux OS root folder space using the Pheonix Box CLI. Ensure to review the test results and logs for any detected issues.
