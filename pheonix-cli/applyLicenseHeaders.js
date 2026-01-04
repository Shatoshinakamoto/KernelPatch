const fs = require('fs');
const path = require('path');

class ApplyLicenseHeadersPlugin {
    constructor(options) {
        this.licenseFileName = options.licenseFileName || 'pheonixBox.js.LICENSE.txt';
        this.version = options.version || this.getPackageVersion();
        this.currentDate = options.date || this.getCurrentDate();
        this.headers = options.headers || {};
        this.debug = options.debug || false; // Add debug option
    }

    logDebug(...args) {
        if (this.debug) {
            console.log(...args);
        }
    }

    getPackageVersion() {
        const packageJsonPath = path.join(__dirname, 'package.json');
        const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
        return packageJson.version;
    }

    getCurrentDate() {
        const now = new Date();
        const year = now.getFullYear();
        const month = String(now.getMonth() + 1).padStart(2, '0');
        const day = String(now.getDate()).padStart(2, '0');
        return `${year}-${month}-${day}`;
    }

    apply(compiler) {
        compiler.hooks.done.tap('ApplyLicenseHeadersPlugin', (stats) => {
            this.logDebug('Applying License!!! Merr');
            const outputPath = stats.compilation.outputOptions.path;
            const licenseFilePath = path.join(outputPath, this.licenseFileName);

            if (fs.existsSync(licenseFilePath)) {
                this.logDebug('Applying License!!! Merr', 'File Exists', licenseFilePath);
                let licenseContent = fs.readFileSync(licenseFilePath, 'utf-8');
                licenseContent = this.applyHeaders(licenseContent);
                fs.writeFileSync(licenseFilePath, licenseContent, 'utf-8');
            }
        });
    }

    applyHeaders(content) {
        const lines = content.split('\n');
        const newLines = [];

        lines.forEach((line, index) => {
            newLines.push(line);

            const match = line.match(/!\*\*\*.*?\.\/src\/(.*?)\.ts\s*\*\*\*\\/) || // Matches /*! *** ./src/char.ts *** */
                      line.match(/!\*\*\*\s*external\s+"(.*?)"\s*\*\*\*\\/) || // Matches /*! *** external "fs" *** */
                      line.match(/!\*\*\*\s*\.\/src\/(.*?)\.ts\s*\*\*\*/) ||   // Matches /*! *** ./src/cli.ts *** */
                      line.match(/!\*\*\*\s*(.*?)\s*\*\*\*\\/) ||              // Matches /*! *** cluster *** */
                      line.match(/\/\*\!\s*\.\/(.*?)\s*\*\//) ||               // Matches /*! ./char */
                      line.match(/\/\*\!\s*(.*?)\s*\*\//);                     // Matches /*! node:sea */
            this.logDebug('Applying License!!! Merr', 'Match', match, line);
            if (match) {
                const fileType = this.getFileTypeFromLine(line);
                const header = this.getHeaderForFileType(fileType);
                if (header) {
                    this.logDebug('Applying License!!! Merr', 'Header', header);
                    newLines.push(header);
                }
            }
        });

        return newLines.join('\n');
    }

    getFileTypeFromLine(line) {
        const match = line.match(/!\*\*\*.*?\.\/src\/(.*?)\.ts\s*\*\*\*\\/) || // Matches /*! *** ./src/char.ts *** */
                      line.match(/!\*\*\*\s*external\s+"(.*?)"\s*\*\*\*\\/) || // Matches /*! *** external "fs" *** */
                      line.match(/!\*\*\*\s*\.\/src\/(.*?)\.ts\s*\*\*\*/) ||   // Matches /*! *** ./src/cli.ts *** */
                      line.match(/!\*\*\*\s*(.*?)\s*\*\*\*\\/) ||              // Matches /*! *** cluster *** */
                      line.match(/\/\*\!\s*\.\/(.*?)\s*\*\//) ||               // Matches /*! ./char */
                      line.match(/\/\*\!\s*(.*?)\s*\*\//);                     // Matches /*! node:sea */
    
        this.logDebug('Applying License!!! Merr', 'Get File Type', line, match);
        return match ? match[1] : null;  // Return the captured file type or null if no match
    }

    getHeaderForFileType(fileType) {
        const defaultLineLength = 116;  // The total line length you want (including `*`s)
        const headerData = this.headers[fileType] || {};
    
        // Get dynamic values or defaults
        const author = headerData.author || 'Unknown Author';
        const purpose = headerData.purpose || 'No Purpose Provided';
        const license = headerData.license || 'No License Provided';
        const version = this.version;
        const date = this.currentDate;
    
        // Function to pad a line with spaces and an ending `*`
        const padLine = (key, value) => {
            const line = `  * ${key}: ${value}`;  // `* key: value`
            const padding = defaultLineLength - line.length - 2;  // Calculate padding
            return line + ' '.repeat(Math.max(padding, 0)) + ' *';  // Fill space and add closing `*`
        };
    
        // Construct the header dynamically
        const header = `  /${'*'.repeat(defaultLineLength - 2)}
${padLine('Author', author)}
${padLine('Purpose', purpose)}
${padLine('Last Modified', date)}
${padLine('License', license)}
${padLine('Version', version)}
  ${'*'.repeat(defaultLineLength - 2)}/`;
    
        return header;
    }
}

module.exports = ApplyLicenseHeadersPlugin;