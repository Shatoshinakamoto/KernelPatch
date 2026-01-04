const path = require('path');
const fs = require('fs');
const archiver = require('archiver');

class ZipReleasesPlugin {
    constructor(options = {}) {
        this.files = options.files || [];
        this.releaseType = options.releaseType || 'default';
        this.outputDir = options.outputDir || __dirname;

        if (this.files.length !== 2) {
            throw new Error('Exactly two files must be specified.');
        }
    }

    getPackageVersion() {
        const packageJsonPath = path.join(process.cwd(), 'package.json');
        const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
        return packageJson.version;
    }

    ensureDirectoryExistence(filePath) {
        const dirname = path.dirname(filePath);
        if (fs.existsSync(dirname)) {
            return true;
        }
        fs.mkdirSync(dirname, { recursive: true });
    }

    apply(compiler) {
        compiler.hooks.done.tapAsync('ZipReleasesPlugin', (compilation, callback) => {
            const version = this.getPackageVersion();
            const outputPath = path.resolve(process.cwd(), this.outputDir);
            const baseOutputPath = path.dirname(outputPath);

            const zipFileName = `release-${this.releaseType}-${version}.zip`;
            const zipFilePath = path.join(outputPath, zipFileName);

            // Ensure the output directory exists
            this.ensureDirectoryExistence(zipFilePath);

            const output = fs.createWriteStream(zipFilePath);
            const archive = archiver('zip', { zlib: { level: 9 } });

            output.on('close', () => {
                console.log(`${archive.pointer()} total bytes`);
                console.log(`Archiver has been finalized and the output file descriptor has closed for ${zipFileName}.`);
                callback();
            });

            archive.on('error', (err) => {
                throw err;
            });

            archive.pipe(output);
            this.files.forEach(file => {
                const filePath = path.join(baseOutputPath, file);
                console.log('Archiving:', filePath);
                archive.file(filePath, { name: file });
            });
            archive.finalize();
        });
    }
}

module.exports = ZipReleasesPlugin;
// Example usage in webpack.config.js:
// const ZipReleasesPlugin = require('./zipReleasesWebpack.js');
//
// module.exports = {
//     // other webpack config options...
//     plugins: [
//         new ZipReleasesPlugin({
//             files: ['file1.js', 'file2.js'],
//             releaseType: 'beta',
//             outputDir: 'dist/releases'
//         })
//     ]
// };