import path from 'path';
import fs from 'fs';
import archiver from 'archiver';

function getPackageVersion() {
    const packageJsonPath = path.join(process.cwd(), 'package.json');
    const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
    return packageJson.version;
}

function ensureDirectoryExistence(filePath) {
    const dirname = path.dirname(filePath);
    if (fs.existsSync(dirname)) {
        return true;
    }
    fs.mkdirSync(dirname, { recursive: true });
}

function zipReleasesPlugin(options = {}) {
    const files = options.files || [];
    const releaseType = options.releaseType || 'default';
    const outputDir = options.outputDir || process.cwd();

    if (files.length !== 2) {
        throw new Error('Exactly two files must be specified.');
    }

    return {
        name: 'zip-releases-plugin',
        generateBundle(outputOptions, bundle, isWrite) {
            const version = getPackageVersion();
            const outputPath = path.resolve(process.cwd(), outputDir);
            const baseOutputPath = path.dirname(outputPath);

            const zipFileName = `release-${releaseType}-${version}.zip`;
            const zipFilePath = path.join(outputPath, zipFileName);
            ensureDirectoryExistence(zipFilePath);

            const output = fs.createWriteStream(zipFilePath);
            const archive = archiver('zip', { zlib: { level: 9 } });

            output.on('close', () => {
                console.log(`${archive.pointer()} total bytes`);
                console.log(`Archiver has been finalized and the output file descriptor has closed for ${zipFileName}.`);
            });

            archive.on('error', (err) => {
                throw err;
            });

            archive.pipe(output);
            files.forEach(file => {
                const filePath = path.join(baseOutputPath, 'production', file);
                console.log('Archiving:', filePath);
                archive.file(filePath, { name: file });
            });
            archive.finalize();
        }
    };
}

export default zipReleasesPlugin;

// Example usage in rollup.config.js:
// import zipReleasesPlugin from './zipReleases.js';
//
// export default {
//     // other rollup config options...
//     plugins: [
//         zipReleasesPlugin({
//             files: ['file1.js', 'file2.js'],
//             releaseType: 'beta',
//             outputDir: 'dist/releases'
//         })
//     ]
// };
