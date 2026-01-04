import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import dts from 'rollup-plugin-dts';
import RollupPkgPlugin from 'pkg-plugin'; // Adjust the path as necessary
import zipReleasesPlugin from './zipReleases.js';
import path from 'path';
const rollupPkgPlugin = new RollupPkgPlugin('pheonix-box-cli.js', 'pheonix-box-cli-', false, 'production');

// Define the entry files
const entryFiles = [
  './node_modules/pkg-plugin/tamperScripts/tamper.js',
  './dist/cli.js',
];

// Generate the entry file
const entryFilePath = './entry.js';
await rollupPkgPlugin.generateEntryFile(entryFilePath, entryFiles);

export default [
  {
    input: [
      entryFilePath,
    ],
    output: {
      dir: './production-npm',
      format: 'cjs',
      entryFileNames: 'pheonix-box-cli.js',
    },
    plugins: [
      resolve(),
      commonjs(),
      {
        name: 'rollup-pkg-plugin',
        buildStart: rollupPkgPlugin.buildStart.bind(rollupPkgPlugin),
        generateBundle: rollupPkgPlugin.generateBundle.bind(rollupPkgPlugin),
      }
      /*zipReleasesPlugin({
        files: ['pheonix-box-cli-linux', 'pheonix-box-cli-linux-hash.txt'],
        releaseType: 'linux',
        outputDir: 'releases'
      }),
      zipReleasesPlugin({
        files: ['pheonix-box-cli-win', 'pheonix-box-cli-win-hash.txt'],
        releaseType: 'win',
        outputDir: 'releases'
      }),
      zipReleasesPlugin({
        files: ['pheonix-box-cli-macos', 'pheonix-box-cli-macos-hash.txt'],
        releaseType: 'macos',
        outputDir: 'releases'
      }),*/
    ],
  },
  {
    input: './types/cli.d.ts',
    output: {
      file: './production-npm/pheonix-box-cli.d.ts',
      format: 'es',
    },
    plugins: [dts()],
  },
];