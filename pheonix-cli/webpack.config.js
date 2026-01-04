// This is a webpack configuration file for the test2.ts file
const path = require("path");
const { WebpackPkgPlugin } = require('pheonix-pkg-plugin');
const ZipReleasesPlugin = require('./zipReleasesWebpack.js');
/**
 * @type {import('webpack').Configuration}
 */
module.exports = {
  mode: 'production',
  entry: "/src/cli.ts",
  module: {
    rules: [
      {
        test: /\.ts/,
        use: "ts-loader",
        exclude: [/wip/, /disabled/]
      }
    ]
  },
  plugins: [
    new WebpackPkgPlugin('pheonixBox.js', 'pheonixBox-', true),
    new ZipReleasesPlugin({
      files: ['pheonixBox-linux', 'pheonixBox-linux-hash.txts'],
      releaseType: 'production',
      outputDir: 'dist/releases'
    }),
    new ZipReleasesPlugin({
      files: ['pheonixBox-win', 'pheonixBox-win-hash.txt'],
      releaseType: 'production',
      outputDir: 'dist/releases'
    }),
    new ZipReleasesPlugin({
      files: ['pheonixBox-macos', 'pheonixBox-macos-hash.txt'],
      releaseType: 'production',
      outputDir: 'dist/releases'
    })
  ],
  target: "node",
  devtool: "source-map",
  optimization: {
    usedExports: true,
    chunkIds: "named",
    minimize: false,
    mangleExports: true,
    moduleIds: "named"
  },
  externalsPresets: { node: true },
  // Remove the externals configuration to include all node modules
  output: {
    filename: "pheonixBox.js",
    path: path.resolve(__dirname, "production")
  },
  resolve: {
    extensions: [".ts", ".js"],
    alias: {
      "@languages": path.resolve(__dirname, "../languages")
    }
  },
/*  cache: {
    type: 'filesystem', // Enable filesystem caching
    cacheDirectory: path.resolve(__dirname, '.webpack_cache'), // Specify cache directory
    buildDependencies: {
      config: [__filename], // Cache the config file itself
    },
  },*/
};