"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.JohnsPheonixBox = exports.clusterLock = void 0;
/************************************************************************************************************************
 * Author: Johnathan Edward Brown                                                                                       *
 * Purpose: Main entry point for the PheonixBox Class Object for the CLI Pheonix application.                           *
 * Last Modified: 2024-10-14                                                                                            *
 * License: X11 License                                                                                                 *
 * Version: 1.0.4                                                                                                       *
 ************************************************************************************************************************/
const config_1 = require("./config");
const crypto = __importStar(require("crypto"));
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const sea = __importStar(require("node:sea")); // Assuming 'sea' is a module for handling sea assets
const char_1 = require("./char");
const worker_1 = __importDefault(require("./worker")); // Import the Worker class from worker.ts
const cluster_1 = __importDefault(require("cluster"));
const os = __importStar(require("os"));
exports.clusterLock = { clusterLock: false };
if (cluster_1.default.isWorker) {
    // If this is a worker process, do nothing and return early
    console.log(`Worker ${process.pid} is running`);
    exports.clusterLock.clusterLock = true;
    process.on('message', async (message) => {
        const msg = message;
        if (msg.type === 'start') {
            console.log('Starting worker process...');
            const { chunk, config, cipherKey, shuffledKey, aesKey, loaded, fileHashes, fileContents } = message;
            const worker = new worker_1.default(config, chunk, {}, cipherKey, shuffledKey, aesKey || Buffer.alloc(0), loaded, fileHashes, fileContents);
            while (true) {
                const result = await worker.processFiles(chunk, {});
                if (process.send)
                    process.send({ type: 'result', fileHashes: result.fileHashes, fileContents: result.fileContents });
                await new Promise(resolve => setTimeout(resolve, config.getConfig().forkExecutionDelay || 1000)); // Add a configurable delay between executions
            }
        }
    });
}
const STATE_FILE_PATH = path.join(process.cwd(), 'pheonixBoxState.json');
/**
 * The `JohnsPheonixBox` class provides functionality for managing file hashes, contents, and encryption keys.
 * It supports runtime protection, state saving/loading, and multi-threaded processing.
 */
class JohnsPheonixBox {
    #cfg;
    #config;
    #fileHashes = {};
    #fileContents = {};
    #cipherKey = '';
    #shuffledKey = '';
    #safeAsciiCharacters = [];
    #aesKey = null;
    #loaded;
    /**
     * Initializes a new instance of the `JohnsPheonixBox` class.
     *
     * @param {Config} [config] - Optional configuration object.
     * @param {boolean} [useSeaAsset=false] - Whether to use a SEA asset for configuration.
     * @param {string} [assetLocation=''] - The location of the SEA asset.
     */
    constructor(config, useSeaAsset = false, assetLocation = '') {
        this.#loaded = false;
        if (config) {
            this.#cfg = config;
            this.#config = this.#cfg.getConfig();
            if (!this.#config.selfNpmTamperProof && !this.#config.selfTamperProof)
                this.#cfg.saveConfigP(); //Prevent Binary Tamper proofing from saving there configurations!
            this.loadState();
        }
        else if (useSeaAsset && assetLocation) {
            this.#cfg = this.loadConfigFromSeaAsset(assetLocation);
            this.#config = this.#cfg.getConfig();
        }
        else {
            this.#cfg = new config_1.Config();
            this.#config = this.#cfg.getConfig();
            if (!this.#config.selfNpmTamperProof && !this.#config.selfTamperProof)
                this.#cfg.saveConfigP(); //Prevent Binary Tamper proofing from saving there configurations!
            this.loadState();
        }
        this.log('Initializing JohnsPheonixBox...');
        console.log('This loaded:', this.#loaded);
        if (this.#loaded === false) {
            this.#safeAsciiCharacters = (0, char_1.generateSafeUtf8Characters)(this.#config.whiteSpaceOffset);
            this.#cipherKey = this.generateCipherKey();
            this.#shuffledKey = this.#cipherKey;
            if (this.#config.useAesKey) {
                this.#aesKey = crypto.randomBytes(32); // Use 256-bit key size
            }
        }
        process.on('exit', (code) => {
            if (code !== 369) {
                if (exports.clusterLock.clusterLock === false)
                    this.saveState();
            }
        });
        process.on('SIGINT', () => {
            if (exports.clusterLock.clusterLock === false)
                this.saveState();
            process.exit(369);
        });
        this.log('JohnsPheonixBox initialized with config:', this.#cfg);
    }
    log(...args) {
        if (this.#config.debug) {
            console.log(...args);
        }
    }
    /**
     * Initializes runtime protection for the application.
     *
     * @param {boolean} [npm] - If true, enables npm tamper-proof protection.
     * @param {boolean} [binary] - If true, enables binary tamper-proof protection.
     * @param {boolean} [localReferences] - If true, adds local file references to the configuration.
     * @param {boolean} [dirname] - If true, uses `__dirname` for path resolution; otherwise, uses `process.cwd()`.
     *
     * @remarks
     * - When `npm` is true, the method configures paths for npm tamper-proof protection.
     * - When `binary` is true, the method configures paths for binary tamper-proof protection.
     * - If `localReferences` is true, it adds the current file and 'node_modules' to the configuration paths.
     * - If `dirname` is true, it uses `__dirname` for path resolution; otherwise, it uses the current working directory.
     * - The method ensures that tamper-proof protection is enabled only if it is not already set.
     */
    initRuntimeProtect(npm, binary, localReferences, dirname) {
        if (npm) {
            if (!this.#config.selfNpmTamperProof) {
                this.#config.selfNpmTamperProof = true;
            }
            if (localReferences) {
                this.#cfg.addPath(__filename);
                this.#cfg.addPath('node_modules');
            }
            else {
                if (dirname) {
                    this.#cfg.addPath(path.join(__dirname, __filename));
                    this.#cfg.addPath(path.join(__dirname, 'node_modules'));
                }
                else {
                    this.#cfg.addPath(path.join(process.cwd(), __filename));
                    this.#cfg.addPath(path.join(process.cwd(), 'node_modules'));
                }
            }
        }
        if (binary) {
            if (!this.#config.selfTamperProof) {
                this.#config.selfTamperProof = true;
            }
            if (localReferences) {
                this.#cfg.addPath(__filename);
            }
            else {
                if (dirname) {
                    this.#cfg.addPath(path.join(__dirname, __filename));
                }
                else {
                    this.#cfg.addPath(path.join(process.cwd(), __filename));
                }
            }
        }
        if (localReferences)
            this.#config.localPathReferences = true;
    }
    /**
     * Loads the configuration from a SEA asset.
     *
     * @param {string} assetLocation - The location of the SEA asset.
     * @returns {Config} The loaded configuration object.
     */
    loadConfigFromSeaAsset(assetLocation) {
        console.log('Loading config from sea asset:', assetLocation);
        const arrayBuffer = sea.getAsset(assetLocation);
        const configString = Buffer.from(arrayBuffer.toString()).toString('utf8');
        console.log('Loaded config from sea asset:', configString);
        return JSON.parse(configString);
    }
    /**
     * Loads the state from a file.
     */
    loadState() {
        console.log('Loading state from file:', STATE_FILE_PATH);
        if (fs.existsSync(STATE_FILE_PATH)) {
            const state = JSON.parse(fs.readFileSync(STATE_FILE_PATH, 'utf-8'));
            this.#cipherKey = state.cipherKey;
            this.#shuffledKey = state.shuffledKey;
            this.#fileHashes = state.fileHashes;
            this.#fileContents = state.fileContents;
            if (this.#config.useAesKey && state.aesKey) {
                this.#aesKey = Buffer.from(state.aesKey, 'hex');
            }
            fs.unlinkSync(STATE_FILE_PATH); // Delete the state file after loading
            this.log('Loaded state:', state);
            this.#loaded = true;
        }
    }
    /**
     * Saves the current state to a file.
     */
    saveState() {
        this.log('Saving state to file:', STATE_FILE_PATH);
        const state = {
            cipherKey: this.#cipherKey,
            shuffledKey: this.#shuffledKey,
            fileHashes: this.#fileHashes,
            fileContents: this.#fileContents
        };
        if (this.#config.useAesKey && this.#aesKey) {
            state.aesKey = this.#aesKey.toString('hex');
        }
        fs.writeFileSync(STATE_FILE_PATH, JSON.stringify(state), 'utf-8');
        this.log('Saved state:', state);
    }
    /**
     * Starts the process, managing worker threads and distributing tasks.
     */
    startProcess() {
        if (cluster_1.default.isPrimary) {
            let numCPUs = os.cpus().length;
            if (numCPUs > this.#config.threads)
                numCPUs = this.#config.threads; // If configurations for threads is lower than the numCpu threads use that!
            const fileList = this.getFileList();
            const chunkSize = Math.ceil(fileList.length / numCPUs);
            this.log(`Master ${process.pid} is running, using ${numCPUs} threads with chunk size ${chunkSize}`);
            // Fork workers.
            let i = 0;
            const forkWorker = () => {
                if (i < numCPUs) {
                    const chunk = fileList.slice(i * chunkSize, (i + 1) * chunkSize);
                    const worker = cluster_1.default.fork();
                    worker.on('message', (message) => {
                        if (message.type === 'result') {
                            this.log(`Master received result from worker ${worker.process.pid}`);
                            Object.assign(this.#fileHashes, message.fileHashes);
                            Object.assign(this.#fileContents, message.fileContents);
                        }
                    });
                    worker.send({ type: 'start', chunk, config: this.#config, cipherKey: this.#cipherKey, shuffledKey: this.#shuffledKey, aesKey: this.#aesKey, loaded: this.#loaded, fileHashes: this.#fileHashes, fileContents: this.#fileContents });
                    i++;
                    setTimeout(forkWorker, this.#config.forkDelay || 100); // Add a configurable delay between forks
                }
            };
            while (i < numCPUs) {
                forkWorker();
            }
            cluster_1.default.on('exit', (worker, code, signal) => {
                this.log(`Worker ${worker.process.pid} died`);
                i = i - 1;
            });
        }
    }
    /**
     * Generates a list of files to be processed.
     *
     * @returns {string[]} The list of file paths.
     */
    getFileList() {
        this.log('Generating file list...');
        const fileList = [];
        const excludePaths = this.#config.excludePaths || [];
        this.#config.paths.forEach((filePath) => {
            if (this.#config.localPathReferences) {
                filePath = path.join(__dirname, filePath);
            }
            if (fs.existsSync(filePath)) {
                const stat = fs.statSync(filePath);
                if (stat.isDirectory()) {
                    fs.readdirSync(filePath).forEach(file => {
                        const fullPath = path.join(filePath, file);
                        if (!excludePaths.includes(fullPath)) {
                            fileList.push(fullPath);
                        }
                    });
                }
                else {
                    if (!excludePaths.includes(filePath)) {
                        fileList.push(filePath);
                    }
                }
            }
        });
        if (this.#config.selfTamperProof) {
            if (fs.existsSync(path.join(__dirname, __filename))) {
                fileList.push(path.join(__dirname, __filename));
            }
            else {
                if (fs.existsSync(path.join(process.cwd(), __filename))) {
                    fileList.push(path.join(process.cwd(), __filename));
                }
            }
        }
        if (this.#config.selfNpmTamperProof) {
            fileList.push(__dirname);
            const npmModulesPath = path.join(__dirname, 'node_modules');
            if (fs.existsSync(npmModulesPath)) {
                fileList.push(npmModulesPath);
            }
        }
        this.log('Generated file list:', fileList);
        return fileList;
    }
    /**
     * Generates a cipher key by shuffling safe ASCII characters.
     *
     * @returns {string} The generated cipher key.
     */
    generateCipherKey() {
        this.log('Generating cipher key...');
        const alphabet = this.#safeAsciiCharacters;
        const array = this.shuffleKeys(alphabet);
        for (let i = array.length - 1; i > 0; i--) {
            const j = crypto.randomInt(0, i + 1);
            [array[i], array[j]] = [array[j], array[i]];
        }
        const cipherKey = array.join('');
        this.log('Generated cipher key:', cipherKey);
        return cipherKey;
    }
    /**
     * Shuffles an array of strings.
     *
     * @param {string[]} array - The array of strings to shuffle.
     * @returns {string[]} The shuffled array.
     */
    shuffleKeys(array) {
        this.log('Shuffling key...');
        for (let i = array.length - 1; i > 0; i--) {
            const j = crypto.randomInt(0, i + 1);
            [array[i], array[j]] = [array[j], array[i]];
        }
        return array;
    }
    /**
     * Shuffles a given key string.
     *
     * @param {string} key - The key string to shuffle.
     * @returns {string} The shuffled key.
     */
    shuffleKey(key) {
        this.log('Shuffling key...');
        const array = key.split('');
        for (let i = array.length - 1; i > 0; i--) {
            const j = crypto.randomInt(0, i + 1);
            [array[i], array[j]] = [array[j], array[i]];
        }
        const shuffledKey = array.join('');
        this.log('Shuffled key:', shuffledKey);
        return shuffledKey;
    }
}
exports.JohnsPheonixBox = JohnsPheonixBox;
