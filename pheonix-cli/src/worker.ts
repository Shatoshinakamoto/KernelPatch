/************************************************************************************************************************
 * Author: Johnathan Edward Brown                                                                                       *
 * Purpose: Worker class for the PheonixBox Class Object for the CLI Pheonix application.                               *
 * Last Modified: 2024-10-18                                                                                            *
 * License: X11 License                                                                                                 *
 * Version: 1.0.2                                                                                                       *
 ************************************************************************************************************************/
import { Config, iConfig } from './config';
import * as fs from 'fs';
import * as crypto from 'crypto';
import * as path from 'path';

/**
 * Represents a collection of file hashes where the key is the file path
 * and the value is the corresponding hash string.
 *
 * @interface FileHashes
 * @property {string} [key] - The file path.
 * @property {string} value - The hash string associated with the file.
 */
interface FileHashes {
    [key: string]: string;
}

/**
 * Represents the contents of a file where each key is a string
 * and the corresponding value is also a string.
 */
interface FileContents {
    [key: string]: string;
}

/**
 * The `JohnsWorker` class is responsible for processing files, encrypting, and decrypting their contents.
 * It supports both Caesar cipher and AES-256-CBC encryption methods.
 * 
 * @class
 * @param {Config} config - Configuration object for the worker.
 * @param {string[]} fileList - List of file paths to be processed.
 * @param {any} chunks - Data chunks to be processed.
 * @param {string} cipherKey - Key used for Caesar cipher encryption.
 * @param {string} shuffledKey - Shuffled key used for Caesar cipher decryption.
 * @param {Buffer} aesKey - Key used for AES-256-CBC encryption.
 * @param {boolean} loaded - Indicates if the worker is loaded.
 * @param {FileHashes} [fileHashes] - Optional precomputed file hashes.
 * @param {FileContents} [fileContents] - Optional precomputed file contents.
 * 
 * @property {Config} config - Configuration object for the worker.
 * @property {FileHashes} fileHashes - Object storing file hashes.
 * @property {FileContents} fileContents - Object storing file contents.
 * @property {string} cipherKey - Key used for Caesar cipher encryption.
 * @property {string} shuffledKey - Shuffled key used for Caesar cipher decryption.
 * @property {Buffer} aesKey - Key used for AES-256-CBC encryption.
 * @property {boolean} loaded - Indicates if the worker is loaded.
 * 
 * @method log - Logs messages if debug mode is enabled in the config.
 * @method encrypt - Encrypts a given text using Caesar cipher and optionally AES-256-CBC.
 * @method decrypt - Decrypts a given text using AES-256-CBC and Caesar cipher.
 * @method processFiles - Processes a list of files and updates their hashes and contents.
 * @method processFile - Processes a single file, updating its hash and content.
 * @method shouldProcessFile - Determines if a file should be processed based on the config.
 * @method terminate - Terminates the worker process.
 */
class JohnsWorker {
    #config: iConfig;
    #fileHashes: FileHashes;
    #fileContents: FileContents;
    #cipherKey: string;
    #shuffledKey: string;
    #aesKey: Buffer;
    #loaded: boolean;

    constructor(config: Config, fileList: string[], chunks: any, cipherKey: string, shuffledKey: string, aesKey: Buffer, loaded: boolean, fileHashes?: FileHashes, fileContents?: FileContents) {
        this.#config = config.getConfig();
        this.#loaded = loaded;
        this.#fileHashes = fileHashes || {};
        this.#fileContents = fileContents || {};
        this.#cipherKey = cipherKey;
        this.#shuffledKey = shuffledKey;
        this.#aesKey = aesKey;
        this.processFiles(fileList, chunks);
    }

    /**
     * Logs messages to the console if debugging is enabled in the configuration.
     *
     * @param {...any[]} args - The messages or objects to log.
     */
    private log(...args: any[]) {
        if (this.#config.debug) {
            console.log(...args);
        }
    }

    /**
     * Encrypts the given text using a Caesar cipher and optionally AES encryption.
     *
     * @param text - The text to be encrypted.
     * @returns The encrypted text. If AES encryption is used, the result will include the initialization vector.
     *
     * @remarks
     * - The method first applies a Caesar cipher using a shuffled key.
     * - If AES encryption is enabled and an AES key is provided, the method further encrypts the result using AES-256-CBC.
     * - Logs the encryption process at various stages.
     */
    #encrypt(text: string): string {
        this.log('Encrypting text...');
        const caesarEncrypted = text.split('').map(char => {
            const index = this.#cipherKey.indexOf(char);
            if (index === -1) {
                return char;
            }
            return this.#shuffledKey[index];
        }).join('');

        if (this.#config.useAesKey && this.#aesKey) {
            const iv = crypto.randomBytes(16); // Initialization vector
            const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(this.#aesKey), iv);
            let encrypted = cipher.update(caesarEncrypted, 'utf8', 'hex');
            encrypted += cipher.final('hex');
            const encryptedWithIv = iv.toString('hex') + ':' + encrypted;
            this.log('Encrypted text with AES:', encryptedWithIv);
            return encryptedWithIv;
        }

        this.log('Encrypted text with Caesar cipher:', caesarEncrypted);
        return caesarEncrypted;
    }

    /**
     * Decrypts the given text using AES-256-CBC and a Caesar cipher.
     *
     * @param text - The encrypted text to decrypt.
     * @returns The decrypted text.
     * @throws {Error} If the encrypted text format is invalid or the initialization vector length is incorrect.
     *
     * The decryption process involves:
     * 1. Logging the start of the decryption process.
     * 2. Checking if AES decryption is enabled and performing AES-256-CBC decryption if applicable.
     * 3. Using a Caesar cipher to further decrypt the text.
     * 4. Logging the decrypted text after applying the Caesar cipher.
     */
    #decrypt(text: string): string {
        this.log('Decrypting text...');
        let decrypted = text;
    
        if (this.#config.useAesKey && this.#aesKey) {
            const textParts = text.split(':');
            if (textParts.length < 2) {
                throw new Error('Invalid encrypted text format');
            }
    
            const iv = Buffer.from(textParts.shift()!, 'hex');
            if (iv.length !== 16) { // AES-256-CBC requires a 16-byte IV
                throw new Error('Invalid initialization vector length');
            }
    
            const encryptedText = textParts.join(':');
            const key = this.#config.useCeaserCipher ? Buffer.from(this.#aesKey) : this.#aesKey;  
            const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
            decrypted = decipher.update(encryptedText, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
        }
    
        const caesarDecrypted = decrypted.split('').map(char => {
            const index = this.#shuffledKey.indexOf(char);
            if (index === -1) {
                return char;
            }
            return this.#cipherKey[index];
        }).join('');
    
        this.log('Decrypted text with Caesar cipher:', caesarDecrypted);
        return caesarDecrypted;
    }

    /**
     * Processes a list of files and returns their hashes and contents.
     *
     * @param fileList - An array of file paths to be processed.
     * @param chunks - Data chunks to be used during file processing.
     * @returns A promise that resolves to an object containing file hashes and file contents.
     * @throws Will reject the promise if an error occurs during file processing.
     */
    public processFiles(fileList: string[], chunks: any): Promise<{ fileHashes: FileHashes; fileContents: FileContents; }> {
        return new Promise((resolve, reject) => {
            try {
                this.log('Processing files...');
                fileList.forEach(filePath => {
                    this.#processFile(filePath);
                });
                resolve({
                    fileHashes: this.#fileHashes,
                    fileContents: this.#fileContents
                });
            } catch (error) {
                reject(error);
            }
        });
    }

    /**
     * Processes a file by reading its content, computing its hash, and comparing it with stored values.
     * If the file should be processed and its hash does not match the stored hash, the file content is replaced
     * with the stored content. The file hash and content can be encrypted/decrypted based on the configuration.
     *
     * @param filePath - The path of the file to process.
     */
    #processFile(filePath: string) {
        this.log('Processing file:', filePath);
        if (this.#shouldProcessFile(filePath)) {
            const fileContent = fs.readFileSync(filePath, 'utf-8');
            const fileHash = crypto.createHash('sha256').update(fileContent).digest('hex');
            if (this.#fileHashes[filePath] !== undefined && this.#fileContents[filePath] !== undefined) {
                const storedHash = this.#config.useCeaserCipher ? this.#decrypt(this.#fileHashes[filePath]) : this.#fileHashes[filePath];
                const storedContent = this.#config.useCeaserCipher ? this.#decrypt(this.#fileContents[filePath]) : this.#fileContents[filePath];
                if (!storedHash) {
                    this.#fileHashes[filePath] = this.#config.useCeaserCipher ? this.#encrypt(fileHash) : fileHash;
                    this.#fileContents[filePath] = this.#config.useCeaserCipher ? this.#encrypt(fileContent) : fileContent;
                } else if (storedHash !== fileHash) {
                    this.log(`File hash mismatch for ${filePath}. Replacing content with stored content. , ${storedContent} \n, ${fileContent}`);
                    fs.writeFileSync(filePath, storedContent, 'utf-8');
                }
            }else{
                this.#fileHashes[filePath] = this.#config.useCeaserCipher ? this.#encrypt(fileHash) : fileHash;
                this.#fileContents[filePath] = this.#config.useCeaserCipher ? this.#encrypt(fileContent) : fileContent;
            }
        }
    }
    
    /**
     * Determines whether a file should be processed based on the configuration settings.
     *
     * @param filePath - The path of the file to check.
     * @returns `true` if the file should be processed, `false` otherwise.
     *
     * The method performs the following checks:
     * - Logs the file path being checked.
     * - Checks if the file path is excluded based on the `excludePaths` configuration.
     * - If `useFileTypes` is enabled, checks if the file extension is included in the `fileTypes` configuration.
     * - If `useFileRegexs` is enabled, checks if the file name matches any of the regular expressions in the `fileRegexs` configuration.
     */
    #shouldProcessFile(filePath: string): boolean {
        this.log('Checking if file should be processed:', filePath);
        if (this.#config.excludePaths?.some((excludePath: string) => filePath.startsWith(excludePath))) {
            this.log(`File ${filePath} is excluded from processing.`);
            return false;
        }

        if (this.#config.useFileTypes) {
            const fileExtension = path.extname(filePath);
            if (!this.#config.fileTypes?.includes(fileExtension)) {
                return false;
            }
        }

        if (this.#config.useFileRegexs) {
            const fileName = path.basename(filePath);
            if (!this.#config.fileRegexs?.some((regex: string | RegExp) => new RegExp(regex).test(fileName))) {
                return false;
            }
        }

        return true;
    }

    /**
     * Terminates the worker process.
     * 
     * This method logs a message indicating that the worker is terminating,
     * then exits the process with a status code of 0.
     * Note that any code after `process.exit(0)` will not be executed.
     */
    public terminate() {
        // Implementation of worker termination
        console.log('Worker terminating...');
        process.exit(0);
    }
}
export default JohnsWorker;