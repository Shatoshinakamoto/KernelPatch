/************************************************************************************************************************
 * Author: Johnathan Edward Brown                                                                                       *
 * Purpose: Configuration class for the CLI Pheonix application.                                                        *
 * Last Modified: 2024-10-18                                                                                            *
 * License: X11 License                                                                                                 *
 * Version: 1.0.2                                                                                                       *
 ************************************************************************************************************************/
import * as fs from 'fs';

export interface iConfig {
    paths: string[];
    excludePaths: string[];
    fileTypes: string[];
    fileRegexs: string[];
    useFileTypes: boolean;
    useFileRegexs: boolean;
    useCeaserCipher: boolean;
    useAesKey: boolean;
    forkDelay: number;
    forkExecutionDelay: number;
    threads: number;
    whiteSpaceOffset: number;
    debug: boolean;
    localPathReferences: boolean;
    selfTamperProof: boolean;
    selfNpmTamperProof: boolean;
}


/**
 * Class representing the configuration settings.
 */
export class Config {
    /**
     * Path to the configuration file.
     */
    #configFilePath = 'configurable.json';
    /**
     * Configuration object containing various settings.
     */
    #config: iConfig;
    #paths: string[];
    #excludePaths: string[];
    #fileTypes: string[];
    #fileRegexs: string[];
    #useFileTypes: boolean;
    #useFileRegexs: boolean;
    #useCeaserCipher: boolean;
    #useAesKey: boolean;
    #forkDelay: number;
    #forkExecutionDelay: number;
    #threads: number;
    #whiteSpaceOffset: number;
    #debug: boolean;
    #localPathReferences: boolean;
    #selfTamperProof: boolean;
    #selfNpmTamperProof: boolean;
    #configLock: boolean = false;

    /**
     * Creates an instance of Config.
     * @param configObject - Optional configuration object to initialize with.
     */
    constructor(configObject?: any) {
        this.#config = {
            paths: [],
            excludePaths: [],
            fileTypes: [],
            fileRegexs: [],
            forkDelay: 1,
            forkExecutionDelay: 1,
            threads: 1,
            useFileTypes: false,
            useFileRegexs: false,
            useCeaserCipher: false,
            useAesKey: false,
            debug: false,
            whiteSpaceOffset: 0,
            localPathReferences: false,
            selfTamperProof: false,
            selfNpmTamperProof: false,
        };

        if (configObject && this.#validateConfig(configObject)) {
            this.#configLock = true;
            this.#config = configObject;
        } else {
            this.#loadConfig();
        }

        this.#paths = this.#config.paths;
        this.#excludePaths = this.#config.excludePaths;
        this.#fileTypes = this.#config.fileTypes;
        this.#fileRegexs = this.#config.fileRegexs;
        this.#useFileRegexs = this.#config.useFileRegexs;
        this.#useFileTypes = this.#config.useFileTypes;
        this.#useCeaserCipher = this.#config.useCeaserCipher;
        this.#useAesKey = this.#config.useAesKey;
        this.#forkDelay = this.#config.forkDelay;
        this.#forkExecutionDelay = this.#config.forkExecutionDelay;
        this.#threads = this.#config.threads;
        this.#debug = this.#config.debug;
        this.#whiteSpaceOffset = this.#config.whiteSpaceOffset;
        this.#localPathReferences = this.#config.localPathReferences;
        this.#selfTamperProof = this.#config.selfTamperProof;
        this.#selfNpmTamperProof = this.#config.selfNpmTamperProof;
    }

    /**
     * Logs a message if debug mode is enabled.
     * @param message - The message to log.
     */
    private log(message: string) {
        if (this.#debug) {
            console.log(message);
        }
    }

    /**
     * Saves the current configuration to the configuration file.
     */
    #saveConfig() {
        if (this.#config.selfTamperProof || this.#config.selfNpmTamperProof) {
            console.error('Configuration is tamper-proof. Save aborted.');
            return;
        }

        if (this.#validateConfig(this.#config)) {
            fs.writeFileSync(this.#configFilePath, JSON.stringify(this.#config, null, 2));
            this.log('Configuration saved successfully.');
        } else {
            console.error('Invalid configuration. Save aborted.');
        }
    }

    /**
     * Validates the given configuration object.
     * @param config - The configuration object to validate.
     * @returns True if the configuration is valid, false otherwise.
     */
    #validateConfig(config: any): boolean {
        if (!Array.isArray(config.paths)) return false;
        if (!Array.isArray(config.excludePaths)) return false;
        if (!Array.isArray(config.fileTypes)) return false;
        if (!Array.isArray(config.fileRegexs)) return false;
        if (typeof config.useFileTypes !== 'boolean') return false;
        if (typeof config.useFileRegexs !== 'boolean') return false;
        if (typeof config.useCeaserCipher !== 'boolean') return false;
        if (typeof config.useAesKey !== 'boolean') return false;
        if (typeof config.forkDelay !== 'number') return false;
        if (typeof config.forkExecutionDelay !== 'number') return false;
        if (typeof config.threads !== 'number') return false;
        if (typeof config.debug !== 'boolean') return false;
        if (typeof config.whiteSpaceOffset !== 'number') return false;
        if (typeof config.localPathReferences !== 'boolean') return false;
        if (typeof config.selfTamperProof !== 'boolean') return false;
        if (typeof config.selfNpmTamperProof !== 'boolean') return false;
        return true;
    }

    /**
     * Loads the configuration from the configuration file.
     */
    #loadConfig() {
        if (this.#config.selfTamperProof || this.#config.selfNpmTamperProof) {
            console.error('Configuration is tamper-proof. Load aborted.');
            return;
        }

        if (fs.existsSync(this.#configFilePath)) {
            const loadedConfig = JSON.parse(fs.readFileSync(this.#configFilePath, 'utf-8'));
            if (this.#validateConfig(loadedConfig)) {
                this.#config = loadedConfig;
                this.log('Configuration loaded successfully.');
            } else {
                console.error('Invalid configuration file. Loading defaults.');
                this.#config = { paths: [], excludePaths: [], fileTypes: [], fileRegexs: [], useFileTypes: false, useFileRegexs: false, useCeaserCipher: false, useAesKey: false, debug: false, forkDelay: 1, forkExecutionDelay: 1, threads: 1, whiteSpaceOffset: 0, localPathReferences: false, selfTamperProof: false, selfNpmTamperProof: false };
            }
        } else {
            this.#config = { paths: [], excludePaths: [], fileTypes: [], fileRegexs: [], useFileTypes: false, useFileRegexs: false, useCeaserCipher: false, useAesKey: false, debug: false, forkDelay: 1, forkExecutionDelay: 1, threads: 1, whiteSpaceOffset: 0, localPathReferences: false, selfTamperProof: false, selfNpmTamperProof: false };
        }
    }

    /**
     * Saves the current configuration to the configuration file.
     * This method is public and updates the internal configuration before saving.
     */
    public saveConfigP() {
        const config = {
            paths: this.#paths,
            excludePaths: this.#excludePaths,
            fileTypes: this.#fileTypes,
            fileRegexs: this.#fileRegexs,
            useFileTypes: this.#useFileTypes,
            useFileRegexs: this.#useFileRegexs,
            useCeaserCipher: this.#useCeaserCipher,
            useAesKey: this.#useAesKey,
            forkDelay: this.#forkDelay,
            forkExecutionDelay: this.#forkExecutionDelay,
            threads: this.#threads,
            debug: this.#debug,
            whiteSpaceOffset: this.#whiteSpaceOffset,
            localPathReferences: this.#localPathReferences,
            selfTamperProof: this.#selfTamperProof,
            selfNpmTamperProof: this.#selfNpmTamperProof,
        }
        if (this.#validateConfig(config)) {
            this.#config = config;
            this.#saveConfig();
        } else {
            console.error('Invalid configuration. Save aborted.');
        }
    }

    /**
     * Adds a path to the configuration.
     * @param path - The path to add.
     */
    addPath(path: string) {
        if (this.#configLock)return;
        if (!this.#config.paths.includes(path)) {
            this.#config.paths.push(path);
            this.#saveConfig();
            this.log(`Path ${path} added to configuration.`);
        }
    }

    /**
     * Removes a path from the configuration.
     * @param path - The path to remove.
     */
    removePath(path: string) {
        if (this.#configLock)return;
        const index = this.#config.paths.indexOf(path);
        if (index > -1) {
            this.#config.paths.splice(index, 1);
            this.#saveConfig();
            this.log(`Path ${path} removed from configuration.`);
        }
    }

    /**
     * Adds an exclude path to the configuration.
     * @param path - The exclude path to add.
     */
    addExcludePath(path: string) {
        if (this.#configLock)return;
        if (!this.#config.excludePaths.includes(path)) {
            this.#config.excludePaths.push(path);
            this.#saveConfig();
            this.log(`Exclude path ${path} added to configuration.`);
        }
    }

    /**
     * Removes an exclude path from the configuration.
     * @param path - The exclude path to remove.
     */
    removeExcludePath(path: string) {
        if (this.#configLock)return;
        const index = this.#config.excludePaths.indexOf(path);
        if (index > -1) {
            this.#config.excludePaths.splice(index, 1);
            this.#saveConfig();
            this.log(`Exclude path ${path} removed from configuration.`);
        }
    }

    /**
     * Adds a file type to the configuration.
     * @param fileType - The file type to add.
     */
    addFileType(fileType: string) {
        if (this.#configLock)return;
        if (!this.#config.fileTypes.includes(fileType)) {
            this.#config.fileTypes.push(fileType);
            this.#saveConfig();
            this.log(`File type ${fileType} added to configuration.`);
        }
    }

    /**
     * Removes a file type from the configuration.
     * @param fileType - The file type to remove.
     */
    removeFileType(fileType: string) {
        if (this.#configLock)return;
        const index = this.#config.fileTypes.indexOf(fileType);
        if (index > -1) {
            this.#config.fileTypes.splice(index, 1);
            this.#saveConfig();
            this.log(`File type ${fileType} removed from configuration.`);
        }
    }

    /**
     * Adds a file regex to the configuration.
     * @param regex - The file regex to add.
     */
    addFileRegex(regex: string) {
        if (this.#configLock)return;
        if (!this.#config.fileRegexs.includes(regex)) {
            this.#config.fileRegexs.push(regex);
            this.#saveConfig();
            this.log(`File regex ${regex} added to configuration.`);
        }
    }

    /**
     * Removes a file regex from the configuration.
     * @param regex - The file regex to remove.
     */
    removeFileRegex(regex: string) {
        if (this.#configLock)return;
        const index = this.#config.fileRegexs.indexOf(regex);
        if (index > -1) {
            this.#config.fileRegexs.splice(index, 1);
            this.#saveConfig();
            this.log(`File regex ${regex} removed from configuration.`);
        }
    }

    getConfig(){
        //Memory safe proper export of configuration incase they want to runtime lock the config file!
        //Exports a duplicate! in runtime config lock mode!
        if (this.#configLock) {
            //Due to the nature of JSON parsing and stringifying we can make a deep copy of the object to return!
            const config = JSON.parse(JSON.stringify(this.#config));
            return config;
        }
        return this.#config;
    }

    // Add similar methods for threads
}