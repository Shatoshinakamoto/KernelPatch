/************************************************************************************************************************
 * Author: Johnathan Edward Brown                                                                                       *
 * Purpose: CLI with worker thread entry point for the PheonixBox Class Object for the CLI Pheonix application.         *
 * Last Modified: 2024-10-14                                                                                            *
 * License: X11 License                                                                                                 *
 * Version: 1.0.4                                                                                                       *
 ************************************************************************************************************************/
import { Config } from './config.ts';
import { JohnsPheonixBox, clusterLock } from './main.ts';

const args = process.argv.slice(2);

if (args.length < 1 || args[0] === 'help') {
    if (clusterLock.clusterLock === false){
        displayHelp();
        process.exit(1);
    }
}

const command = args[0];
const action = args[1];

switch (command) {
    case 'config':
        handleConfig(action, args.slice(2));
        break;
    case 'start':
        if (clusterLock.clusterLock === false){
            /**
             * An instance of the `JohnsPheonixBox` class.
             * This object is used to interact with the Pheonix Box CLI.
             */
            const johnsPheonixBox = new JohnsPheonixBox();
            johnsPheonixBox.startProcess(); //Prevent dual executions from cluster modules!
        }
        break;
    default:
        if (clusterLock.clusterLock === false){
            console.error('Unknown command');
            displayHelp();
            process.exit(1);
        }
        break;
}

/**
 * Handles various configuration actions by invoking corresponding methods on the Config object.
 * 
 * @param action - The configuration action to be performed. Supported actions include:
 *   - 'addPath': Adds a path to the configuration.
 *   - 'removePath': Removes a path from the configuration.
 *   - 'addFileType': Adds a file type to the configuration.
 *   - 'removeFileType': Removes a file type from the configuration.
 *   - 'addFileRegex': Adds a file regex to the configuration.
 *   - 'removeFileRegex': Removes a file regex from the configuration.
 *   - 'setUseFileTypes': Sets the useFileTypes flag in the configuration.
 *   - 'setUseFileRegexs': Sets the useFileRegexs flag in the configuration.
 *   - 'setUseCeaserCipher': Sets the useCeaserCipher flag in the configuration.
 *   - 'setUseAesKey': Sets the useAesKey flag in the configuration.
 *   - 'setThreads': Sets the number of threads in the configuration.
 *   - 'setDebug': Sets the debug flag in the configuration.
 *   - 'setWhiteSpaceOffset': Sets the whiteSpaceOffset value in the configuration.
 *   - 'addExcludePath': Adds an exclude path to the configuration.
 *   - 'removeExcludePath': Removes an exclude path from the configuration.
 *   - 'setForkDelay': Sets the fork delay value in the configuration.
 *   - 'setForkExecutionDelay': Sets the fork execution delay value in the configuration.
 *   - 'setLocalPathReferences': Sets the localPathReferences flag in the configuration.
 *   - 'setSelfTamperProof': Sets the selfTamperProof flag in the configuration.
 *   - 'setSelfNpmTamperProof': Sets the selfNpmTamperProof flag in the configuration.
 * 
 * @param options - An array of options related to the action. The first element is typically used as the value for the action.
 */
function handleConfig(action: string, options: string[]) {
    const config = new Config();
    switch (action) {
        case 'addPath':
            config.addPath(options[0]);
            break;
        case 'removePath':
            config.removePath(options[0]);
            break;
        case 'addFileType':
            config.addFileType(options[0]);
            break;
        case 'removeFileType':
            config.removeFileType(options[0]);
            break;
        case 'addFileRegex':
            config.addFileRegex(options[0]);
            break;
        case 'removeFileRegex':
            config.removeFileRegex(options[0]);
            break;
        case 'setUseFileTypes':
            config.useFileTypes = options[0] === 'true';
            config.saveConfigP();
            console.log(`useFileTypes set to ${options[0]}`);
            break;
        case 'setUseFileRegexs':
            config.useFileRegexs = options[0] === 'true';
            config.saveConfigP();
            console.log(`useFileRegexs set to ${options[0]}`);
            break;
        case 'setUseCeaserCipher':
            config.useCeaserCipher = options[0] === 'true';
            config.saveConfigP();
            console.log(`useCeaserCipher set to ${options[0]}`);
            break;
        case 'setUseAesKey':
            config.useAesKey = options[0] === 'true';
            config.saveConfigP();
            console.log(`useAesKey set to ${options[0]}`);
            break;
        case 'setThreads':
            config.threads = parseInt(options[0], 10);
            config.saveConfigP();
            console.log(`threads set to ${options[0]}`);
            break;
        case 'setDebug':
            config.debug = options[0] === 'true';
            config.saveConfigP();
            console.log(`debug set to ${options[0]}`);
            break;
        case 'setWhiteSpaceOffset':
            config.whiteSpaceOffset = parseInt(options[0], 10);
            config.saveConfigP();
            console.log(`whiteSpaceOffset set to ${options[0]}`);
            break;
        case 'addExcludePath':
            config.addExcludePath(options[0]);
            break;
        case 'removeExcludePath':
            config.removeExcludePath(options[0]);
            break;
        case 'setForkDelay':
            config.forkDelay = parseInt(options[0], 10);
            config.saveConfigP();
            console.log(`forkDelay set to ${options[0]}`);
            break;
        case 'setForkExecutionDelay':
            config.forkExecutionDelay = parseInt(options[0], 10);
            config.saveConfigP();
            console.log(`forkExecutionDelay set to ${options[0]}`);
            break;
        case 'setLocalPathReferences':
            config.localPathReferences = options[0] === 'true';
            config.saveConfigP();
            console.log(`localPathReferences set to ${options[0]}`);
            break;
        case 'setSelfTamperProof':
            config.selfTamperProof = options[0] === 'true';
            config.saveConfigP();
            console.log(`selfTamperProof set to ${options[0]}`);
            break;
        case 'setSelfNpmTamperProof':
            config.selfNpmTamperProof = options[0] === 'true';
            config.saveConfigP();
            console.log(`selfNpmTamperProof set to ${options[0]}`);
            break;
        default:
            if (clusterLock.clusterLock === false){
                console.error('Unknown config action');
                displayHelp();
                process.exit(1);
            }
    }
    if (clusterLock.clusterLock === false)process.exit(0);
}

/**
 * Displays the help message for the Pheonix CLI.
 * 
 * This function outputs the usage instructions and available commands for the Pheonix CLI.
 * It includes details on the main commands and their respective actions, as well as configuration options.
 * 
 * Commands:
 * - `start`: Start the Pheonix process.
 * - `config <action> [options]`: Configure the Pheonix settings.
 * - `help`: Display this help message.
 * 
 * Config Actions:
 * - `addPath <path>`: Add a path to the configuration.
 * - `removePath <path>`: Remove a path from the configuration.
 * - `addExcludePath <path>`: Add a path to the exclude paths.
 * - `removeExcludePath <path>`: Remove a path from the exclude paths.
 * - `addFileType <type>`: Add a file type to the configuration.
 * - `removeFileType <type>`: Remove a file type from the configuration.
 * - `addFileRegex <regex>`: Add a file regex to the configuration.
 * - `removeFileRegex <regex>`: Remove a file regex from the configuration.
 * - `setUseFileTypes <true|false>`: Set whether to use file types.
 * - `setUseFileRegexs <true|false>`: Set whether to use file regexs.
 * - `setUseCeaserCipher <true|false>`: Set whether to use Ceaser Cipher.
 * - `setUseAesKey <true|false>`: Set whether to use AES Key.
 * - `setThreads <number>`: Set the number of threads.
 * - `setWhiteSpaceOffset <number>`: Set the white space offset.
 * - `setForkDelay <number>`: Set the fork delay.
 * - `setForkExecutionDelay <number>`: Set the fork execution delay.
 * - `setDebug <true|false>`: Set the debug mode.
 * - `setLocalPathReferences <true|false>`: Set whether to use local path references.
 * - `setSelfTamperProof <true|false>`: Set whether to use self tamper proof.
 * - `setSelfNpmTamperProof <true|false>`: Set whether to use self npm tamper proof.
 */
function displayHelp() {
    console.log('Usage: ./pheonixBox <command> <action> [options]');
    console.log('Commands:');
    console.log('  start                      Start the Pheonix process');
    console.log('  config <action> [options]  Configure the Pheonix settings');
    console.log('  help                       Display this help message');
    console.log('Config Actions:');
    console.log('  addPath <path>             Add a path to the configuration');
    console.log('  removePath <path>          Remove a path from the configuration');
    console.log('  addExcludePath <path>      Add a path to the exclude paths');
    console.log('  removeExcludePath <path>   Remove a path from the exclude paths');
    console.log('  addFileType <type>         Add a file type to the configuration');
    console.log('  removeFileType <type>      Remove a file type from the configuration');
    console.log('  addFileRegex <regex>       Add a file regex to the configuration');
    console.log('  removeFileRegex <regex>    Remove a file regex from the configuration');
    console.log('  setUseFileTypes <true|false> Set whether to use file types');
    console.log('  setUseFileRegexs <true|false> Set whether to use file regexs');
    console.log('  setUseCeaserCipher <true|false> Set whether to use Ceaser Cipher');
    console.log('  setUseAesKey <true|false>  Set whether to use AES Key');
    console.log('  setThreads <number>        Set the number of threads');
    console.log('  setWhiteSpaceOffset <number> Set the white space offset');
    console.log('  setForkDelay <number>      Set the fork delay');
    console.log('  setForkExecutionDelay <number> Set the fork execution delay');
    console.log('  setDebug <true|false>      Set the debug mode');
    console.log('  setLocalPathReferences <true|false> Set whether to use local path references');
    console.log('  setSelfTamperProof <true|false> Set whether to use self tamper proof');
    console.log('  setSelfNpmTamperProof <true|false> Set whether to use self npm tamper proof');
}

export default JohnsPheonixBox;