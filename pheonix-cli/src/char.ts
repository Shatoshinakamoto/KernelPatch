/************************************************************************************************************************
 * Author: Johnathan Edward Brown                                                                                       *
 * Purpose: Generate safe UTF-8 characters for use in the PheonixBox Class Object for the CLI Pheonix application.      *
 * Last Modified: 2024-10-14                                                                                            *
 * License: X11 License                                                                                                 *
 * Version: 1.0.4                                                                                                       *
 ************************************************************************************************************************/

/**
 * Generates an array of safe UTF-8 characters, excluding certain control characters and other specified characters.
 *
 * @param count - The number of additional spaces to append to the array of safe characters.
 * @returns An array of safe UTF-8 characters.
 *
 * @remarks
 * The function excludes characters such as backslashes, backticks, dollar signs, escape characters, and other control characters.
 * It also skips surrogate pairs and C1 control characters.
 * The resulting characters are filtered to ensure they are within the byte range of the UTF-8 format.
 *
 * @example
 * ```typescript
 * const safeChars = generateSafeUtf8Characters(5);
 * console.log(safeChars);
 * ```
 */
export function generateSafeUtf8Characters(count: number): string[] {
    const excludedCharacters = [
        '\\', '`', '$', '\x1B', '\uFFFD', '\b', '\f', '\n', '\r', '\t', '\v', '\0', 
        '\'', '\"', '\u2028', '\u2029', '\uD800-\uDFFF', '\uFFFE', '\uFFFF'
    ]; // Add more exclusions as needed
    const safeCharacters: string[] = [];
    
    for (let i = 32; i < 0x10FFFF; i++) { // UTF-8 characters range from 32 to 0x10FFFF
        if (i >= 0xD800 && i <= 0xDFFF) continue; // Skip surrogate pairs
        if (i >= 0x7F && i <= 0x9F) continue; // Skip C1 control characters
        const char = String.fromCodePoint(i);
        if (!excludedCharacters.includes(char) && char.trim().length > 0) {
            safeCharacters.push(char);
        }
    }

    const aesSafeCharacters = safeCharacters.filter(char => char.charCodeAt(0) <= 0x10FFF); //This ensure safe utf-8 characters are within the byte range of format!

    for (let i = 0; i < count; i++){
        aesSafeCharacters.push('  ');
    }
//    console.log('safeCharacters:', safeCharacters.join(''));
    console.log('safeCharacters:', aesSafeCharacters.join('').length);
    return aesSafeCharacters;
}


export function generateSafeUtf8CharactersForAES(count: number): string[] {
    const excludedCharacters = [
        '\\', '`', '$', '\x1B', '\uFFFD', '\b', '\f', '\n', '\r', '\t', '\v', '\0', 
        '\'', '\"', '\u2028', '\u2029', '\uD800-\uDFFF', '\uFFFE', '\uFFFF'
    ]; // Add more exclusions as needed
    const safeCharacters: string[] = [];
    
    for (let i = 32; i < 0x10FFFF; i++) { // UTF-8 characters range from 32 to 0x10FFFF
        if (i >= 0xD800 && i <= 0xDFFF) continue; // Skip surrogate pairs
        if (i >= 0x7F && i <= 0x9F) continue; // Skip C1 control characters
        const char = String.fromCodePoint(i);
        if (!excludedCharacters.includes(char) && char.trim().length > 0) {
            safeCharacters.push(char);
        }
    }

    for (let i = 0; i < count; i++){
        //safeCharacters.push('  ');
    }

    // AES encryption typically works with bytes, so we need to ensure the characters are within the byte range
    const aesSafeCharacters = safeCharacters.filter(char => char.charCodeAt(0) <= 0xFFF); //This ensure safe AES characters are within the byte range of format!

    for (let i = 0; i < count; i++){
        aesSafeCharacters.push('  ');
    }
//    console.log('aesSafeCharacters:', aesSafeCharacters.join(''));
    console.log('aesSafeCharacters:', aesSafeCharacters.join('').length);
    return aesSafeCharacters;
}

//console.log(generateSafeUtf8Characters(32)); //Generate with random off spaces of white spaces!