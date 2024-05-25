
#include "LuciferCipher.h"

/**
* @brief A class with a description of the cipher structure
*
* This class describes the format of an incoming message, cipher blocks, and round keys.
*/
LuciferCipher::LuciferCipher()
{
}


/**
* @brief The function of the reverse S-block
*
* The function is used to create a reverse S-block when decrypting a message.
*/
void LuciferCipher::genInverseSBox()
{
    for (unsigned int i = 0; i < 16; ++i) {
        s_box_inverse[s_box[i]] = i;
    }
}

void LuciferCipher::genInversePBox()
{

}

string LuciferCipher::stringToHex(const string& input)
{
    stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char c : input)
        ss << std::setw(2) << static_cast<unsigned int>(c);
    return ss.str();
}

string LuciferCipher::hexToString(const string& input)
{
    string result;
    for (size_t i = 0; i < input.length(); i += 2) {
        istringstream iss(input.substr(i, 2));
        int hexValue;
        iss >> std::hex >> hexValue;
        result.push_back(static_cast<unsigned char>(hexValue));
    }
    return result;
}

uint8_t LuciferCipher::hexCharToDecimal(char hexChar)
{
    if (hexChar >= '0' && hexChar <= '9') {
        return hexChar - '0';
    }
    else if (hexChar >= 'A' && hexChar <= 'F') {
        return hexChar - 'A' + 10;
    }
    else if (hexChar >= 'a' && hexChar <= 'f') {
        return hexChar - 'a' + 10;
    }
    else {
        // Íåêîððåêòíûé ñèìâîë
        return 255;
    }
}

/**
* @brief Round key generation function.
*
* @param key 8-bit key
* @param roundKeys The key matrix
*/
void LuciferCipher::genRoundKeys(uint8_t* key, uint8_t roundKeys[16][8])
{
    for (unsigned int i = 0; i < 16; ++i) {
        for (unsigned int j = 0; j < 8; ++j) {
            roundKeys[i][j] = key[(7 * i + j) % 16];
        }
    }
}

/**
* @brief The bit permutation function
*
* @param block A block of bits
* @param p_box Permutation box
*/
void LuciferCipher::permuteBits(uint8_t_union* block, uint8_t* p_box)
{
    uint8_t_union tmp[16] = { 0 };

    for (unsigned int i = 0; i < 128; ++i) {
        uint8_t from_byte = i / 8;
        uint8_t from_bit = i % 8;
        uint8_t to_byte = p_box[i] / 8;
        uint8_t to_bit = p_box[i] % 8;

        uint8_t bit_value = 0;
        switch (from_bit) {
        case 0: bit_value = block[from_byte].bit_block.b0; break;
        case 1: bit_value = block[from_byte].bit_block.b1; break;
        case 2: bit_value = block[from_byte].bit_block.b2; break;
        case 3: bit_value = block[from_byte].bit_block.b3; break;
        case 4: bit_value = block[from_byte].bit_block.b4; break;
        case 5: bit_value = block[from_byte].bit_block.b5; break;
        case 6: bit_value = block[from_byte].bit_block.b6; break;
        case 7: bit_value = block[from_byte].bit_block.b7; break;
        }

        switch (to_bit) {
        case 0: tmp[to_byte].bit_block.b0 = bit_value; break;
        case 1: tmp[to_byte].bit_block.b1 = bit_value; break;
        case 2: tmp[to_byte].bit_block.b2 = bit_value; break;
        case 3: tmp[to_byte].bit_block.b3 = bit_value; break;
        case 4: tmp[to_byte].bit_block.b4 = bit_value; break;
        case 5: tmp[to_byte].bit_block.b5 = bit_value; break;
        case 6: tmp[to_byte].bit_block.b6 = bit_value; break;
        case 7: tmp[to_byte].bit_block.b7 = bit_value; break;
        }
    }

    for (unsigned int i = 0; i < 16; ++i) {
        block[i].block = tmp[i].block;
    }
}

/**
* @brief Bit block replacement function
*
* @param block A block of bits g
* @param s_box Substitution block 
*/
void LuciferCipher::transformSBits(uint8_t_union* block, uint8_t* s_box)
{
    for (unsigned int i = 0; i < 16; ++i) {
        uint8_t lowBits = block[i].block & 0b00001111;
        uint8_t highBits = (block[i].block >> 4);
        uint8_t res = 0;
        res += s_box[highBits] << 4;
        res += s_box[lowBits];
        block[i].block = res;
    }
}

void LuciferCipher::padString(string& str, size_t blockSize)
{
    while (str.size() % blockSize != 0) {
        str += '\0';
    }
}

void LuciferCipher::encryptBlock(uint8_t_union* block, uint8_t* p_box, uint8_t* s_box, uint8_t roundKeys[16][8], unsigned int round)
{
    // XOR block with the round key
    for (unsigned int i = 0; i < 16; ++i) {
        block[i].block ^= roundKeys[round][i % 8];
    }

    transformSBits(block, s_box);

    // Ïðèìåíåíèå ïåðåñòàíîâêè áèòîâ
    permuteBits(block, p_box);
}

/**
* @brief Encryption function
*
* @param text The source text
* @param key The key for encryption
* @param numRounds Number of rounds of encryption
* 
* @return Encrypted message
*/
string LuciferCipher::encrypt(const string& text, const string& key, unsigned int numRounds)
{
    // Ïðîâåðêà êîððåêòíîñòè äëèíû êëþ÷à
    if (key.size() != 32) {
        cout << "Miscusi: Key size is not 128 bit!\n";
        return "";
    }

    // Ïðîâåðêà êîððåêòíîñòè ôîðìàòà êëþ÷à
    for (char hexChar : key) {
        if (!isxdigit(hexChar)) {
            cout << "Miscusi: Key is not in hex format!\n";
            return "";
        }
    }

    string paddedText = text;
    padString(paddedText, 16);

    string encryptedText = "";
    uint8_t_union byteArray[16];
    uint8_t byteKey[16];
    uint8_t roundKeys[16][8];

    // key string to byte array
    for (unsigned int i = 0; i < 16; ++i) {
        uint8_t highBit = hexCharToDecimal(key.at(i * 2)) << 4;
        uint8_t lowBit = hexCharToDecimal(key.at(i * 2 + 1));
        byteKey[i] = highBit + lowBit;
    }

    genRoundKeys(byteKey, roundKeys);

    for (unsigned int i_block = 0; i_block < paddedText.size() / 16; ++i_block) {
        for (unsigned int i_char = 0; i_char < 16; ++i_char) {
            byteArray[i_char].block = paddedText.at(i_block * 16 + i_char);
        }

        for (unsigned int i_round = 0; i_round < numRounds; ++i_round) {
            encryptBlock(byteArray, p_box, s_box, roundKeys, i_round);
        }

        for (unsigned int i_char = 0; i_char < 16; ++i_char) {
            encryptedText += (char)byteArray[i_char].block;
        }
    }

    return stringToHex(encryptedText);
}

void LuciferCipher::decryptBlock(uint8_t_union* block, uint8_t* p_box, uint8_t* s_box, uint8_t roundKeys[16][8], unsigned int round)
{
    // Îáðàòíàÿ ïåðåñòàíîâêà áèòîâ
    for (unsigned int i = 0; i < 128; ++i) {
        p_box_reverse[p_box[i]] = i;
    }

    permuteBits(block, p_box_reverse);

    transformSBits(block, s_box);

    // XOR block with the round key
    for (unsigned int i = 0; i < 16; ++i) {
        block[i].block ^= roundKeys[round][i % 8];
    }
}

/**
* @brief Decryption function
*
* @param text Encrypted text
* @param key The key for decryption
* @param numRounds Number of rounds of decryption
*
* @return The decrypted message
*/
string LuciferCipher::decrypt(const string& text, const string& key, unsigned int numRounds)
{
    // Ïðîâåðêà êîððåêòíîñòè äëèíû òåêñòà
    if (text.size() % 32 != 0) {
        cout << "Miscusi: Text length is not a multiple of 16 bytes!\n";
        return "";
    }

    // Ïðîâåðêà êîððåêòíîñòè äëèíû êëþ÷à
    if (key.size() != 32) {
        cout << "Miscusi: Key size is not 128 bit!\n";
        return "";
    }

    // Ïðîâåðêà êîððåêòíîñòè ôîðìàòà êëþ÷à
    for (char hexChar : key) {
        if (!isxdigit(hexChar)) {
            cout << "Miscusi: Key is not in hex format!\n";
            return "";
        }
    }

    string decryptedText = "";
    uint8_t_union byteArray[16];
    uint8_t byteKey[16];
    uint8_t roundKeys[16][8];

    // key string to byte array
    for (unsigned int i = 0; i < 16; ++i) {
        uint8_t highBit = hexCharToDecimal(key.at(i * 2)) << 4;
        uint8_t lowBit = hexCharToDecimal(key.at(i * 2 + 1));
        byteKey[i] = highBit + lowBit;
    }

    genRoundKeys(byteKey, roundKeys);
    genInverseSBox();

    for (unsigned int i_block = 0; i_block < text.size() / 32; ++i_block) {
        for (unsigned int i_char = 0; i_char < 16; ++i_char) {
            uint8_t highBit = hexCharToDecimal(text.at(i_block * 32 + i_char * 2)) << 4;
            uint8_t lowBit = hexCharToDecimal(text.at(i_block * 32 + i_char * 2 + 1));
            byteArray[i_char].block = highBit + lowBit;
        }

        for (int i_round = numRounds - 1; i_round >= 0; --i_round) {
            decryptBlock(byteArray, p_box, s_box_inverse, roundKeys, i_round);
        }

        for (unsigned int i_char = 0; i_char < 16; ++i_char) {
            decryptedText += (char)byteArray[i_char].block;
        }
    }

    // Remove padding
    decryptedText.erase(decryptedText.find_last_not_of('\0') + 1);

    return decryptedText;
}
