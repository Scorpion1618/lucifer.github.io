#pragma once

#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstdint>

using namespace std;

class LuciferCipher
{
private:
    typedef struct
    {
        uint8_t b0 : 1;
        uint8_t b1 : 1;
        uint8_t b2 : 1;
        uint8_t b3 : 1;
        uint8_t b4 : 1;
        uint8_t b5 : 1;
        uint8_t b6 : 1;
        uint8_t b7 : 1;
    } uint8_t_1bit;

    union uint8_t_union
    {
        uint8_t block;
        uint8_t_1bit bit_block;
    };

    uint8_t p_box[128] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
        48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
        64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
        80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95,
        96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
        112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127
    };

    uint8_t s_box[16] = {
        0x0C, 0x05, 0x06, 0x0B,
        0x09, 0x00, 0x0A, 0x0D,
        0x03, 0x0E, 0x0F, 0x08,
        0x04, 0x07, 0x01, 0x02
    };

    uint8_t s_box_inverse[16];
    uint8_t p_box_reverse[128];

    void genInverseSBox();
    void genInversePBox();

    string stringToHex(const string& input);
    string hexToString(const string& input);
    uint8_t hexCharToDecimal(char hexChar);

    void genRoundKeys(uint8_t* key, uint8_t roundKeys[16][8]);
    void permuteBits(uint8_t_union* block, uint8_t* p_box);
    void transformSBits(uint8_t_union* block, uint8_t* s_box);

    void padString(string& str, size_t blockSize);

    //void encryptBlock(uint8_t_union* block, uint8_t* p_box, uint8_t* s_box, uint8_t roundKeys[16][8], unsigned int round)
    void encryptBlock(uint8_t_union* block, uint8_t* p_box, uint8_t* s_box, uint8_t roundKeys[16][8], unsigned int round);
    void decryptBlock(uint8_t_union* block, uint8_t* p_box, uint8_t* s_box, uint8_t roundKeys[16][8], unsigned int round);

public:
    LuciferCipher();

    string encrypt(const string& text, const string& key, unsigned int numRounds);
    string decrypt(const string& text, const string& key, unsigned int numRounds);

};
