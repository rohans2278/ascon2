#include "main.hpp"
#include <iostream>
#include <cstdint>
#include <string>
#include <iomanip>
#include <vector>
#include <sstream>

static constexpr uint64_t ROUND_CONSTANTS[12] = {0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b};
static constexpr uint64_t IV = 0x80400c0600000000ULL;

void constantAddition(uint64_t* s, int round, int total_rounds){
    s[2] ^= ROUND_CONSTANTS[12 - total_rounds + round];
}

void substitutionLayer(uint64_t* s) {
    uint64_t t[5];

    s[0] ^= s[4];
    s[4] ^= s[3];
    s[2] ^= s[1];

    t[0] = ~s[0] & s[1];
    t[1] = ~s[1] & s[2];
    t[2] = ~s[2] & s[3];
    t[3] = ~s[3] & s[4];
    t[4] = ~s[4] & s[0];

    s[0] ^= t[1];
    s[1] ^= t[2];
    s[2] ^= t[3];
    s[3] ^= t[4];
    s[4] ^= t[0];

    s[1] ^= s[0];
    s[0] ^= s[4];
    s[3] ^= s[2];
    s[2] = ~s[2];
}

uint64_t rot(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}

void linearDiffusion(uint64_t* s) {
    s[0] ^= (rot(s[0], 19) ^ rot(s[0], 28));
    s[1] ^= (rot(s[1], 61) ^ rot(s[1], 39));
    s[2] ^= (rot(s[2], 1)  ^ rot(s[2], 6));
    s[3] ^= (rot(s[3], 10) ^ rot(s[3], 17));
    s[4] ^= (rot(s[4], 7)  ^ rot(s[4], 41));
}

void permutation(uint64_t s[5], int rounds) {
    for (int i = 0; i < rounds; ++i) {
        constantAddition(s, i, rounds);
        substitutionLayer(s);
        linearDiffusion(s);
    }
}

//_______________END OF PERMUTATION________________________________________________//


void initialization(uint64_t* s, uint64_t K0, uint64_t K1){
    permutation(s, 12);
    s[3] ^= K0;
    s[4] ^= K1;
}


void processAssociatedData(uint64_t* s, const std::string& adata)
{
    std::string padded = pad(adata);
    auto blocks = separate(padded);

    for (const auto& b : blocks) {
        uint64_t block = std::stoull(b, nullptr, 16);
        s[0] ^= block;
        permutation(s, 6);
    }

    s[4] ^= 1;
}


std::string processPlaintext(uint64_t* s, const std::string& plaintext) {
    std::string padded = pad(plaintext);
    auto blocks = separate(padded);
    std::string ct = "";

    for (size_t i = 0; i < blocks.size() - 1; i++) {
        uint64_t block = std::stoull(blocks[i], nullptr, 16);
        s[0] ^= block;
        std::ostringstream oss;
        oss << std::hex << std::setw(16) << std::setfill('0') << s[0];
        ct += oss.str();
        permutation(s, 6);
    }

    uint64_t last = std::stoull(blocks.back(), nullptr, 16);
    s[0] ^= last;
    std::ostringstream oss;
    oss << std::hex << std::setw(16) << std::setfill('0') << s[0];
    ct += oss.str();

    ct = ct.substr(0, plaintext.size());
    return ct;
}

void finalization(uint64_t* s, uint64_t K0, uint64_t K1) {
    s[1] ^= K0;
    s[2] ^= K1;
    permutation(s, 12);
    s[3] ^= K0;
    s[4] ^= K1;
}

std::string processCiphertext(uint64_t* s, const std::string& ciphertext) {
    std::string pt = "";
    bool even = false;
    std::string ct = ciphertext;

    if (ct.size() % 16 == 0) {
        ct = pad(ct);
        even = true;
    } else {
        ct = pad(ct);  
    }

    auto blocks = separate(ct);

    for (size_t i = 0; i < blocks.size() - 1; i++) {
        uint64_t block = std::stoull(blocks[i], nullptr, 16);
        uint64_t ptBlock = s[0] ^ block;
        std::ostringstream oss;
        oss << std::hex << std::setw(16) << std::setfill('0') << ptBlock;
        pt += oss.str();
        s[0] = block;
        permutation(s, 6);
    }

    uint64_t lastCt = std::stoull(blocks.back(), nullptr, 16);
    uint64_t lastPt = s[0] ^ lastCt;

    std::ostringstream oss;
    oss << std::hex << std::setw(16) << std::setfill('0') << lastPt;
    std::string lastBit = oss.str().substr(0, ciphertext.size() - pt.size());

    if (!even) {
        pt += lastBit;
        uint64_t paddedLastBit = std::stoull(pad(lastBit), nullptr, 16);
        s[0] ^= paddedLastBit;
    } else {
        s[0] = lastPt;
    }

    return pt;
}


//_______________END OF PERMUTATION________________________________________________//


void encrypt(const std::string& nonce, const std::string& key, const std::string& plaintext, const std::string& adata) {
    displayInfo(nonce, key, plaintext, adata, "e");
    uint64_t K0 = std::stoull(key.substr(0, 16), nullptr, 16);
    uint64_t K1 = std::stoull(key.substr(16, 16), nullptr, 16);

    uint64_t s[5];
    s[0] = IV;
    s[1] = K0;
    s[2] = K1;
    s[3] = std::stoull(nonce.substr(0, 16), nullptr, 16);
    s[4] = std::stoull(nonce.substr(16, 16), nullptr, 16);

    initialization(s, K0, K1);

    if (!adata.empty()){
        processAssociatedData(s, adata);
    }
    else{
        s[4] ^= 1;
    }  

    std::string ct = processPlaintext(s, plaintext);
    finalization(s, K0, K1);
    std::string tag = produceTag(s);

    std::cout << "\nCiphertext:\n0x" << ct << "\n\n";
    std::cout << "Tag:\n0x" << tag << "\n\n";
}

void decrypt(const std::string& nonce, const std::string& key, const std::string& ciphertext, const std::string& adata, const std::string& tag) {

    uint64_t K0 = std::stoull(key.substr(0, 16), nullptr, 16);
    uint64_t K1 = std::stoull(key.substr(16, 16), nullptr, 16);

    uint64_t s[5];
    s[0] = IV;
    s[1] = K0;
    s[2] = K1;
    s[3] = std::stoull(nonce.substr(0, 16), nullptr, 16);
    s[4] = std::stoull(nonce.substr(16, 16), nullptr, 16);

    initialization(s, K0, K1);

    if (!adata.empty())
        processAssociatedData(s, adata);
    else
        s[4] ^= 1;

    std::string pt = processCiphertext(s, ciphertext);
    finalization(s, K0, K1);
    std::string computedTag = produceTag(s);
    // std::cout << "Computed Tag: " << computedTag << std::endl;

    if (computedTag == tag) {
        std::cout << "\n\nPlaintext: " << pt << "\n\n";
    } else {
        std::cout << "Unable to decrypt\n\n";
    }
}

//_________________________________________________________________________________________________________________________________________


void run() {
    std::string key, nonce, plaintext, adata, ciphertext, tag, mode;

   

    while (true) {
        std::cout << "\nChoose to encrypt ('e') or decrypt ('d'): ";
        std::getline(std::cin, mode);
        if (mode == "e" || mode == "encrypt" || mode == "d" || mode == "decrypt") break;
        std::cout << "Invalid input\n";
    }

    if (mode == "e" || mode == "encrypt") {
        while (true) {
            std::cout << "\nEnter a 128-bit key or press enter to generate a random key: ";
            std::getline(std::cin, key);
            processInput(key);
            if (key.empty()) {
                key = generateString();
                std::cout << "Generated key: " << key << "\n";
                break;
            }
            if (isValidHex(key) && key.size() == 32) break;
            std::cout << "Invalid key\n";
        }

        nonce = generateString();

        while (true) {
            std::cout << "Enter the plaintext (in hexadecimal) to encrypt: ";
            std::getline(std::cin, plaintext);
            processInput(plaintext);
            if (isValidHex(plaintext)) break;
            std::cout << "Invalid format\n";
        }

        while (true) {
            std::cout << "Enter any associated data (in hexadecimal) or press enter to skip: ";
            std::getline(std::cin, adata);
            processInput(adata);
            if (adata.empty() || isValidHex(adata)) break;
            std::cout << "Invalid format\n";
        }

        encrypt(nonce, key, plaintext, adata);

    } else {
        while (true) {
            std::cout << "Enter the 128-bit key: ";
            std::getline(std::cin, key);
            processInput(key);
            if (isValidHex(key) && key.size() == 32) break;
            std::cout << "Invalid key\n";
        }

        while (true) {
            std::cout << "Enter the nonce used: ";
            std::getline(std::cin, nonce);
            processInput(nonce);
            if (isValidHex(nonce) && nonce.size() == 32) break;
            std::cout << "Invalid nonce\n";
        }

        while (true) {
            std::cout << "Enter the ciphertext (in hexadecimal) to decrypt: ";
            std::getline(std::cin, ciphertext);
            processInput(ciphertext);
            if (isValidHex(ciphertext)) break;
            std::cout << "Invalid format\n";
        }

        while (true) {
            std::cout << "Enter any associated data (in hexadecimal) or press enter to skip: ";
            std::getline(std::cin, adata);
            processInput(adata);
            if (adata.empty() || isValidHex(adata)) break;
            std::cout << "Invalid format\n";
        }

        while (true) {
            std::cout << "Enter the tag: ";
            std::getline(std::cin, tag);
            processInput(tag);
            if (isValidHex(tag) && tag.size() == 32) break;
            std::cout << "Invalid tag\n";
        }

        decrypt(nonce, key, ciphertext, adata, tag);
    }
}



int main()
{   
 
    // std::string key = "0x000102030405060708090a0b0c0d0e0f";
    // std::string adata = "0x000102030405060708090a0b0c0d0e0f";
    // std::string plaintext = "0x000102030405060708090a0b0c0d0e0f";
    // std::string nonce ="0x000102030405060708090a0b0c0d0e0f";
    // std::string ciphertext = "1ee34125fdba17443d01da8a0eefb045";
    // std::string tag = "4281d1d3b962418d2e1c8a6d14f3e8a2";

    // processInput(key);
    // processInput(adata);
    // processInput(plaintext);
    // processInput(nonce);

    // encrypt(nonce, key, plaintext, adata);
    // decrypt(nonce, key, ciphertext, adata, tag);
    run();

    return 0;
}   