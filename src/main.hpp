#include <string>
#include <vector>
#include <iostream>
#include <iomanip>
#include <random>
#include <chrono>

std::string pad(const std::string& data) {
    std::string output = data;
    output += "8";

    while ((output.size() * 4) % 64 != 0) {
        output += "0";
    }
    return output;
}

std::vector<std::string> separate(const std::string& data) {
    std::vector<std::string> blocks;
    for (size_t i = 0; i < data.size(); i += 16) {
        blocks.push_back(data.substr(i, 16));
    }
    return blocks;
}


void processInput(std::string& in)
{
    if (in.size() >= 2 &&
        in[0] == '0' &&
        (in[1] == 'x' || in[1] == 'X'))
    {
        in.erase(0, 2);
    }
}

void printState(const uint64_t s[5]) {
    for (int i = 0; i < 5; ++i) {
        std::cout << std::endl << "x" << i << "=0x"
                  << std::hex << std::setw(16) << std::setfill('0')
                  << s[i];
    }
    std::cout << std::dec << "\n" << "__________________________________________" << std::endl;
}

std::string produceTag(uint64_t* s) {
    std::ostringstream oss;
    oss << std::hex << std::setw(16) << std::setfill('0') << s[3]
        << std::setw(16) << std::setfill('0') << s[4];
    return oss.str();
}

bool isValidHex(const std::string& s) {
    for (char c : s)
        if (!isxdigit(c)) return false;
    return !s.empty();
}

std::string generateString() {
    const std::string chars = "0123456789abcdef";
    std::string result;
    static std::mt19937 gen(
        (uint32_t)std::chrono::high_resolution_clock::now()
            .time_since_epoch().count()
    );
    static std::uniform_int_distribution<int> distr(0, 15);
    for (int i = 0; i < 32; i++)
        result += chars[distr(gen)];
    return result;
}

void displayInfo(const std::string& nonce, const std::string& key,
                 const std::string& data, const std::string& adata,
                 const std::string& mode, const std::string& tag = "") {
    std::cout << "\n____________________________________________________\n";
    std::cout << "\nKey:\n0x" << key << "\n";
    std::cout << "\nNonce:\n0x" << nonce << "\n";

    if (!adata.empty())
        std::cout << "\nAssociated Data:\n0x" << adata << "\n";
    else
        std::cout << "\nAssociated Data:\nN/A\n";

    if (mode == "e" || mode == "encrypt")
        std::cout << "\nPlaintext:\n0x" << data << "\n";
    else {
        std::cout << "\nCiphertext:\n0x" << data << "\n";
        std::cout << "\nTag:\n0x" << tag << "\n";
    }

    std::cout << "____________________________________________________\n\n";
}