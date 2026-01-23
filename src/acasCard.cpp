#include "acasCard.h"
#include <random>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include "config.h"

static void print_hex_simple_acas(const std::string& label, const uint8_t* data, size_t len) {
    std::cout << label << ": ";
    for (size_t i = 0; i < len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    std::cout << std::dec << std::endl;
}

bool AcasCard::getA0AuthKcl(sha256_t& output) {
    std::default_random_engine engine(std::random_device{}());
    std::uniform_int_distribution<int> distrib(0, 255);

    std::vector<uint8_t> data = { 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x8A, 0xF7 };
    std::vector<uint8_t> a0init(8);

    for (size_t i = 0; i < 8; ++i) {
        a0init[i] = static_cast<uint8_t>(distrib(engine));
    }

    data.insert(data.end(), a0init.begin(), a0init.end());

    ApduCommand apdu(0x90, 0xA0, 0x00, 0x01);
    ApduResponse response;

    if (!smartCard->isInited()) {
        smartCard->init();
    }
    if (!smartCard->isConnected()) {
        smartCard->connect();
    }

    if (smartCard->transmit(apdu.case4short(data, 0x00), response) != SCARD_S_SUCCESS) {
        return false;
    }

    if (!response.isSuccess()) {
        return false;
    }

    auto a0data = response.getData();
    std::vector<uint8_t> a0response(a0data.begin() + 0x06, a0data.begin() + 0x06 + 0x08);
    std::vector<uint8_t> a0hash(a0data.begin() + 0x0e, a0data.end());

    std::vector<uint8_t> plainKcl;
    plainKcl.insert(plainKcl.end(), std::begin(masterKey), std::end(masterKey));
    plainKcl.insert(plainKcl.end(), a0init.begin(), a0init.end());
    plainKcl.insert(plainKcl.end(), a0response.begin(), a0response.end());

    sha256_t kcl = SHA256::hash(plainKcl);

    std::vector<uint8_t> plainData;
    plainData.insert(plainData.end(), kcl.begin(), kcl.end());
    plainData.insert(plainData.end(), a0init.begin(), a0init.end());

    sha256_t hash = SHA256::hash(plainData);

    if (!std::equal(hash.begin(), hash.end(), a0hash.begin())) {
        return false;
    }

    static int a0_debug = 0;
    if (a0_debug < 2) {
        std::cout << "[AcasCard] Debugging Kcl derivation:" << std::endl;
        print_hex_simple_acas("  plainKcl (48 bytes)", plainKcl.data(), plainKcl.size());
        print_hex_simple_acas("  kcl (32 bytes)", kcl.data(), kcl.size());
        a0_debug++;
    }

    output = kcl;

    return true;
}

bool AcasCard::ecm(const std::vector<uint8_t>& ecm, DecryptionKey& output) {
    ApduResponse response;
    sha256_t kcl;
    uint32_t retryCount = 0;
    if (smartCard == nullptr) {
        return false;
    }

    try {
    retry:
        if (!smartCard->isInited()) {
            smartCard->init();
        }
        if (!smartCard->isConnected()) {
            smartCard->connect();
        }

        auto scope = smartCard->scopedTransaction();

        if (!getA0AuthKcl(kcl)) {
            if (retryCount > 1) {
                return false;
            }

            ++retryCount;
            goto retry;
        }

        ApduCommand apdu(0x90, 0x34, 0x00, 0x01);
        uint32_t ret = smartCard->transmit(apdu.case4short(ecm, 0x00), response);
        if (ret != SCARD_S_SUCCESS) {
            if (ret == SCARD_W_RESET_CARD || ret == SCARD_E_INVALID_HANDLE) {
                if (retryCount > 1) {
                    return false;
                }

                ++retryCount;
                goto retry;
            }

            return false;
        }

        if (!response.isSuccess()) {
            return false;
        }

        auto ecmData = response.getData();
        std::vector<uint8_t> ecmResponse(ecmData.begin() + 0x06, ecmData.end());
        std::vector<uint8_t> ecmInit(ecm.begin() + 0x04, ecm.begin() + 0x04 + 0x17);

        std::vector<uint8_t> plainData;
        plainData.insert(plainData.end(), kcl.begin(), kcl.end());
        plainData.insert(plainData.end(), ecmInit.begin(), ecmInit.end());

        sha256_t hash = SHA256::hash(plainData);

        static int ecm_debug = 0;
        if (ecm_debug < 2) {
            std::cout << "[AcasCard] Debugging CW derivation:" << std::endl;
            print_hex_simple_acas("  plainData (55 bytes)", plainData.data(), plainData.size());
            print_hex_simple_acas("  ecmResponse (32 bytes)", ecmResponse.data(), ecmResponse.size());
            print_hex_simple_acas("  finalHash (32 bytes)", hash.data(), hash.size());
            ecm_debug++;
        }

        for (size_t i = 0; i < hash.size(); i++) {
            hash[i] ^= ecmResponse[i];
        }

        std::copy(hash.begin(), hash.begin() + 0x10, output.odd.begin());
        std::copy(hash.begin() + 0x10, hash.begin() + 0x20, output.even.begin());

        return true;
    }
    catch (const std::runtime_error& e) {
        std::cerr << e.what() << std::endl;
    }

    return false;
}

void AcasCard::setSmartCard(std::unique_ptr<ISmartCard> sc) {
    smartCard = std::move(sc);
}
