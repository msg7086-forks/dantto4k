#include "acasHandler.h"
#include "config.h"
#include "mmtp.h"
#include "aes.h"
#include <iostream>
#include <iomanip>

static void print_hex_simple(const std::string& label, const uint8_t* data, size_t len) {
    std::cout << label << ": ";
    for (size_t i = 0; i < len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    std::cout << std::dec << std::endl;
}

AcasHandler::AcasHandler() {
    acasCard = std::make_unique<AcasCard>();
    workerThread = std::thread(&AcasHandler::worker, this);
    hasAESNI = AESCtrCipher::hasAESNI();
}

AcasHandler::~AcasHandler() {
    {
        std::lock_guard<std::mutex> lock(queueMutex);
        running = false;
    }

    queueCv.notify_all();
    if (workerThread.joinable()) {
        workerThread.join();
    }
}

bool AcasHandler::onEcm(const std::vector<uint8_t>& ecm) {
    if (lastEcm == ecm) {
        return true;
    }
    lastEcm = ecm;

    {
        std::lock_guard<std::mutex> lock(queueMutex);
        queue.push(ecm);
    }
    queueCv.notify_one();
    ecmReady = true;

    return true;
}

bool AcasHandler::decrypt(MmtTlv::Mmtp& mmtp) {
    auto key = getDecryptionKey(mmtp.extensionHeaderScrambling->encryptionFlag);
    if (!key) {
        return false;
    }

    std::array<uint8_t, 16> iv{};
    uint16_t packetIdBe = MmtTlv::Common::swapEndian16(mmtp.packetId);
    uint32_t packetSequenceNumberBe = MmtTlv::Common::swapEndian32(mmtp.packetSequenceNumber);
    memcpy(iv.data(), &packetIdBe, 2);
    memcpy(iv.data() + 2, &packetSequenceNumberBe, 4);

    static int decrypt_count = 0;
    if (decrypt_count < 10) {
        std::cout << "[Dantto] Decrypting PID=0x" << std::hex << mmtp.packetId << " Seq=" << mmtp.packetSequenceNumber << std::dec << " Len=" << (mmtp.payload.size() - 8) << std::endl;
        print_hex_simple("  Key", (*key).data(), 16);
        print_hex_simple("  IV ", iv.data(), 16);
        print_hex_simple("  Src", mmtp.payload.data() + 8, std::min((size_t)16, mmtp.payload.size() - 8));
    }

    if (hasAESNI) { [[likely]]
        if (lastKey != *key) { [[unlikely]]
            aes.setKey(*key);
            lastKey = *key;
        }
        aes.setIv(iv);
        aes.decrypt(mmtp.payload.data() + 8, static_cast<int>(mmtp.payload.size() - 8), mmtp.payload.data() + 8);
    }
    else {
        struct AES_ctx ctx;
        AES_init_ctx_iv(&ctx, (*key).data(), iv.data());
        AES_CTR_xcrypt_buffer(&ctx, mmtp.payload.data() + 8, static_cast<int>(mmtp.payload.size() - 8));
    }

    if (decrypt_count < 10) {
        print_hex_simple("  Dst", mmtp.payload.data() + 8, std::min((size_t)16, mmtp.payload.size() - 8));
        decrypt_count++;
    }

    return true;
}

void AcasHandler::setSmartCard(std::unique_ptr<ISmartCard> sc) {
    acasCard->setSmartCard(std::move(sc));
}

std::optional<std::array<uint8_t, 16>> AcasHandler::getDecryptionKey(MmtTlv::EncryptionFlag keyType) {
    if (!ecmReady) {
        return std::nullopt;
    }

    if (lastPayloadKeyType != keyType) {
        std::unique_lock<std::mutex> lock(queueMutex);
        bool ready = queueCv.wait_for(lock, std::chrono::seconds(10), [&]() {
            return queue.empty();
            });
        if (!ready) {
            // timeout
            return std::nullopt;
        }
    }

    lastPayloadKeyType = keyType;

    {
        std::lock_guard<std::mutex> lock(keyMutex);
        if (keyType == MmtTlv::EncryptionFlag::EVEN) {
            return key.even;
        }
        else {
            return key.odd;
        }
    }
}

void AcasHandler::worker() {
    while (true) {
        std::vector<uint8_t> ecmData;
        {
            std::unique_lock<std::mutex> lock(queueMutex);
            queueCv.wait(lock, [&]() {
                return !queue.empty() || !running;
                });

            if (!running) {
                break;
            }

            ecmData = queue.front();
        }

        AcasCard::DecryptionKey k;
        if (acasCard->ecm(ecmData, k)) {
            std::lock_guard<std::mutex> lock(keyMutex);
            key = k;
        }

        {
            std::lock_guard<std::mutex> lock(queueMutex);
            queue.pop();
        }
        queueCv.notify_all();
    }
}
