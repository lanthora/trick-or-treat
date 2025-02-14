#include "peer/info.h"
#include "peer/peer.h"
#include <bit>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

namespace {

constexpr std::size_t AES_256_GCM_IV_LEN = 12;
constexpr std::size_t AES_256_GCM_TAG_LEN = 16;
constexpr std::size_t AES_256_GCM_KEY_LEN = 32;

} // namespace

namespace Candy {

PeerInfo::PeerInfo(const IP4 &addr, Peer *peer) : peer(peer), addr(addr) {
    {
        std::string data;
        data.append(this->peer->getPassword());
        auto leaddr = std::endian::native == std::endian::little ? uint32_t(this->addr) : std::byteswap(uint32_t(this->addr));
        data.append((char *)&leaddr, sizeof(leaddr));

        this->key.resize(SHA256_DIGEST_LENGTH);
        SHA256((unsigned char *)data.data(), data.size(), (unsigned char *)this->key.data());

        this->encryptCtx = std::shared_ptr<EVP_CIPHER_CTX>(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    }

    for (const std::string &transport : peer->getTransport()) {
        if (transport == "UDP4") {
            this->connectors[transport] = std::make_shared<UDP4>(this);
            continue;
        }
        if (transport == "UDP6") {
            this->connectors[transport] = std::make_shared<UDP6>(this);
            continue;
        }
        if (transport == "TCP4") {
            this->connectors[transport] = std::make_shared<TCP4>(this);
            continue;
        }
        if (transport == "TCP6") {
            this->connectors[transport] = std::make_shared<TCP6>(this);
            continue;
        }
        spdlog::warn("unknown transport: {}", transport);
    }
}

PeerInfo::~PeerInfo() {}

bool PeerInfo::isConnected() const {
    for (const std::string &transport : peer->getTransport()) {
        auto it = this->connectors.find(transport);
        if (it != this->connectors.end()) {
            if (it->second->isConnected()) {
                return true;
            }
        }
    }
    return false;
}

void PeerInfo::tryConnecct() {
    for (const std::string &transport : peer->getTransport()) {
        auto it = this->connectors.find(transport);
        if (it != this->connectors.end()) {
            it->second->tryToConnect();
        }
    }
}

void PeerInfo::tick() {
    for (const std::string &transport : peer->getTransport()) {
        auto it = this->connectors.find(transport);
        if (it != this->connectors.end()) {
            it->second->tick();
        }
    }
}

int PeerInfo::send(const std::string &data) {
    return -1;
}

void PeerInfo::handleUdp4Conn(IP4 ip, uint16_t port) {
    auto it = this->connectors.find("UDP4");
    if (it == this->connectors.end()) {
        return;
    }

    std::shared_ptr<UDP4> conn = std::dynamic_pointer_cast<UDP4>(it->second);
    conn->updateInfo(ip, port);
}

void PeerInfo::handleUdpStunResponse() {
    auto it = this->connectors.find("UDP4");
    if (it == this->connectors.end()) {
        return;
    }

    std::shared_ptr<UDP4> conn = std::dynamic_pointer_cast<UDP4>(it->second);
    conn->handleStunResponse();
}

Peer *PeerInfo::getPeer() {
    return this->peer;
}

IP4 PeerInfo::getAddr() {
    return this->addr;
}

std::optional<std::string> PeerInfo::encrypt(const std::string &plaintext) {
    int len = 0;
    int ciphertextLen = 0;
    unsigned char ciphertext[1500] = {0};
    unsigned char iv[AES_256_GCM_IV_LEN] = {0};
    unsigned char tag[AES_256_GCM_TAG_LEN] = {0};

    // Generate an initialization vector and set the first two bits to the ciphertext length
    {
        if (!RAND_bytes(iv, AES_256_GCM_IV_LEN)) {
            spdlog::debug("generate random iv failed");
            return std::nullopt;
        }
        uint16_t size = (plaintext.size() + AES_256_GCM_IV_LEN + AES_256_GCM_TAG_LEN);
        iv[0] = size & 0xFF00;
        iv[1] = size & 0x00FF;
    }

    auto ctx = this->encryptCtx.get();

    if (!EVP_CIPHER_CTX_reset(ctx)) {
        spdlog::debug("reset cipher context failed");
        return std::nullopt;
    }
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, (unsigned char *)key.data(), iv)) {
        spdlog::debug("initialize cipher context failed");
        return std::nullopt;
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_256_GCM_IV_LEN, NULL)) {
        spdlog::debug("set iv length failed");
        return std::nullopt;
    }
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char *)plaintext.data(), plaintext.size())) {
        spdlog::debug("encrypt update failed");
        return std::nullopt;
    }
    ciphertextLen = len;
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        spdlog::debug("encrypt final failed");
        return std::nullopt;
    }
    ciphertextLen += len;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_256_GCM_TAG_LEN, tag)) {
        spdlog::debug("get tag failed");
        return std::nullopt;
    }

    std::string result;
    result.append((char *)iv, AES_256_GCM_IV_LEN);
    result.append((char *)tag, AES_256_GCM_TAG_LEN);
    result.append((char *)ciphertext, ciphertextLen);
    return result;
}

} // namespace Candy
