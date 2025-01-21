#include "peer/info.h"

namespace {

constexpr std::size_t AES_256_GCM_IV_LEN = 12;
constexpr std::size_t AES_256_GCM_TAG_LEN = 16;
constexpr std::size_t AES_256_GCM_KEY_LEN = 32;

} // namespace

namespace Candy {

PeerInfo::PeerInfo(const IP4 &addr) {
    this->addr = addr;
    this->encryptCtx = std::shared_ptr<EVP_CIPHER_CTX>(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

    this->connectors["UDP4"] = std::make_shared<UDP4>();
    this->connectors["UDP6"] = std::make_shared<UDP6>();
    this->connectors["TCP4"] = std::make_shared<TCP4>();
    this->connectors["TCP6"] = std::make_shared<TCP6>();
}

PeerInfo::~PeerInfo() {}

bool PeerInfo::isConnected() const {
    for (const auto &t : std::vector<std::string>{"UDP4"}) {
        auto it = this->connectors.find(t);
        if (it != this->connectors.end()) {
            if (it->second->isConnected()) {
                return true;
            }
        }
    }
    return false;
}

void PeerInfo::tryConnecct() {
    for (const auto &t : std::vector<std::string>{"UDP4"}) {
        auto it = this->connectors.find(t);
        if (it != this->connectors.end()) {
            if (it->second->tryToConnect()) {
                spdlog::debug("try to connect: protocol=[{}] peer={}", t, this->addr.toString());
            }
        }
    }
}

int PeerInfo::send(const std::string &data) {
    return -1;
}

std::string PeerInfo::encrypt(const std::string &plaintext) {
    return "";
}

} // namespace Candy
