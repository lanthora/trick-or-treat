#include "peer/info.h"
#include "peer/peer.h"

namespace {

constexpr std::size_t AES_256_GCM_IV_LEN = 12;
constexpr std::size_t AES_256_GCM_TAG_LEN = 16;
constexpr std::size_t AES_256_GCM_KEY_LEN = 32;

} // namespace

namespace Candy {

PeerInfo::PeerInfo(const IP4 &addr, const Peer *peer) : peer(peer), addr(addr) {
    this->encryptCtx = std::shared_ptr<EVP_CIPHER_CTX>(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

    for (const std::string &transport : peer->transport) {
        if (transport == "UDP4") {
            this->connectors[transport] = std::make_shared<UDP4>();
        } else if (transport == "UDP6") {
            this->connectors[transport] = std::make_shared<UDP6>();
        } else if (transport == "TCP4") {
            this->connectors[transport] = std::make_shared<TCP4>();
        } else if (transport == "TCP6") {
            this->connectors[transport] = std::make_shared<TCP6>();
        } else {
            spdlog::warn("unknown transport: {}", transport);
        }
    }
}

PeerInfo::~PeerInfo() {}

bool PeerInfo::isConnected() const {
    for (const std::string &transport : peer->transport) {
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
    for (const std::string &transport : peer->transport) {
        auto it = this->connectors.find(transport);
        if (it != this->connectors.end()) {
            if (it->second->tryToConnect()) {
                spdlog::debug("try to connect: protocol=[{}] peer={}", transport, this->addr.toString());
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
