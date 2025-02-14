// SPDX-License-Identifier: MIT
#ifndef CANDY_PEER_INFO_H
#define CANDY_PEER_INFO_H

#include "core/net.h"
#include "peer/tcp.h"
#include "peer/udp.h"
#include <cstdint>
#include <map>
#include <memory>
#include <openssl/evp.h>
#include <optional>
#include <string>

namespace Candy {

class Peer;

class PeerInfo {
public:
    PeerInfo(const IP4 &addr, Peer *peer);
    ~PeerInfo();

public:
    bool isConnected() const;
    void tryConnecct();
    void tick();
    int send(const std::string &data);

    void handleUdp4Conn(IP4 ip, uint16_t port);
    void handleUdpStunResponse();

    Peer *getPeer();
    IP4 getAddr();

private:
    // 对端虚拟地址
    IP4 addr;
    Peer *peer;

public:
    // 所有对等连接使用统一的加密方式, 为了解决 TCP 无法分包的问题,
    // 加密使用的 IV 前两个字节用于表示报文长度, 由于 MTU 的限制, 两个字节大小足够
    std::optional<std::string> encrypt(const std::string &plaintext);

private:
    std::shared_ptr<EVP_CIPHER_CTX> encryptCtx;
    std::string key;

private:
    std::map<std::string, std::shared_ptr<Connector>> connectors;
};

} // namespace Candy

#endif
