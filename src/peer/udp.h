// SPDX-License-Identifier: MIT
#ifndef CANDY_PEER_UDP_H
#define CANDY_PEER_UDP_H

#include "peer/connector.h"

namespace Candy {

enum class UdpPeerState {
    INIT,          // 默认状态
    PREPARING,     // 开始尝试建立对等连接
    SYNCHRONIZING, // 本机已经将建立对等连接所需的信息发送给了对端,但还没有收到对方的信息
    CONNECTING,    // 已经收到了对端的对等连接信息,且将自己的信息发送给了对方
    CONNECTED,     // 连接成功,持续发送心跳
    WAITING,       // 连接失败,一段时间后重新进入 INIT
    FAILED,        // 连接失败,且不会再主动进入其他状态,除非收到对端的对等连接信息
};

class UDP : public Connector {
public:
    UDP(PeerInfo *info) : Connector(info) {}

    bool isConnected() const;
    bool tryToConnect();

protected:
    UdpPeerState state = UdpPeerState::INIT;
    std::string stateString() const;
    std::string stateString(UdpPeerState state) const;
    void updateState(UdpPeerState state);
};

class UDP4 : public UDP {
public:
    UDP4(PeerInfo *info) : UDP(info) {}
    std::string name();
    void tick();
};

class UDP6 : public UDP {
public:
    UDP6(PeerInfo *info) : UDP(info) {}
    std::string name();
    void tick();
};

} // namespace Candy

#endif
