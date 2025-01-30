// SPDX-License-Identifier: MIT
#ifndef CANDY_PEER_PEER_H
#define CANDY_PEER_PEER_H

#include "core/message.h"
#include "core/net.h"
#include "peer/info.h"
#include "peer/message.h"
#include <Poco/Net/DatagramSocket.h>
#include <Poco/Net/PollSet.h>
#include <Poco/Net/ServerSocket.h>
#include <Poco/Net/StreamSocket.h>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace Candy {

class Client;

struct Stun {
    std::string uri;
    Poco::Net::SocketAddress address;
    bool needed = false;
};

class Peer {
public:
    int setPassword(const std::string &password);
    int setStun(const std::string &stun);
    int setDiscoveryInterval(int interval);
    int setForwardCost(int cost);
    int setPort(int port);
    int setLocalhost(const std::string &ip);
    int setTransport(const std::vector<std::string> &transport);

    int run(Client *client);
    int shutdown();

private:
    std::string password;

private:
    // 处理来自消息队列的数据
    void handlePeerQueue();
    void handlePacket(Msg msg);
    void handleTryP2P(Msg msg);
    void handlePubInfo(Msg msg);

    std::thread msgThread;

    // 处理 PACKET 报文,并判断目标是否可达
    int sendTo(IP4 dst, const Msg &msg);

private:
    void tick();
    std::thread tickThread;

private:
    std::shared_mutex ipPeerMutex;
    std::unordered_map<IP4, PeerInfo> ipPeerMap;

    std::shared_mutex rtTableMutex;
    std::unordered_map<IP4, IP4> rtTableMap;

private:
    int initSocket();
    void sendUdpStunRequest();

    std::optional<std::string> decrypt(const std::string &ciphertext);

    // 默认监听端口,如果不配置,随机监听
    uint16_t listenPort = 0;

    // 维护用于监听的 socket, 读操作统一在外部完成, 写操作给到 PeerInfo
    Poco::Net::DatagramSocket udp4socket, udp6socket;
    Poco::Net::ServerSocket tcp4socket, tcp6socket;
    Poco::Net::PollSet pollSet;

    std::vector<std::string> transport;

    std::thread pollThread;

    Stun udpStun;

private:
    Client *client;

    friend class PeerInfo;
    friend class UDP4;
    friend class UDP6;
};

} // namespace Candy

#endif
