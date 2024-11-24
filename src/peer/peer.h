// SPDX-License-Identifier: MIT
#ifndef CANDY_PEER_PEER_H
#define CANDY_PEER_PEER_H

#include "core/message.h"
#include "core/net.h"
#include "peer/info.h"
#include <Poco/Net/DatagramSocket.h>
#include <Poco/Net/PollSet.h>
#include <Poco/Net/ServerSocket.h>
#include <Poco/Net/StreamSocket.h>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>

namespace Candy {

class Client;

class Peer {
public:
    int setPassword(const std::string &password);
    int setStun(const std::string &stun);
    int setDiscoveryInterval(int interval);
    int setForwardCost(int cost);
    int setPort(int port);
    int setLocalhost(const std::string &ip);

    // TODO: 设置不同 P2P 类型的优先级，不设置任何 P2P 类型表示禁用 P2P

    int run(Client *client);
    int shutdown();

private:
    // 处理来自消息队列的数据
    void handlePeerQueue();
    void handlePacket(Msg msg);
    void handleTryP2P(Msg msg);

    std::thread msgThread;

    // 处理 PACKET 报文,并判断目标是否可达
    int sendTo(IP4 dst, const Msg &msg);

private:
    std::shared_mutex ipPeerMutex;
    std::unordered_map<IP4, PeerInfo> ipPeerMap;

    std::shared_mutex rtTableMutex;
    std::unordered_map<IP4, IP4> rtTableMap;

private:
    int initSocket();
    // 默认监听端口, 如果不配置, 各个模块自行随机端口号
    uint16_t listenPort = 0;

    // 维护用于监听的 socket, 读操作统一在外部完成, 写操作给到 PeerInfo
    Poco::Net::DatagramSocket udp4socket, udp6socket;
    Poco::Net::ServerSocket tcp4socket, tcp6socket;
    Poco::Net::PollSet pollSet;

private:
    Client *client;
};

} // namespace Candy

#endif
