// SPDX-License-Identifier: MIT
#include "peer/peer.h"
#include "core/client.h"
#include "core/message.h"
#include "core/net.h"
#include "peer/message.h"
#include "utility/time.h"
#include <Poco/Net/NetException.h>
#include <shared_mutex>
#include <spdlog/spdlog.h>

namespace Candy {

int Peer::setPassword(const std::string &password) {
    return 0;
}

int Peer::setStun(const std::string &stun) {
    return 0;
}

int Peer::setDiscoveryInterval(int interval) {
    return 0;
}

int Peer::setForwardCost(int cost) {
    return 0;
}

int Peer::setPort(int port) {
    if (port > 0 && port <= UINT16_MAX) {
        this->listenPort = port;
    }
    return 0;
}

int Peer::setLocalhost(const std::string &ip) {
    return 0;
}

int Peer::run(Client *client) {
    this->client = client;

    if (this->initSocket()) {
        Candy::shutdown(this->client);
        return -1;
    }

    this->msgThread = std::thread([&] {
        while (this->client->running) {
            handlePeerQueue();
        }
    });
    this->tickThread = std::thread([&] {
        while (this->client->running) {
            // 执行耗时操作前设置唤醒时间
            auto wake_time = std::chrono::system_clock::now() + std::chrono::seconds(1);
            // 操作时间不应该超过总休眠时间
            tick();
            // 根据先前设定时间唤醒进程,能够确保唤醒时间不受 tick() 执行时间影响
            std::this_thread::sleep_until(wake_time);
        }
    });

    return 0;
}

int Peer::shutdown() {
    if (this->msgThread.joinable()) {
        this->msgThread.join();
    }
    if (this->tickThread.joinable()) {
        this->tickThread.join();
    }
    return 0;
}

void Peer::handlePeerQueue() {
    Msg msg = this->client->peerMsgQueue.read();
    switch (msg.kind) {
    case MsgKind::TIMEOUT:
        break;
    case MsgKind::PACKET:
        handlePacket(std::move(msg));
        break;
    case MsgKind::TRYP2P:
        handleTryP2P(std::move(msg));
        break;
    default:
        spdlog::warn("unexcepted peer message type: {}", static_cast<int>(msg.kind));
        break;
    }
}

int Peer::sendTo(IP4 dst, const Msg &msg) {
    // 这两个锁同时使用时先给 ipPeerMap 加锁,避免死锁
    std::shared_lock ipPeerLock(this->ipPeerMutex);
    std::shared_lock rtTableLock(this->rtTableMutex);

    auto rt = this->rtTableMap.find(dst);
    if (rt == this->rtTableMap.end()) {
        return -1;
    }
    auto it = this->ipPeerMap.find(rt->second);
    if (it == this->ipPeerMap.end()) {
        return -1;
    }
    auto &info = it->second;
    if (!info.isConnected()) {
        return -1;
    }
    std::string data;
    data.push_back(PeerMsgKind::FORWARD);
    data += msg.data;
    return info.send(data);
}

void Peer::handlePacket(Msg msg) {
    IP4Header *header = (IP4Header *)msg.data.data();
    // 尝试 P2P 转发流量
    if (!sendTo(header->daddr, msg)) {
        return;
    }
    // 无法通过 P2P 转发流量,交给 WS 模块通过服务端转发
    this->client->wsMsgQueue.write(std::move(msg));
}

void Peer::handleTryP2P(Msg msg) {
    IP4 src(msg.data);

    std::shared_lock ipPeerLock(this->ipPeerMutex);
    auto it = this->ipPeerMap.find(src);
    if (it == this->ipPeerMap.end()) {
        // 释放读锁临时加写锁修改 ipPeerMap
        this->ipPeerMutex.unlock_shared();
        {
            // 单独的作用域内加锁，否则造成死锁
            std::unique_lock lock(this->ipPeerMutex);
            this->ipPeerMap.emplace(src, std::move(PeerInfo(src)));
        }
        this->ipPeerMutex.lock_shared();
        // 释放写锁重新获取读锁的过程中迭代器可能失效,需要重新获取
        it = this->ipPeerMap.find(src);
    }

    if (it == this->ipPeerMap.end()) {
        spdlog::warn("can not find peer: {}", src.toString());
        return;
    }

    it->second.tryConnecct();
}

void Peer::tick() {
    spdlog::debug("tick: {}", getCurrentTimeWithMillis());

    // TODO: 替换成真实操作,这里模拟 500 ms 的耗时操作
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
}

int Peer::initSocket() {
    using Poco::Net::AddressFamily;
    using Poco::Net::SocketAddress;
    using Poco::Net::PollSet::POLL_READ;

    try {
        this->udp4socket.bind(SocketAddress(AddressFamily::IPv4, this->listenPort), true);
        this->udp6socket.bind6(SocketAddress(AddressFamily::IPv6, this->listenPort), true, true, true);
        this->tcp4socket.bind(SocketAddress(AddressFamily::IPv4, this->listenPort), true);
        this->tcp6socket.bind6(SocketAddress(AddressFamily::IPv6, this->listenPort), true, true);

        this->tcp4socket.listen();
        this->tcp6socket.listen();

        spdlog::info("ipv4 listen port: udp=[{}] tcp=[{}]", this->udp4socket.address().port(), this->tcp4socket.address().port());
        spdlog::info("ipv6 listen port: udp=[{}] tcp=[{}]", this->udp6socket.address().port(), this->tcp6socket.address().port());

        this->pollSet.add(this->udp4socket, POLL_READ);
        this->pollSet.add(this->udp6socket, POLL_READ);
        this->pollSet.add(this->tcp4socket, POLL_READ);
        this->pollSet.add(this->tcp6socket, POLL_READ);

        return 0;
    } catch (Poco::Net::NetException &e) {
        spdlog::critical("peer init socket failed: {}: {}", e.what(), e.message());
        return -1;
    }
}

} // namespace Candy
