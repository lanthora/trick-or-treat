// SPDX-License-Identifier: MIT
#include "peer/peer.h"
#include "core/client.h"
#include "core/message.h"
#include "core/net.h"
#include "peer/message.h"
#include "utility/time.h"
#include <Poco/Net/NetException.h>
#include <Poco/Timespan.h>
#include <Poco/URI.h>
#include <shared_mutex>
#include <spdlog/fmt/bin_to_hex.h>
#include <spdlog/spdlog.h>

namespace Candy {

int Peer::setPassword(const std::string &password) {
    this->password = password;
    return 0;
}

int Peer::setStun(const std::string &stun) {
    this->udpStun.uri = stun;
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

int Peer::setTransport(const std::vector<std::string> &transport) {
    this->transport = transport;
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
    if (this->pollThread.joinable()) {
        this->pollThread.join();
    }
    return 0;
}

std::string Peer::getPassword() {
    return this->password;
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
    case MsgKind::PUBINFO:
        handlePubInfo(std::move(msg));
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

int Peer::sendPubInfo(CoreMsg::PubInfo info) {
    info.src = this->client->address();
    if (!info.v6 && !info.tcp && !info.local) {
        info.ip = this->udpStun.ip;
        info.port = this->udpStun.port;
    }
    this->client->wsMsgQueue.write(Msg(MsgKind::PUBINFO, std::string((char *)(&info), sizeof(info))));
    return 0;
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
        this->ipPeerMutex.unlock_shared();
        {
            std::unique_lock lock(this->ipPeerMutex);
            this->ipPeerMap.emplace(std::piecewise_construct, std::forward_as_tuple(src), std::forward_as_tuple(src, this));
        }
        this->ipPeerMutex.lock_shared();
        it = this->ipPeerMap.find(src);
    }

    if (it == this->ipPeerMap.end()) {
        spdlog::warn("can not find peer: {}", src.toString());
        return;
    }

    it->second.tryConnecct();
}

void Peer::handlePubInfo(Msg msg) {
    CoreMsg::PubInfo *info = (CoreMsg::PubInfo *)(msg.data.data());

    if (info->src == this->client->address() || info->dst != this->client->address()) {
        spdlog::warn("invalid public info: src=[{}] dst=[{}]", info->src.toString(), info->dst.toString());
        return;
    }

    std::shared_lock ipPeerLock(this->ipPeerMutex);
    auto it = this->ipPeerMap.find(info->src);
    if (it == this->ipPeerMap.end()) {
        spdlog::warn("can not find src peer: {}", info->src.toString());
        return;
    }

    if (!info->v6 && !info->tcp && !info->local) {
        it->second.handleUdp4Conn(info->ip, info->port);
    }
}

void Peer::tick() {
    {
        std::shared_lock ipPeerLock(this->ipPeerMutex);
        for (auto &[ip, peer] : this->ipPeerMap) {
            peer.tick();
        }
    }

    if (this->udpStun.needed) {
        sendUdpStunRequest();
        this->udpStun.needed = false;
    }
}

int Peer::initSocket() {
    using Poco::Net::AddressFamily;
    using Poco::Net::PollSet;
    using Poco::Net::SocketAddress;

    try {
        this->udp4socket.bind(SocketAddress(AddressFamily::IPv4, this->listenPort), true);
        this->udp6socket.bind6(SocketAddress(AddressFamily::IPv6, this->listenPort), true, true, true);
        this->tcp4socket.bind(SocketAddress(AddressFamily::IPv4, this->listenPort), true);
        this->tcp6socket.bind6(SocketAddress(AddressFamily::IPv6, this->listenPort), true, true);

        this->tcp4socket.listen();
        this->tcp6socket.listen();

        spdlog::info("ipv4 listen port: udp=[{}] tcp=[{}]", this->udp4socket.address().port(), this->tcp4socket.address().port());
        spdlog::info("ipv6 listen port: udp=[{}] tcp=[{}]", this->udp6socket.address().port(), this->tcp6socket.address().port());

        this->pollSet.add(this->udp4socket, PollSet::POLL_READ);
        this->pollSet.add(this->udp6socket, PollSet::POLL_READ);
        this->pollSet.add(this->tcp4socket, PollSet::POLL_READ);
        this->pollSet.add(this->tcp6socket, PollSet::POLL_READ);
    } catch (Poco::Net::NetException &e) {
        spdlog::critical("peer init socket failed: {}: {}", e.what(), e.message());
        return -1;
    }

    this->pollThread = std::thread([&]() {
        while (this->client->running) {
            poll();
        }
    });
    return 0;
}

void Peer::sendUdpStunRequest() {
    try {
        Poco::URI uri(this->udpStun.uri);
        if (!uri.getPort()) {
            uri.setPort(3478);
        }
        StunRequest request;
        this->udpStun.address = Poco::Net::SocketAddress(uri.getHost(), uri.getPort());
        if (this->udp4socket.sendTo(&request, sizeof(request), this->udpStun.address) != sizeof(request)) {
            spdlog::warn("the stun request was not completely sent");
        }
    } catch (std::exception &e) {
        spdlog::debug("send stun request failed: {}", e.what());
    }
}

void Peer::handleUdpStunResponse(const std::string &buffer) {
    if (buffer.length() < sizeof(StunResponse)) {
        spdlog::debug("invalid stun response length: {}", buffer.length());
        return;
    }
    StunResponse *response = (StunResponse *)buffer.c_str();
    if (ntoh(response->type) != 0x0101) {
        spdlog::debug("invalid stun reponse type: {}", ntoh(response->type));
        return;
    }

    int pos = 0;
    uint32_t ip = 0;
    uint16_t port = 0;
    uint8_t *attr = response->attr;
    while (pos < ntoh(response->length)) {
        // mapped address
        if (ntoh(*(uint16_t *)(attr + pos)) == 0x0001) {
            pos += 6; // 跳过 2 字节类型, 2 字节长度, 1 字节保留, 1 字节IP版本号,指向端口号
            port = ntoh(*(uint16_t *)(attr + pos));
            pos += 2; // 跳过2字节端口号,指向地址
            ip = *(uint32_t *)(attr + pos);
            break;
        }
        // xor mapped address
        if (ntoh(*(uint16_t *)(attr + pos)) == 0x0020) {
            pos += 6; // 跳过 2 字节类型, 2 字节长度, 1 字节保留, 1 字节IP版本号,指向端口号
            port = ntoh(*(uint16_t *)(attr + pos)) ^ 0x2112;
            pos += 2; // 跳过2字节端口号,指向地址
            ip = (*(uint32_t *)(attr + pos)) ^ hton(0x2112a442);
            break;
        }
        // 跳过 2 字节类型,指向属性长度
        pos += 2;
        // 跳过 2 字节长度和用该属性其他内容
        pos += 2 + ntoh(*(uint16_t *)(attr + pos));
    }
    if (!ip || !port) {
        spdlog::warn("stun response parse failed: {:n}", spdlog::to_hex(buffer));
        return;
    }

    memcpy(&this->udpStun.ip, &ip, sizeof(this->udpStun.ip));
    this->udpStun.port = port;

    // 收到 STUN 响应后,向所有 PREPARING 状态的对端发送自己的公网信息,如果当前持有对端公网信息,就将状态调整为 CONNECTING,
    // 否则调整为 SYNCHRONIZING
    std::shared_lock lock(this->ipPeerMutex);
    for (auto &[tun, peer] : this->ipPeerMap) {
        peer.handleUdpStunResponse();
    }

    return;
}

void Peer::poll() {
    using Poco::Net::PollSet;
    using Poco::Net::Socket;
    using Poco::Net::SocketAddress;

    PollSet::SocketModeMap socketModeMap = this->pollSet.poll(Poco::Timespan(1, 0));
    for (auto &pair : socketModeMap) {
        if (pair.second & PollSet::POLL_READ) {
            if (pair.first == tcp4socket) {
                Socket clientSocket = tcp4socket.acceptConnection();
                pollSet.add(clientSocket, PollSet::POLL_READ);
                continue;
            }
            if (pair.first == tcp6socket) {
                Socket clientSocket = tcp6socket.acceptConnection();
                pollSet.add(clientSocket, PollSet::POLL_READ);
                continue;
            }
            if (pair.first == udp4socket) {
                std::string buffer(1500, 0);
                SocketAddress address;
                auto size = udp4socket.receiveFrom(buffer.data(), buffer.size(), address);
                buffer.resize(size);
                if (this->udpStun.address == address) {
                    handleUdpStunResponse(buffer);
                } else {
                    auto plaintext = decrypt(buffer);
                    if (plaintext) {
                        spdlog::info("udp4socket received message: {}", address.toString());
                    }
                }
                continue;
            }
            if (pair.first == udp6socket) {
                continue;
            }
        }
    }
}

std::optional<std::string> Peer::decrypt(const std::string &ciphertext) {
    // TODO: 实现解密
    return std::nullopt;
}

std::vector<std::string> Peer::getTransport() {
    return this->transport;
}

Client *Peer::getClient() {
    return this->client;
}

} // namespace Candy
