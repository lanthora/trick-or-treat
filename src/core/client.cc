// SPDX-License-Identifier: MIT
#include "core/client.h"
#include "core/message.h"
#include <Poco/String.h>
#include <chrono>

namespace Candy {

Msg MsgQueue::read() {
    std::unique_lock lock(msgMutex);
    if (!msgCondition.wait_for(lock, std::chrono::seconds(1), [this] { return !msgQueue.empty(); })) {
        return Msg(MsgKind::TIMEOUT);
    }

    Msg msg = std::move(msgQueue.front());
    msgQueue.pop();
    return msg;
}

void MsgQueue::write(Msg msg) {
    {
        std::unique_lock lock(this->msgMutex);
        msgQueue.push(std::move(msg));
    }
    msgCondition.notify_one();
}

void Client::setName(const std::string &name) {
    this->tunName = name;
    tun.setName(name);
    ws.setName(name);
}

std::string Client::getName() const {
    return this->tunName;
}

IP4 Client::address() {
    return this->tun.getIP();
}

void Client::setPassword(const std::string &password) {
    ws.setPassword(password);
    peerManager.setPassword(password);
}

void Client::setWebSocket(const std::string &uri) {
    ws.setWsServerUri(uri);
}

void Client::setTunAddress(const std::string &cidr) {
    ws.setAddress(cidr);
}

void Client::setExptTunAddress(const std::string &cidr) {
    ws.setExptTunAddress(cidr);
}

void Client::setVirtualMac(const std::string &vmac) {
    ws.setVirtualMac(vmac);
}

void Client::setTransport(const std::string &transport) {
    std::vector<std::string> inner_transport;
    std::istringstream stream(transport);
    std::string item;

    while (std::getline(stream, item, ';')) {
        item = Poco::trim(item);
        if (!item.empty()) {
            inner_transport.push_back(item);
        }
    }
    peerManager.setTransport(inner_transport);
}

void Client::setStun(const std::string &stun) {
    peerManager.setStun(stun);
}

void Client::setDiscoveryInterval(int interval) {
    peerManager.setDiscoveryInterval(interval);
}

void Client::setRouteCost(int cost) {
    peerManager.setForwardCost(cost);
}

void Client::setPort(int port) {
    peerManager.setPort(port);
}

void Client::setLocalhost(std::string ip) {
    peerManager.setLocalhost(ip);
}

void Client::setMtu(int mtu) {
    tun.setMTU(mtu);
}

void Client::setTunUpdateCallback(std::function<int(const std::string &)> callback) {
    this->ws.setTunUpdateCallback(callback);
}

void Client::run() {
    this->running = true;
    ws.run(this);
    tun.run(this);
    peerManager.run(this);
}

void Client::shutdown() {
    this->running = false;
    ws.shutdown();
    tun.shutdown();
    peerManager.shutdown();
}

} // namespace Candy
