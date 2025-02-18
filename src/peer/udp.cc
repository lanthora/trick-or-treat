#include "peer/udp.h"
#include "core/client.h"
#include "core/message.h"
#include "peer/info.h"
#include "peer/peer.h"
#include <algorithm>
#include <spdlog/spdlog.h>

namespace Candy {

bool UDP::isConnected() const {
    return this->state == UdpPeerState::CONNECTED;
}

bool UDP::tryToConnect() {
    if (this->state == UdpPeerState::INIT) {
        updateState(UdpPeerState::PREPARING);
        return true;
    }
    return false;
}

void UDP::updateState(UdpPeerState state) {
    this->refreshActiveTime();
    if (this->state == state) {
        return;
    }

    spdlog::debug("state: {} {} {} => {}", this->address().toString(), this->name(), stateString(), stateString(state));

    if (state == UdpPeerState::INIT || state == UdpPeerState::WAITING || state == UdpPeerState::FAILED) {
        resetState();
    }

    if (this->state == UdpPeerState::WAITING && state == UdpPeerState::INIT) {
        this->retry = std::min(this->retry * 2, RETRY_MAX);
    } else if (state == UdpPeerState::INIT || state == UdpPeerState::FAILED) {
        this->retry = RETRY_MIN;
    }

    this->state = state;
}

std::string UDP::stateString() const {
    return this->stateString(this->state);
}

std::string UDP::stateString(UdpPeerState state) const {
    switch (state) {
    case UdpPeerState::INIT:
        return "INIT";
    case UdpPeerState::PREPARING:
        return "PREPARING";
    case UdpPeerState::SYNCHRONIZING:
        return "SYNCHRONIZING";
    case UdpPeerState::CONNECTING:
        return "CONNECTING";
    case UdpPeerState::CONNECTED:
        return "CONNECTED";
    case UdpPeerState::WAITING:
        return "WAITING";
    case UdpPeerState::FAILED:
        return "FAILED";
    default:
        return "UNKNOWN";
    }
}

std::string UDP4::name() {
    return "UDP4";
}

void UDP4::updateInfo(IP4 ip, uint16_t port, bool local) {
    if (local) {
        this->local.ip = ip;
        this->local.port = port;
        return;
    }

    this->wide.ip = ip;
    this->wide.port = port;

    if (this->state == UdpPeerState::CONNECTED) {
        return;
    }

    if (this->state == UdpPeerState::SYNCHRONIZING) {
        updateState(UdpPeerState::CONNECTING);
        return;
    }

    if (this->state != UdpPeerState::CONNECTING) {
        updateState(UdpPeerState::PREPARING);
        CoreMsg::PubInfo info = {.dst = this->address(), .local = true};
        peerManager().sendPubInfo(info);
        return;
    }
}

void UDP4::handleStunResponse() {
    if (this->state != UdpPeerState::PREPARING) {
        return;
    }
    if (this->wide.ip.empty() || this->wide.port == 0) {
        updateState(UdpPeerState::SYNCHRONIZING);
    } else {
        updateState(UdpPeerState::CONNECTING);
    }
    CoreMsg::PubInfo info = {.dst = this->address()};
    peerManager().sendPubInfo(info);
}

void UDP4::tick() {
    switch (this->state) {
    case UdpPeerState::INIT:
        break;
    case UdpPeerState::PREPARING:
        if (isActiveIn(std::chrono::seconds(10))) {
            peerManager().udpStun.needed = true;
        } else {
            updateState(UdpPeerState::FAILED);
        }
        break;
    case UdpPeerState::SYNCHRONIZING:
        if (isActiveIn(std::chrono::seconds(10))) {
            sendHeartbeat();
        } else {
            updateState(UdpPeerState::FAILED);
        }
        break;
    case UdpPeerState::CONNECTING:
        if (isActiveIn(std::chrono::seconds(10))) {
            sendHeartbeat();
        } else {
            updateState(UdpPeerState::WAITING);
        }
        break;
    case UdpPeerState::CONNECTED:
        // 进行超时检测,超时后清空对端信息,否则发送心跳
        if (isActiveIn(std::chrono::seconds(3))) {
            sendHeartbeat();
            // TODO: 检测延迟
        } else {
            updateState(UdpPeerState::INIT);
            // TODO: 广播断开连接事件
        }
        break;
    case UdpPeerState::WAITING:
        if (!isActiveIn(std::chrono::seconds(this->retry))) {
            updateState(UdpPeerState::INIT);
        }
        break;
    case UdpPeerState::FAILED:
        break;
    default:
        break;
    }
}

void UDP4::sendHeartbeat() {
    PeerMsg::Heartbeat heartbeat;
    heartbeat.kind = PeerMsgKind::HEARTBEAT;
    heartbeat.ip = peerManager().getTunIp();
    heartbeat.ack = this->ack;

    auto buffer = this->info->encrypt(std::string((char *)&heartbeat, sizeof(heartbeat)));
    if (!buffer) {
        return;
    }

    using Poco::Net::SocketAddress;
    if ((this->state == UdpPeerState::CONNECTED) && (!this->real.ip.empty() && this->real.port)) {
        SocketAddress address(this->real.ip.toString(), this->real.port);
        peerManager().udp4socket.sendTo(buffer->data(), buffer->size(), address);
    }

    if ((this->state == UdpPeerState::CONNECTING) && (!this->wide.ip.empty() && this->wide.port)) {
        SocketAddress address(this->wide.ip.toString(), this->wide.port);
        peerManager().udp4socket.sendTo(buffer->data(), buffer->size(), address);
    }

    if ((this->state == UdpPeerState::PREPARING || this->state == UdpPeerState::SYNCHRONIZING ||
         this->state == UdpPeerState::CONNECTING) &&
        (!this->local.ip.empty() && this->local.port)) {
        SocketAddress address(this->local.ip.toString(), this->local.port);
        peerManager().udp4socket.sendTo(buffer->data(), buffer->size(), address);
    }
}

void UDP4::resetState() {
    this->wide.reset();
    this->local.reset();
    this->real.reset();
    this->ack = 0;
    this->delay = DELAY_LIMIT;
}

std::string UDP6::name() {
    return "UDP6";
}

void UDP6::tick() {}

} // namespace Candy
