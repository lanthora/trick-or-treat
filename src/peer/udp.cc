#include "peer/udp.h"
#include "core/message.h"
#include "peer/info.h"
#include "peer/peer.h"
#include "spdlog/spdlog.h"

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
        // TODO: sendLocalConnMessage()
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
    this->info->peer->sendPubInfo(info);
}

void UDP4::tick() {
    switch (this->state) {
    case UdpPeerState::INIT:
        break;
    case UdpPeerState::PREPARING:
        if (isActiveIn(std::chrono::seconds(10))) {
            this->info->peer->udpStun.needed = true;
        } else {
            updateState(UdpPeerState::FAILED);
        }
        break;
    case UdpPeerState::SYNCHRONIZING:
        if (isActiveIn(std::chrono::seconds(10))) {
            // TODO: 发送心跳
        } else {
            updateState(UdpPeerState::FAILED);
        }
        break;
    case UdpPeerState::CONNECTING:
        if (isActiveIn(std::chrono::seconds(10))) {
            // TODO: 发送心跳
        } else {
            updateState(UdpPeerState::WAITING);
        }
        break;
    case UdpPeerState::CONNECTED:
        // 进行超时检测,超时后清空对端信息,否则发送心跳
        if (isActiveIn(std::chrono::seconds(3))) {
            // TODO: 发送心跳
            // TODO: 检测延迟
        } else {
            updateState(UdpPeerState::INIT);
            // TODO: 广播断开连接事件
        }
        break;
    case UdpPeerState::WAITING:
        // TODO: 根据指数退避算法判定是否需要回到 INIT 状态
        updateState(UdpPeerState::FAILED);
        break;
    case UdpPeerState::FAILED:
        break;
    default:
        break;
    }
}

std::string UDP6::name() {
    return "UDP6";
}

void UDP6::tick() {}

} // namespace Candy
