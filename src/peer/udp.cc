#include "peer/udp.h"
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

    spdlog::debug("state: {} {} {} => {}", this->address(), this->name(), stateString(), stateString(state));
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
        return "Unknown";
    }
}

std::string UDP4::name() {
    return "UDP4";
}

void UDP4::tick() {
    switch (this->state) {
    case UdpPeerState::INIT:
        break;
    case UdpPeerState::PREPARING:
        if (isActiveIn(std::chrono::seconds(10))) {
            this->info->peer->udpStunNeeded = true;
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
