#include "peer/tcp.h"
#include "peer/info.h"
#include "spdlog/spdlog.h"

namespace Candy {

bool TCP::isConnected() const {
    // TODO: 判断 TCP 是否是连接状态
    return false;
}

bool TCP::tryToConnect() {
    // TODO: 尝试 TCP P2P
    return false;
}

std::string TCP4::name() {
    return "TCP6";
}

void TCP4::tick() {}

std::string TCP6::name() {
    return "TCP6";
}

void TCP6::tick() {}

} // namespace Candy
