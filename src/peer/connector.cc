#include "peer/connector.h"
#include "peer/info.h"

namespace Candy {

IP4 Connector::address() {
    return this->info->addr;
}

void Connector::refreshActiveTime() {
    this->lastActiveTime = std::chrono::system_clock::now();
}

bool Connector::isActiveIn(std::chrono::system_clock::duration duration) {
    return std::chrono::system_clock::now() - lastActiveTime < duration;
}

} // namespace Candy
