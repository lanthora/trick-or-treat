#include "peer/udp.h"

namespace Candy {

bool UDP::isConnected() const {
    return this->state == UdpPeerState::CONNECTED;
}

bool UDP::tryToConnect() {
    if (this->state == UdpPeerState::INIT) {
        this->state = UdpPeerState::PREPARING;
        return true;
    }
    return false;
}

} // namespace Candy
