#include "peer/udp.h"

namespace Candy {

bool UDP::isConnected() const {
    return this->state == UdpPeerState::CONNECTED;
}

} // namespace Candy
