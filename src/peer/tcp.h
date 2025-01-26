// SPDX-License-Identifier: MIT
#ifndef CANDY_PEER_TCP_H
#define CANDY_PEER_TCP_H

#include "peer/connector.h"

namespace Candy {

class TCP : public Connector {
public:
    TCP(PeerInfo *info) : Connector(info) {}

    bool isConnected() const;
    bool tryToConnect();
};

class TCP4 : public TCP {
public:
    TCP4(PeerInfo *info) : TCP(info) {}
    std::string name();
    void tick();
};

class TCP6 : public TCP {
public:
    TCP6(PeerInfo *info) : TCP(info) {}
    std::string name();
    void tick();
};

} // namespace Candy

#endif
