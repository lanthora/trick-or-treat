// SPDX-License-Identifier: MIT
#ifndef CANDY_PEER_CONNECTOR_H
#define CANDY_PEER_CONNECTOR_H

#include "core/net.h"
#include <chrono>
#include <string>

namespace Candy {

class PeerInfo;
class Peer;

class Connector {
public:
    Connector(PeerInfo *info) : info(info) {}

    virtual bool isConnected() const = 0;
    virtual bool tryToConnect() = 0;
    virtual void tick() = 0;
    virtual std::string name() = 0;
    IP4 address();
    Peer *peer();

protected:
    void refreshActiveTime();
    bool isActiveIn(std::chrono::system_clock::duration duration);
    PeerInfo *info;

private:
    std::chrono::system_clock::time_point lastActiveTime;
};

} // namespace Candy

#endif
