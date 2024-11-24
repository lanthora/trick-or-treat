// SPDX-License-Identifier: MIT
#ifndef CANDY_PEER_CONNECTOR_H
#define CANDY_PEER_CONNECTOR_H

namespace Candy {

class Connector {
public:
    virtual bool isConnected() const = 0;
};

} // namespace Candy

#endif
