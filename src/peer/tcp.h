// SPDX-License-Identifier: MIT
#ifndef CANDY_PEER_TCP_H
#define CANDY_PEER_TCP_H

#include "peer/connector.h"

namespace Candy {

class TCP : public Connector {
public:
    bool isConnected() const;
};

class TCP4 : public TCP {};

class TCP6 : public TCP {};

} // namespace Candy

#endif
