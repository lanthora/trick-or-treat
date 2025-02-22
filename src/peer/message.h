// SPDX-License-Identifier: MIT
#ifndef CANDY_PEER_MESSAGE_H
#define CANDY_PEER_MESSAGE_H

#include "core/net.h"
#include <cstdint>

namespace Candy {

namespace PeerMsgKind {
constexpr uint8_t HEARTBEAT = 0;
constexpr uint8_t FORWARD = 1;
constexpr uint8_t DELAY = 2;
// TODO: 遗漏了 3, 新功能时使用
constexpr uint8_t ROUTE = 4;

} // namespace PeerMsgKind

struct StunRequest {
    uint8_t type[2] = {0x00, 0x01};
    uint8_t length[2] = {0x00, 0x08};
    uint8_t cookie[4] = {0x21, 0x12, 0xa4, 0x42};
    uint8_t id[12] = {0x00};
    struct {
        uint8_t type[2] = {0x00, 0x03};
        uint8_t length[2] = {0x00, 0x04};
        uint8_t notset[4] = {0x00};
    } attr;
};

struct StunResponse {
    uint16_t type;
    uint16_t length;
    uint32_t cookie;
    uint8_t id[12];
    uint8_t attr[0];
};

namespace PeerMsg {

struct Heartbeat {
    uint8_t kind;
    IP4 tunip;
    IP4 _ip;
    uint16_t _port;
    uint8_t ack;
} __attribute__((packed));

} // namespace PeerMsg

} // namespace Candy

#endif
