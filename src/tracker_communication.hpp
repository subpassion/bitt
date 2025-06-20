#pragma once

#include <string>
#include <stdint.h>

namespace Communication
{
struct AnnouncementInfo
{
    std::string info_hash;
    std::string peer_id;
    uint16_t port;
    uint64_t uploaded;
    uint64_t downloaded;
    uint64_t left;
    uint8_t compact;
};

struct HandshakeInfo
{
    std::string hash;
    std::string peer_id;
};

std::string create_handshake_message(const HandshakeInfo& info); 
std::string create_announcement_query(const AnnouncementInfo& info); 
};