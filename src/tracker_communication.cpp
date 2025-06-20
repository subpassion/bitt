#include <format>

#include "tracker_communication.hpp"
#include "lib/httplib/httplib.h"
#include "tcp_client.hpp"

namespace Communication
{
    std::string create_announcement_query(const AnnouncementInfo &info)
    {
        return std::format("/announce?info_hash={}&peer_id={}&port={}&uploaded={}&downloaded={}&left={}&compact={}",
                           httplib::detail::encode_query_param(info.info_hash),
                           info.peer_id, info.port, info.uploaded, info.downloaded, info.left, info.compact);

    }

    std::string create_handshake_message(const HandshakeInfo& info)
    {
        auto message = std::string("\x13", 1);
        message.append("BitTorrent protocol");
        message.append("\x00\x00\x00\x00\x00\x00\x00\x00", 8);
        message.append(info.hash);
        message.append(info.peer_id);
        return message;
    }
}