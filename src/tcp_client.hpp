#pragma once

#include <stdint.h>
#include <string>
#include <winsock2.h>

class TcpClient
{
public:
    TcpClient(const std::string &ip, uint32_t port);

    void init();
    int send_message(const std::string &message);
    std::string receive_message();
private:
    std::string m_ip;
    uint32_t m_port;
    SOCKET m_client_socket;
};