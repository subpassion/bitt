#include "tcp_client.hpp"

#include <iostream>
#include <ws2tcpip.h>

TcpClient::TcpClient(const std::string &ip, uint32_t port)
    : m_ip(ip), m_port(port), m_client_socket(INVALID_SOCKET)
{
}

void TcpClient::init()
{
    // Assume that WSAStartup is called by httplib
    m_client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_client_socket == INVALID_SOCKET)
    {
        throw std::runtime_error(std::format("Error during socket creation {}\n", WSAGetLastError()));
    }
    std::cout << "[INFO] Create socket successfully\n";

    sockaddr_in service;
    service.sin_family = AF_INET;
    service.sin_addr.s_addr = inet_addr(m_ip.c_str());
    service.sin_port = htons(m_port);
    if (connect(m_client_socket, reinterpret_cast<SOCKADDR *>(&service), sizeof(service)) == SOCKET_ERROR)
    {
        closesocket(m_client_socket);
        throw std::runtime_error(std::format("Can't connect socket to {}:{}, error - {}\n", m_ip, m_port, WSAGetLastError()));
    }
    std::cout << "[INFO] Connected to socket successfully\n";
}

int TcpClient::send_message(const std::string &message)
{
    std::cout << std::format("[INFO] Sending message of size {} to {}:{}\n", message.size(), m_ip, m_port);

    auto send_bytes = send(m_client_socket, message.data(), message.size(), 0);
    if (send_bytes == SOCKET_ERROR)
    {
        throw std::runtime_error(std::format("Client failed to send message: {}\n", WSAGetLastError()));
    }
    return send_bytes;
}

std::string TcpClient::receive_message()
{
    constexpr uint32_t buffer_size = 200;
    char receive_buffer[buffer_size];
    auto receive_bytes = recv(m_client_socket, receive_buffer, buffer_size, 0);
    auto res = std::string();
    if (receive_bytes < 0)
    {
        throw std::runtime_error(std::format("Client recv error: {}", WSAGetLastError()));
    }
    
    std::cout << std::format("[INFO] Received {} bytes\n", receive_bytes);
    return std::string(receive_buffer, receive_bytes);
}