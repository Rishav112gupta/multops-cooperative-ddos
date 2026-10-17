// udp_sender.cpp -- see udp_sender.hpp.

#include "multops/udp_sender.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace multops {

UdpSender::UdpSender() : fd_(-1), addr_(0), port_(0), last_errno_(0), sent_(0), failed_(0) {}

UdpSender::~UdpSender() { close(); }

bool UdpSender::open(uint32_t ipv4_host, uint16_t port, std::string *error) {
    close();
    fd_ = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd_ < 0) {
        last_errno_ = errno;
        if (error) *error = std::string("socket: ") + std::strerror(errno);
        return false;
    }
    int flags = ::fcntl(fd_, F_GETFL, 0);
    if (flags < 0 || ::fcntl(fd_, F_SETFL, flags | O_NONBLOCK) < 0) {
        last_errno_ = errno;
        if (error) *error = std::string("fcntl: ") + std::strerror(errno);
        close();
        return false;
    }
    addr_ = ipv4_host;
    port_ = port;
    return true;
}

void UdpSender::close() {
    if (fd_ >= 0) ::close(fd_);
    fd_ = -1;
}

bool UdpSender::send(const uint8_t *data, std::size_t len) {
    if (fd_ < 0) {
        ++failed_;
        return false;
    }
    sockaddr_in sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port_);
    sa.sin_addr.s_addr = htonl(addr_);
    ssize_t n = ::sendto(fd_, data, len, 0, reinterpret_cast<const sockaddr *>(&sa), sizeof(sa));
    if (n < 0 || static_cast<std::size_t>(n) != len) {
        last_errno_ = n < 0 ? errno : EMSGSIZE;
        ++failed_;
        return false;
    }
    ++sent_;
    return true;
}

}  // namespace multops
