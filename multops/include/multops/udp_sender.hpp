// udp_sender.hpp -- minimal IPv4 UDP datagram sender (POSIX sockets).
//
// The paper's send_stats_packet() uses sendto(); this is the same mechanism,
// wrapped as a telemetry::DatagramSink. The socket is non-blocking so that a
// full socket buffer can never stall the packet path (a Click timer runs in
// the router's main loop); such a datagram is counted as a send failure and
// dropped -- consistent with UDP's best-effort semantics.

#ifndef MULTOPS_UDP_SENDER_HPP
#define MULTOPS_UDP_SENDER_HPP

#include <cstdint>
#include <string>

#include "multops/telemetry.hpp"

namespace multops {

class UdpSender : public telemetry::DatagramSink {
  public:
    UdpSender();
    ~UdpSender() override;
    UdpSender(const UdpSender &) = delete;
    UdpSender &operator=(const UdpSender &) = delete;

    // Destination in host byte order. Returns false and sets *error on failure.
    bool open(uint32_t ipv4_host, uint16_t port, std::string *error);
    void close();
    bool is_open() const { return fd_ >= 0; }

    bool send(const uint8_t *data, std::size_t len) override;

    int last_errno() const { return last_errno_; }
    uint64_t sent() const { return sent_; }
    uint64_t failed() const { return failed_; }

  private:
    int fd_;
    uint32_t addr_;
    uint16_t port_;
    int last_errno_;
    uint64_t sent_;
    uint64_t failed_;
};

}  // namespace multops

#endif
