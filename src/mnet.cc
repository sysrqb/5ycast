/*  5ycast - Google/chromecast implementation
 *  Copyright (C) 2017  Matthew Finkel
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string>
#include <cstring>
#include <unistd.h>
#include <cerrno>
#include <poll.h>

#include "mnet.h"

namespace mnet {

// Returns -1 on failure, >= 0 on success
static bool find_usable_socket(const char* node, const char* service,
                              std::string& err, struct addrinfo *ai, int *fd)
{
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  int sfd, s;
  char buf[1];
  const int sock_flags = MSG_DONTWAIT | MSG_CMSG_CLOEXEC | MSG_PEEK;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = 0;
  hints.ai_flags = AI_NUMERICSERV|AI_CANONNAME;

  s = getaddrinfo(node, service, &hints, &result);
  if (s != 0) {
    err.assign(gai_strerror(s));
    err += std::string("; node: ") + node;
    err += std::string("; service: ") + service;
    return false;
  }

  for (rp = result; rp != nullptr; rp = rp->ai_next) {
    sfd = socket(rp->ai_family, rp->ai_socktype,
    rp->ai_protocol);
    if (sfd == -1)
      continue;

    ssize_t r = recvfrom(sfd, &buf, sizeof buf, sock_flags, nullptr, 0);
    if (r == 0) {
      break;
    } else if (r == -1 && errno == EAGAIN) {
      break;
    }

    close(sfd);
  }

  if (rp == nullptr) {
    err.assign("none found");
    return false;
  }
  memcpy(ai, rp, sizeof(*ai));
  *fd = sfd;

  return true;
}

bool MNet::CreateSocket(std::string& errmsg)
{
  std::string errmsg_r;
  struct addrinfo rp;
  int socket;
  if (!find_usable_socket(mdns_addr, mdns_port, errmsg_r, &rp, &socket)) {
    errmsg = "Failure while searching for usable socket: " + errmsg_r;
    return false;
  }
  std::memmove(&ai, &rp, sizeof(ai));
  mFd = socket;
  return true;
}

// Disable message loop
// Add mdns_addr membership
bool MNet::DisableMulticastLoop(std::string& errmsg)
{
  const uint8_t loop = 0;
  if (setsockopt(mFd, IPPROTO_IP, IP_MULTICAST_LOOP,
                 &loop, sizeof(loop)) != 0) {
    errmsg = "Disabling multicast loop failed: ";
    errmsg += std::string(strerror(errno));
    return false;
  }
  return true;
}

bool MNet::AddMulticastMembership(std::string& errmsg)
{
  const uint8_t loop = 0;
  struct sockaddr_in* ai_addr_in = reinterpret_cast<struct sockaddr_in*>(ai.ai_addr);
  if (ai_addr_in == nullptr) {
    errmsg = "sockaddr is null";
    return false;
  }
  const struct ip_mreq mrq{ai_addr_in->sin_addr.s_addr, INADDR_ANY};
  if (setsockopt(mFd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                 &mrq, sizeof(mrq)) != 0) {
    errmsg = "Joining the multicast group failed: ";
    errmsg += std::string(strerror(errno));
    return false;
  }
  char srcaddr[NI_MAXHOST], srcport[NI_MAXSERV];
  if (getnameinfo(ai.ai_addr, sizeof(*ai.ai_addr), srcaddr, NI_MAXHOST, srcport, NI_MAXSERV,
                  NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
    errmsg = std::string("Multicast membership added for ");
    errmsg += std::string(srcaddr) + ":"; + srcport;
  }
  return true;
}

bool MNet::Poll(std::string& errmsg) const
{
  uint8_t revents;
  struct pollfd pfd {mFd, POLLIN|POLLOUT, 0};
  int count = poll(&pfd, 1, 0);
  if (count == -1) {
    errmsg = "poll() failed with error: " + std::string(strerror(errno));
    return false;
  } else if (count == 0) {
    errmsg = "poll() says there's nothing new";
    return false;
  }
  return true;
}

// Returns true on success, false on failure
// Error message is stored in errmsg
// On success, *msg contains a buffer with the recevied bytes
// If *msg contains bytes, then msglen specifies the number of bytes
bool MNet::Read(char** msg, size_t& msglen, std::string& errmsg) const
{
  struct sockaddr src_addr;
  socklen_t addrlen = sizeof(src_addr);
  ssize_t count;
  int flags = MSG_DONTWAIT;
  // DNS supports up to 512 bytes, MDNS supports whatever is the LAN's MTU
  // Let's assume 1500
  char buf[1500];

  count = recvfrom(mFd, buf, sizeof(buf) / sizeof(buf[0]), flags,
                   &src_addr, &addrlen);
  if (count == -1 && errno != EAGAIN) {
    errmsg = std::string("recvfrom() failed with error: ") + strerror(errno);
    return false;
  } else if (count == 0) {
    errmsg = "recvfrom() returned 0 count";
    return false;
  } else if (count == -1  && errno == EAGAIN) {
    errmsg = "recvfrom() returned EAGAIN";
    return false;
  }
  *msg = new char[count];
  if (*msg == nullptr) {
    errmsg = std::string("Couldn't allocate a buffer: ") + strerror(errno);
    return false;
  }
  char srcaddr[NI_MAXHOST], srcport[NI_MAXSERV];
  if (getnameinfo(&src_addr, addrlen, srcaddr, NI_MAXHOST, srcport, NI_MAXSERV,
                  NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
    errmsg = std::string("Received message from: ") + srcaddr + ":" + srcport;
  } else {
    errmsg = "Received message from unknown peer";
  }
  msglen = count;
  memmove(*msg, buf, msglen);
  return true;
}

} // namespace mnet
