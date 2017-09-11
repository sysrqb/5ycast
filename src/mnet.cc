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
    errmsg += std::string(strerror(errno)) + "\n";
    return false;
  }
  return true;
}

bool MNet::AddMulticastMembership(std::string& errmsg)
{
  const uint8_t loop = 0;
  struct sockaddr_in* ai_addr_in = reinterpret_cast<struct sockaddr_in*>(ai.ai_addr);
  const struct ip_mreq mrq {ai_addr_in->sin_addr.s_addr, INADDR_ANY};
  if (setsockopt(mFd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                 &mrq, sizeof(mrq)) != 0) {
    errmsg = "Joining the multicast group failed: ";
    errmsg += std::string(strerror(errno)) + "\n";
    return false;
  }
  return true;
}
} // namespace mnet
