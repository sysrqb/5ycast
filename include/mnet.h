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

#ifndef MNET_H
#define MNET_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

// Needs C++14 support
//#include <gsl/gsl>

namespace mnet {

class MNet {
  int mFd;
  const char* mdns_addr = "224.0.0.251";
  const char* mdns_port = "5353";
  bool is_ready;

public:
  MNet() = default;
  bool CreateSocket(std::string& errmsg);
  bool DisableMulticastLoop(std::string& errmsg);
  bool AddMulticastMembership(std::string& errmsg);
  bool IsReady() const { return is_ready; }
  bool Poll(std::string& errmsg) const;
  bool Read(char** msg, size_t& msglen, std::string& errmsg) const;
};

} // namespace mnet
#endif // MNET_H
