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

namespace mnet {

#define MDNS_PORT 5353
class MNet {
  int mFd;
  const char* mdns_addr = "224.0.0.251";
  const char* mdns_port_str = "MDNS_PORT";
  const uint16_t mdns_port = MDNS_PORT;
  struct addrinfo ai;
  bool is_ready;

public:
  MNet() = default;
  bool CreateSocket(std::string& errmsg);
  bool DisableMulticastLoop(std::string& errmsg);
  bool AddMulticastMembership(std::string& errmsg);
  bool IsReady() const { return is_ready; }
};
#undef MDNS_PORT

} // namespace mnet
#endif // MNET_H
