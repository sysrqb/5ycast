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

#include <cstdio>
#include <string>

#include "mdns_message.h"
#include "mnet.h"

int main()
{
  std::string errmsg;
  mnet::MNet mnet;
  if (!mnet.CreateSocket(errmsg)) {
    printf("CreateSocket() failed: %s\n", errmsg.c_str());
    return -1;
  }
  if (!mnet.DisableMulticastLoop(errmsg)) {
    printf("DisableMulticastLoop() failed: %s\n", errmsg.c_str());
    return -1;
  }
  if (!mnet.AddMulticastMembership(errmsg)) {
    printf("AddMulticastMembership() failed: %s\n", errmsg.c_str());
    return -1;
  }
  printf("AddMulticastMembership() said: %s\n", errmsg.c_str());
  if (!mnet.Poll(errmsg)) {
    printf("Poll() failed: %s\n", errmsg.c_str());
    return -1;
  }
  printf("Poll() said: %s\n", errmsg.c_str());

  char* msgbuf;
  size_t msgbuflen;
  if (!mnet.Read(&msgbuf, msgbuflen, errmsg)) {
    printf("Read() failed: %s\n", errmsg.c_str());
    return -1;
  }
  if (msgbuflen == 0) {
    printf("Read() said: %s\n", errmsg.c_str());
  } else {
    printf("Read %zd bytes: '%s'\n\n", msgbuflen, msgbuf);
    dns_message::DNSMessage msg{msgbuf, msgbuflen};
    msg.ProcessMessage();
    printf("%s\n", msg.Stringify().c_str());
  }
  printf("Everything ran successfully!\n");
  return 0;
}
