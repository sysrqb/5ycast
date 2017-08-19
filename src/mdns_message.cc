#include "mdns_message.h"

namespace dns_message {

DNSMessage::DNSMessage(const char * const m) : rawmsg(m)
{
  header = new DNSHeader();
  rr_section[0] = new DNSRR();
  rr_section[1] = new DNSRR();
  rr_section[2] = new DNSRR();
}

bool DNSMessage::processMessage()
{
  return false;
}

} // namespace dns_message
