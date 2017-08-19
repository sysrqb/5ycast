#include "mdns_message.h"

namespace dns_message {

DNSMessage::DNSMessage(const char* const m) : mRawMsg(m)
{
  mHeader = new DNSHeader();
  mRRSection[0] = new DNSRR();
  mRRSection[1] = new DNSRR();
  mRRSection[2] = new DNSRR();
}

bool DNSMessage::ProcessMessage()
{
  return false;
}

} // namespace dns_message
