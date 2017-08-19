#include <string.h>

#include "mdns_message.h"

namespace dns_message {

DNSMessage::DNSMessage(const char* const m, const size_t mlen) : mRawMsg(m, mlen)
{
  mHeader = new DNSHeader();
  mRRSection[0] = new DNSRR();
  mRRSection[1] = new DNSRR();
  mRRSection[2] = new DNSRR();
}

DNSMessage::DNSMessage(const char* const m) : DNSMessage(m, strlen(m)) { }

bool DNSMessage::ProcessMessage()
{
  return false;
}

} // namespace dns_message
