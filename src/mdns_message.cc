#include <cstring>

#include "mdns_message.h"

namespace dns_message {

DNSMessage::DNSMessage(const char* const m, const std::size_t mlen) : mRawMsg(m, mlen)
{
  mHeader = new DNSHeader();
  mRRSection[0] = new DNSRR();
  mRRSection[1] = new DNSRR();
  mRRSection[2] = new DNSRR();
}

DNSMessage::DNSMessage(const char* const m) : DNSMessage(m, std::strlen(m)) { }

DNSMessage::~DNSMessage()
{
  delete mHeader;
  delete mRRSection[0];
  delete mRRSection[1];
  delete mRRSection[2];
}


bool DNSMessage::ProcessMessage()
{
  if (!mHeader->ProcessHeader(mRawMsg.c_str(), mRawMsg.length())) {
    return false;
  }
  return true;
}

} // namespace dns_message
