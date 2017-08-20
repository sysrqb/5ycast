#include <string.h>

#include "mdns_message.h"

namespace dns_message {

bool DNSHeader::ProcessHeader(const char* const m, const std::size_t mlen)
{
  return false;
}

bool DNSHeader::ProcessHeader(const char* const m)
{
  return ProcessHeader(m, strlen(m));
}

} // namespace dns_message
