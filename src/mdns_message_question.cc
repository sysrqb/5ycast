#include "mdns_message.h"

namespace dns_message {

DNSQuestion::DNSQuestion(DNSQuestion&& q)
{
  mQNames = std::move(q.mQNames);
  mQCode = q.mQCode;
  mQClass = q.mQClass;
}

bool DNSQuestion::ProcessQName(const char* const m, std::size_t mlen,
                               std::string &name, std::uint8_t &nlen)
{
  if (m == nullptr) {
    return false;
  }
  if (mlen == 0) {
    return false;
  }
  nlen = m[0];
  if (nlen == 0) {
    name = "";
    return true;
  }
  if ((nlen & 0xC0) == 0xC0) {
    // Capture the message compression. nlen is 1 because the on return
    // ProcessQuestion adds 1 so it accounts for the 1 byte length value.
    nlen = 1;
    name = std::string(m, nlen + 1);
    return true;
  }
  if (nlen > (mlen - 1)) {
    return false;
  }
  name = std::string((m+1), nlen);
  return true;
}

bool DNSQuestion::ProcessQuestion(const char* const m, std::size_t mlen,
                                  std::size_t& offset)
{
  const std::uint8_t minimum_qlen = 1 + 2 + 2;
  if (mlen < minimum_qlen) {
    return false;
  }
  std::vector<std::string> qnames;
  std::string name;
  std::uint8_t nlen;
  std::uint16_t next_label = offset;
  while (ProcessQName(m + next_label, mlen - next_label, name, nlen)) {
    qnames.push_back(std::move(name));
    next_label += nlen + 1;
    if (nlen == 0) {
      if (mlen - next_label < 4) {
        while (qnames.size() > 0) { qnames.pop_back(); }
        return false;
      }
      mQNames = std::move(qnames);
      mQCode = (std::uint8_t(m[next_label++]) << 8);
      mQCode |= std::uint8_t(m[next_label++]);
      mQClass = (std::uint8_t(m[next_label++]) << 8);
      mQClass |= std::uint8_t(m[next_label++]);
      offset = next_label;
      return true;
    }
    // If we didn't find a zero length label, but we are running past the
    // end of the message, then processing failed.
    if (mlen < next_label) {
      return false;
    }
  }
  return false;
}

} // namespace dns_messge
