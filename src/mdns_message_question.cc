#include "mdns_message.h"

namespace dns_message {

DNSQuestion::DNSQuestion(DNSQuestion&& q)
{
  mQNames = std::move(q.mQNames);
  mQType = q.mQType;
  mQClass = q.mQClass;
}

// Parse the question from the message
// m: string for parsing
// mlen: length of m
// offset: position within m where parsing should begin
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
  while (DNSMessage::ProcessName(m + next_label,
                                 mlen - next_label,
                                 name,
                                 nlen)) {
    qnames.push_back(std::move(name));
    next_label += nlen + 1;
    if (nlen == 0) {
      if (mlen - next_label < 4) {
        return false;
      }
      mQNames = std::move(qnames);
      mQType = (std::uint8_t(m[next_label++]) << 8);
      mQType |= std::uint8_t(m[next_label++]);
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
