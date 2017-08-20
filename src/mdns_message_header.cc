#include <cstring>

#include <arpa/inet.h>

#include "mdns_message.h"

namespace dns_message {

bool DNSHeader::ProcessHeader(const char* const m, const std::size_t mlen)
{
  std::uint16_t id;
  bool qr;
  std::uint8_t opcode;
  bool aa, tc, rd, ra, ad, cd;
  std::uint8_t rcode;
  std::uint16_t qdcount, ancount, nscount, arcount;

  if (mlen < 12) {
    return false;
  }
  if (m == nullptr) {
    return false;
  }
  const std::string header = std::string(m, mlen);
  {
    const std::string id_bytes = header.substr(0, 2);
    const char* id_bytes_c = id_bytes.c_str();
    id = ntohs(*id_bytes_c);
  }

  {
    const std::string byte = header.substr(2, 1);
    const char* byte_c = byte.c_str();
    qr = (*byte_c >> 7) == 1;
    // Drop the lower three bit fields, AND the top bit with 0
    opcode = (*byte_c >> 3) & 0xF;
    aa = (*byte_c >> 2) & 0x1;
    tc = (*byte_c >> 1) & 0x1;
    rd = *byte_c & 0x1;
  }

  {
    const std::string byte = header.substr(3, 1);
    const char* byte_c = byte.c_str();
    ra = (*byte_c >> 7);
    std::uint8_t z = (*byte_c >> 6) & 0x1;
    if (z != 0) {
      return false;
    }

    ad = (*byte_c >> 5) & 0x1;
    cd = (*byte_c >> 4) & 0x1;
    rcode = (*byte_c & 0xF);
  }

  {
    const std::string qd_str = header.substr(4, 2);
    const char* qd_c = qd_str.c_str();
    qdcount = ntohs(*qd_c);
  }

  {
    const std::string an_str = header.substr(4, 2);
    const char* an_c = an_str.c_str();
    ancount = ntohs(*an_c);
  }

  {
    const std::string ns_str = header.substr(4, 2);
    const char* ns_c = ns_str.c_str();
    nscount = ntohs(*ns_c);
  }

  {
    const std::string ar_str = header.substr(4, 2);
    const char* ar_c = ar_str.c_str();
    arcount = ntohs(*ar_c);
  }

  mMsgID = id;
  mOpCode = opcode;
  mBits.mQRField = qr;
  mBits.mAAField = aa;
  mBits.mTCField = tc;
  mBits.mRDField = rd;
  mBits.mRAField = ra;
  mRcode = rcode;
  mQDCount = qdcount;
  mANCount = ancount;
  mNSCount = nscount;
  mARCount = arcount;

  return true;
}

bool DNSHeader::ProcessHeader(const char* const m)
{
  return ProcessHeader(m, strlen(m));
}

} // namespace dns_message
