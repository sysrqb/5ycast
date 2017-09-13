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

#include <cstring>

#include "mdns_message.h"

namespace dns_message {

// Parse the header of the message
// m: string for parsing
// mlen: length of m
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
    id = (id_bytes_c[0] << 8) | (id_bytes_c[1]);
  }

  {
    const std::string byte = header.substr(2, 1);
    const char* byte_c = byte.c_str();
    qr = (std::uint8_t(*byte_c) >> 7) == 1;
    // Drop the lower three bit fields, AND the top bit with 0
    opcode = (*byte_c >> 3) & 0xF;
    aa = ((*byte_c >> 2) & 0x1) == 1;
    tc = ((*byte_c >> 1) & 0x1) == 1;
    rd = (*byte_c & 0x1) == 1;
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
    // The spec says we should ignore these
    (void)ad;
    (void)cd;
    rcode = (*byte_c & 0xF);
    // We should silently ignore messages with non-zero rcode
    if (rcode != 0) {
      return false;
    }
  }

  {
    const std::string qd_str = header.substr(4, 2);
    const char* qd_c = qd_str.c_str();
    qdcount = (qd_c[0] << 8) | qd_c[1];
  }

  {
    const std::string an_str = header.substr(6, 2);
    const char* an_c = an_str.c_str();
    ancount = (an_c[0] << 8) | an_c[1];
  }

  {
    const std::string ns_str = header.substr(8, 2);
    const char* ns_c = ns_str.c_str();
    nscount = (ns_c[0] << 8) | ns_c[1];
  }

  {
    const std::string ar_str = header.substr(10, 2);
    const char* ar_c = ar_str.c_str();
    arcount = (ar_c[0] << 8) | ar_c[1];
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

const std::string DNSHeader::Stringify() const
{
  constexpr size_t line_len = StringifyDNSMessage::line_len;
  std::vector<std::string> vrep;

  vrep.push_back(
    std::move(StringifyDNSMessage::GetByteLabels()));

  vrep.push_back(StringifyDNSMessage::GetRowSep());

  std::string str_line;
  {
    std::string line{"|"};
    line.append(StringifyDNSMessage::GetFieldRep(mMsgID, line_len));
    line.append("|");
    str_line = std::move(line);
  }
  vrep.push_back(std::move(str_line));

  vrep.push_back(StringifyDNSMessage::GetRowSep());

  str_line.erase();
  {
    std::string line{"| "};
    line.append(std::to_string(mBits.mQRField)).append("|");
    line.append(StringifyDNSMessage::GetFieldRep(mOpCode, 11));
    line.append("| ").append(std::to_string(mBits.mAAField));
    line.append("| ").append(std::to_string(mBits.mTCField));
    line.append("| ").append(std::to_string(mBits.mRDField));
    line.append("| ").append(std::to_string(mBits.mRAField));
    line.append("| 0");
    line.append("| 0");
    line.append("| 0");
    line.append("|");

    line.append(StringifyDNSMessage::GetFieldRep(mRcode, 11)).append("|");

    str_line = std::move(line);
  }
  vrep.push_back(std::move(str_line));

  vrep.push_back(StringifyDNSMessage::GetRowSep());

  str_line.erase();
  {
    std::string line{"|"};
    line.append(StringifyDNSMessage::GetFieldRep(mQDCount, line_len));
    line.append("|");
    str_line = std::move(line);
  }
  vrep.push_back(std::move(str_line));

  vrep.push_back(StringifyDNSMessage::GetRowSep());

  str_line.erase();
  {
    std::string line{"|"};
    line.append(StringifyDNSMessage::GetFieldRep(mANCount, line_len));
    line.append("|");
    str_line = std::move(line);
  }
  vrep.push_back(std::move(str_line));

  vrep.push_back(StringifyDNSMessage::GetRowSep());

  str_line.erase();
  {
    std::string line{"|"};
    line.append(StringifyDNSMessage::GetFieldRep(mNSCount, line_len));
    line.append("|");
    str_line = std::move(line);
  }
  vrep.push_back(std::move(str_line));

  vrep.push_back(StringifyDNSMessage::GetRowSep());

  str_line.erase();
  {
    std::string line{"|"};
    line.append(StringifyDNSMessage::GetFieldRep(mARCount, line_len));
    line.append("|");
    str_line = std::move(line);
  }
  vrep.push_back(std::move(str_line));

  vrep.push_back(StringifyDNSMessage::GetRowSep());

  return [&vrep]() -> std::string {
    std::string r;
    for (auto&& e : vrep) { r.append(e); r += "\n"; }
    return r;
  }();
}

} // namespace dns_message
