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

#include "mdns_message.h"

namespace dns_message {

// Parse the names from the message
// m: string for parsing
// mlen: length of m
// offset: position within m where parsing should begin
// aName: vector containing the successfully parsed names
static bool processNames(const char* const m, std::size_t mlen,
                       std::size_t& offset, std::vector<std::string>& aName)
{
  std::vector<std::string> names;
  std::string name;
  std::uint8_t nlen;
  std::uint16_t next_label = offset;
  while (DNSMessage::ProcessName(m + next_label,
                                 mlen - next_label,
                                 name,
                                 nlen)) {
    names.push_back(std::move(name));
    next_label += nlen + 1;
    if (nlen == 0) {
      if (mlen - next_label < 4) {
        return false;
      }
      aName = std::move(names);
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

// Parse the resource record section of the message
// m: string for parsing
// mlen: length of m
// offset: position within m where parsing should begin
bool DNSRR::ProcessRR(const char* const m, std::size_t mlen,
                      std::size_t& offset)
{
  // Assuming 1 byte for 0 length plus 10 bytes for meta fields
  const uint8_t minimum_name_length = 1;
  const uint8_t rr_meta_length = 10;
  const uint8_t minimum_rr_length = rr_meta_length + minimum_name_length;
  std::vector<std::string> name;
  std::uint16_t rrtype;
  std::uint16_t rrclass;
  std::uint32_t rrttl;
  std::uint16_t rrdlength;
  DNSRData *rdata;

  if (mlen < minimum_rr_length) {
    return false;
  }
  if (!processNames(m, mlen, offset, name)) {
    return false;
  }
  if (mlen - offset < rr_meta_length) {
    return false;
  }
  rrtype = (m[offset++] << 8) | m[offset++];
  rrclass = (m[offset++] << 8) | m[offset++];
  rrclass = (m[offset++] << 8) | m[offset++];
  rrclass <<= 16;
  rrclass = (m[offset++] << 8) | m[offset++];
  rrdlength = (m[offset++] << 8) | m[offset++];
  return false;
}

void DNSPtrRData::AddPtrNames(const std::vector<std::string>&& names)
{
  mPtrDName = names;
}

} // namespace dns_message
