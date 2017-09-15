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
    bool is_ptr = (nlen == 1 && ((name[0] & 0xc0) == 0xc0));
    qnames.push_back(std::move(name));

    next_label += nlen + 1;
    if (nlen == 0 || is_ptr) {
      // This was either a nul byte or a pointer. In either case the question
      // is complete and the remaining bytes are the meta fields
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

const std::string DNSQuestion::Stringify() const
{
  constexpr size_t line_len = StringifyDNSMessage::line_len;
  std::vector<std::string> vrep;

  vrep.push_back(std::move(StringifyDNSMessage::GetByteLabels()));

  vrep.push_back(StringifyDNSMessage::GetRowSep());

  std::string str_line;
  // GetNameRep() includes '|' when needed
  str_line.append(StringifyDNSMessage::GetNameRep(mQNames, line_len));
  vrep.push_back(std::move(str_line));

  vrep.push_back(StringifyDNSMessage::GetRowSep());

  str_line.erase();
  {
    std::string line{"|"};
    line.append(StringifyDNSMessage::GetFieldRep(mQType, line_len));
    line.append("|");
    str_line = std::move(line);
  }
  vrep.push_back(std::move(str_line));

  vrep.push_back(StringifyDNSMessage::GetRowSep());

  str_line.erase();
  {
    std::string line{"|"};
    line.append(StringifyDNSMessage::GetFieldRep(mQClass, line_len));
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

} // namespace dns_messge
