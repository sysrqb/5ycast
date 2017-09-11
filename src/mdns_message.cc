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

#include <cassert>
#include <cstring>
#include <cstdio>

#include "mdns_message.h"

namespace dns_message {

// m: string for parsing
// mlen: length of m
DNSMessage::DNSMessage(const char* const m, const std::size_t mlen) : mHeader(new DNSHeader),
                                                                      mRawMsg(m, mlen)
{
}

// Delegating constructor
// m: string for parsing, cannot contain nul characters
DNSMessage::DNSMessage(const char* const m) : DNSMessage(m, std::strlen(m)) { }

// Process each section of the dns packet until any failure occurs or the
// message is parsed successfully.
bool DNSMessage::ProcessMessage()
{
  const std::uint8_t header_length = 12;
  const std::uint8_t an_section = 0;
  const std::uint8_t ns_section = 1;
  const std::uint8_t ar_section = 2;
  std::size_t offset = 0;
  if (!mHeader->ProcessHeader(mRawMsg.c_str(), mRawMsg.length())) {
    return false;
  }
  if (mHeader->GetQDCount() > 0 &&
      !ProcessQuestions(mRawMsg.c_str() + header_length,
                        mRawMsg.length() - header_length,
                        mHeader->GetQDCount(), offset)) {
    return false;
  }
  if (mHeader->GetANCount() > 0 &&
      !ProcessRRs(mRawMsg.c_str() + header_length,
                  mRawMsg.length() - header_length,
                  mHeader->GetANCount(), offset, an_section)) {
    return false;
  }
  if (mHeader->GetNSCount() > 0 &&
      !ProcessRRs(mRawMsg.c_str() + header_length,
                  mRawMsg.length() - header_length,
                  mHeader->GetNSCount(), offset, ns_section)) {
    return false;
  }
  if (mHeader->GetARCount() > 0 &&
      !ProcessRRs(mRawMsg.c_str() + header_length,
                  mRawMsg.length() - header_length,
                  mHeader->GetARCount(), offset, ar_section)) {
    return false;
  }
  return true;
}

// Parse the question section of the message
// m: string for parsing
// mlen: length of m
// qcount: number of questions encapsulated in this section
// offset: Tracks position within m of processing
bool DNSMessage::ProcessQuestions(const char* const m, std::size_t mlen,
                                  std::uint16_t qcount, std::size_t& offset)
{
  std::size_t i;
  std::vector<DNSQuestion> qs;
  for (i = 0; i < qcount; i++) {
    DNSQuestion question;
    if (!question.ProcessQuestion(m, mlen, offset)) {
      return false;
    }
    qs.push_back(std::move(question));
  }
  mQuestions = std::move(qs);
  return true;
}

// Parse the resource record sections of the message
// m: string for parsing
// mlen: length of m
// count: number of questions encapsulated in this section
// offset: Tracks position within m of processing
// section: Specifies the section of the message (0: an, 1: ns, 2: ar)
bool DNSMessage::ProcessRRs(const char* const m, std::size_t mlen,
                            std::uint16_t count, std::size_t& offset,
                            std::uint8_t section)
{
  std::size_t i;
  std::vector<DNSRR> rrs;
  for (i = 0; i < count; i++) {
    DNSRR rr;
    if (!rr.ProcessRR(m, mlen, offset)) {
      return false;
    }
    rrs.push_back(std::move(rr));
  }
  mRRSection[section] = std::move(rrs);
  return true;
}

// static - Parse the next name in the message
// m: pointers at the location in the string for parsing
// mlen: length of m
// name: string ref where string is returned, on success
// nlen: length of name as specified within m, or 1 if name is compressed
bool DNSMessage::ProcessName(const char* const m, std::size_t mlen,
                             std::string& name, std::uint8_t &nlen)
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
    // Capture the message compression. nlen is 1 because on return
    // it is expected the caller adds 1 so it accounts for the 1 byte
    // length value.
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

bool DNSMessage::DecompressName(const char* const m, const std::size_t mlen,
                                const std::string& name, std::string& ref)
{
  std::string ptrstr;
  std::uint8_t nlen;
  const char last_byte2 = name.at(name.size()-2);
  const char last_byte1 = name.at(name.size()-1);

  if (m == nullptr) {
    return false;
  }
  if ((last_byte2 & 0xC0) != 0xC0) {
    return false;
  }
  // Last byte is a pointer, using message compression
  std::uint16_t ptr = ((last_byte2 & 0x3F) << 8);
  ptr |= last_byte1;
  if (mlen < ptr) {
    return false;
  }
  if (!ProcessName(m + ptr, mlen - ptr, ptrstr, nlen)) {
    return false;
  }
  if (nlen > 1 && (ptrstr.at(nlen-2) & 0xC0) == 0xC0) {
    // TODO We're not supporting pointer-to-pointer chaining right now.
    return false;
  }
  ref = std::move(ptrstr);
  return true;
}

} // namespace dns_message
