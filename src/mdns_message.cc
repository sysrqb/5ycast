#include <cassert>
#include <cstring>

#include "mdns_message.h"

namespace dns_message {

DNSMessage::DNSMessage(const char* const m, const std::size_t mlen) : mRawMsg(m, mlen),
                                                                      mHeader(new DNSHeader)
{
}

DNSMessage::DNSMessage(const char* const m) : DNSMessage(m, std::strlen(m)) { }

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
    // Capture the message compression. nlen is 1 because the on return
    // It is expected the caller adds 1 so it accounts for the 1 byte
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

} // namespace dns_message
