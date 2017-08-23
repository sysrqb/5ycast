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

bool DNSMessage::ProcessQuestions(const char* const m, std::size_t mlen,
                                   std::uint16_t qcount)
{
  std::size_t i;
  std::size_t offset = 0;
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

} // namespace dns_message
