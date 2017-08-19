#include "gtest/gtest.h"
#include "mdns_message.h"

namespace dns_message {

namespace testing {

TEST(DNSMessageTest, GetRawMessageReturnsmRawMsg)
{
  char* input;
  std::string result;
  std::string expected;
  DNSMessage* dnsMsg;

  input = (char* )"foo";
  expected = std::string("foo");
  dnsMsg = new DNSMessage(input);
  result = dnsMsg->GetRawMessage();
  EXPECT_EQ(expected, result);
  delete dnsMsg;
  
  input = (char* )"foo\0";
  expected = std::string("foo\0", 5);
  dnsMsg = new DNSMessage(input, 5);
  result = dnsMsg->GetRawMessage();
  EXPECT_EQ(expected, result);
  delete dnsMsg;
  
  input = (char* )"foo\0bar";
  expected = std::string("foo\0bar", 8);
  dnsMsg = new DNSMessage(input, 8);
  result = dnsMsg->GetRawMessage();
  EXPECT_EQ(expected, result);
  delete dnsMsg;
}

} // namespace testing
} // namespace dns_message
