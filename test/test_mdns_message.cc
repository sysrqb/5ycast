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

TEST(DNSMessageTest, ProcessMessageRawMsg) {
  char* input;
  bool result;
  DNSMessage* dnsMsg;

  input = (char* )"";
  dnsMsg = new DNSMessage(input);
  result = dnsMsg->ProcessMessage();
  EXPECT_FALSE(result);
  delete dnsMsg;

  input = (char* )"lessthan12";
  dnsMsg = new DNSMessage(input);
  result = dnsMsg->ProcessMessage();
  EXPECT_FALSE(result);
  delete dnsMsg;

  input = (char* )"morethan12foo";
  dnsMsg = new DNSMessage(input);
  result = dnsMsg->ProcessMessage();
  EXPECT_FALSE(result);
  delete dnsMsg;
}

TEST(DNSHeaderTest, ProcessHeaderRawMsg) {
  char* input;
  bool result;
  DNSHeader* dnsHeader;

  input = NULL;
  dnsHeader = new DNSHeader();
  result = dnsHeader->ProcessHeader(input, 0);
  EXPECT_FALSE(result);
  delete dnsHeader;

  input = nullptr;
  dnsHeader = new DNSHeader();
  result = dnsHeader->ProcessHeader(input, 0);
  EXPECT_FALSE(result);
  delete dnsHeader;

  input = nullptr;
  dnsHeader = new DNSHeader();
  result = dnsHeader->ProcessHeader(input, 13);
  EXPECT_FALSE(result);
  delete dnsHeader;

  input = (char* )"";
  dnsHeader = new DNSHeader();
  result = dnsHeader->ProcessHeader(input, 0);
  EXPECT_FALSE(result);
  delete dnsHeader;

  input = (char* )"000000000000";
  dnsHeader = new DNSHeader();
  result = dnsHeader->ProcessHeader(input, 12);
  EXPECT_TRUE(result);
  delete dnsHeader;

  input = (char* )"000\x40""000000000";
  dnsHeader = new DNSHeader();
  result = dnsHeader->ProcessHeader(input, 12);
  EXPECT_FALSE(result);
  delete dnsHeader;
}

} // namespace testing
} // namespace dns_message
