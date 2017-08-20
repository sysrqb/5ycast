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

  input = (char* )"\0\0\0\0\0\0\0\0\0\0\0\0\0";
  dnsHeader = new DNSHeader();
  result = dnsHeader->ProcessHeader(input, 12);
  EXPECT_TRUE(result);
  EXPECT_EQ(0, dnsHeader->GetMsgID());
  EXPECT_EQ(0, dnsHeader->GetOpCode());
  EXPECT_FALSE(dnsHeader->GetQRField());
  EXPECT_FALSE(dnsHeader->GetAAField());
  EXPECT_FALSE(dnsHeader->GetTCField());
  EXPECT_FALSE(dnsHeader->GetRDField());
  EXPECT_FALSE(dnsHeader->GetRAField());
  EXPECT_EQ(0, dnsHeader->GetRCode());
  EXPECT_EQ(0, dnsHeader->GetQDCount());
  EXPECT_EQ(0, dnsHeader->GetANCount());
  EXPECT_EQ(0, dnsHeader->GetNSCount());
  EXPECT_EQ(0, dnsHeader->GetARCount());
  delete dnsHeader;

  /* If Z is non-zero, we return early */
  input = (char* )"\xff\xff\xff\x8f\xff\xff\xff\xff\xff\xff\xff\xff";
  dnsHeader = new DNSHeader();
  result = dnsHeader->ProcessHeader(input, 12);
  EXPECT_TRUE(result);
  EXPECT_EQ((1<<16)-1, dnsHeader->GetMsgID());
  EXPECT_EQ((1<<4)-1, dnsHeader->GetOpCode());
  EXPECT_TRUE(dnsHeader->GetQRField());
  EXPECT_TRUE(dnsHeader->GetAAField());
  EXPECT_TRUE(dnsHeader->GetTCField());
  EXPECT_TRUE(dnsHeader->GetRDField());
  EXPECT_TRUE(dnsHeader->GetRAField());
  EXPECT_EQ((1<<4)-1, dnsHeader->GetRCode());
  EXPECT_EQ((1<<16)-1, dnsHeader->GetQDCount());
  EXPECT_EQ((1<<16)-1, dnsHeader->GetANCount());
  EXPECT_EQ((1<<16)-1, dnsHeader->GetNSCount());
  EXPECT_EQ((1<<16)-1, dnsHeader->GetARCount());
  delete dnsHeader;

  input = (char* )"\1\0\0\0\0\1\1\0\0\0\0\0\1";
  dnsHeader = new DNSHeader();
  result = dnsHeader->ProcessHeader(input, 12);
  EXPECT_TRUE(result);
  EXPECT_EQ(256, dnsHeader->GetMsgID());
  EXPECT_EQ(0, dnsHeader->GetOpCode());
  EXPECT_FALSE(dnsHeader->GetQRField());
  EXPECT_FALSE(dnsHeader->GetAAField());
  EXPECT_FALSE(dnsHeader->GetTCField());
  EXPECT_FALSE(dnsHeader->GetRDField());
  EXPECT_FALSE(dnsHeader->GetRAField());
  EXPECT_EQ(0, dnsHeader->GetRCode());
  EXPECT_EQ(1, dnsHeader->GetQDCount());
  EXPECT_EQ(256, dnsHeader->GetANCount());
  EXPECT_EQ(0, dnsHeader->GetNSCount());
  EXPECT_EQ(0, dnsHeader->GetARCount());
  delete dnsHeader;

  input = (char* )"\0\4\x81""\0\2\0\0\x8""\0\0\1\0\1";
  dnsHeader = new DNSHeader();
  result = dnsHeader->ProcessHeader(input, 12);
  EXPECT_TRUE(result);
  EXPECT_EQ(4, dnsHeader->GetMsgID());
  EXPECT_EQ(0, dnsHeader->GetOpCode());
  EXPECT_TRUE(dnsHeader->GetQRField());
  EXPECT_FALSE(dnsHeader->GetAAField());
  EXPECT_FALSE(dnsHeader->GetTCField());
  EXPECT_TRUE(dnsHeader->GetRDField());
  EXPECT_FALSE(dnsHeader->GetRAField());
  EXPECT_EQ(0, dnsHeader->GetRCode());
  EXPECT_EQ(512, dnsHeader->GetQDCount());
  EXPECT_EQ(8, dnsHeader->GetANCount());
  EXPECT_EQ(0, dnsHeader->GetNSCount());
  EXPECT_EQ(256, dnsHeader->GetARCount());
  delete dnsHeader;
}

} // namespace testing
} // namespace dns_message
