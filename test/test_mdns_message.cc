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
}
  
TEST(DNSMessageTest, GetRawMessageReturnsmRawMsgFoo)
{
  char* input;
  std::string result;
  std::string expected;
  DNSMessage* dnsMsg;

  input = (char* )"foo\0";
  expected = std::string("foo\0", 5);
  dnsMsg = new DNSMessage(input, 5);
  result = dnsMsg->GetRawMessage();
  EXPECT_EQ(expected, result);
  delete dnsMsg;
}
  
TEST(DNSMessageTest, GetRawMessageReturnsmRawMsgFooAndBar)
{
  char* input;
  std::string result;
  std::string expected;
  DNSMessage* dnsMsg;

  input = (char* )"foo\0bar";
  expected = std::string("foo\0bar", 8);
  dnsMsg = new DNSMessage(input, 8);
  result = dnsMsg->GetRawMessage();
  EXPECT_EQ(expected, result);
  delete dnsMsg;
}

TEST(DNSMessageTest, ProcessMessageRawMsgEmptyString) {
  char* input;
  bool result;
  DNSMessage* dnsMsg;

  input = (char* )"";
  dnsMsg = new DNSMessage(input);
  result = dnsMsg->ProcessMessage();
  EXPECT_FALSE(result);
  delete dnsMsg;
}

TEST(DNSMessageTest, ProcessMessageRawMsgLessThan12) {
  char* input;
  bool result;
  DNSMessage* dnsMsg;

  input = (char* )"lessthan12";
  dnsMsg = new DNSMessage(input);
  result = dnsMsg->ProcessMessage();
  EXPECT_FALSE(result);
  delete dnsMsg;
}

TEST(DNSMessageTest, ProcessMessageRawMsgMoreThan12Foo) {
  char* input;
  bool result;
  DNSMessage* dnsMsg;

  input = (char* )"morethan12foo";
  dnsMsg = new DNSMessage(input);
  result = dnsMsg->ProcessMessage();
  EXPECT_FALSE(result);
  delete dnsMsg;
}

TEST(DNSMessageTest, ProcessMessageRawMsg12Null) {
  char* input;
  bool result;
  DNSMessage* dnsMsg;

  input = (char* )"\0\0\0\0\0\0\0\0\0\0\0\0";
  dnsMsg = new DNSMessage(input, 12);
  result = dnsMsg->ProcessMessage();
  EXPECT_TRUE(result);
  delete dnsMsg;
}

TEST(DNSMessageTest, ProcessMessageRawMsg11NullAnd40Z) {
  char* input;
  bool result;
  DNSMessage* dnsMsg;

  input = (char* )"\0\0\0\x40\0\0\0\0\0\0\0\0";
  dnsMsg = new DNSMessage(input, 12);
  result = dnsMsg->ProcessMessage();
  EXPECT_FALSE(result);
  delete dnsMsg;
}

TEST(DNSMessageTest, ProcessQuestionsHeaderAndQuestion) {
  char* input;
  bool result;
  DNSMessage* dnsMsg;

  input = (char* )"\0\0\0\0\0\x01\0\0\0\0\0\0\x10""0123456789abcdef\0\0\xc\1\0";
  dnsMsg = new DNSMessage(input, 34);
  result = dnsMsg->ProcessMessage();
  EXPECT_TRUE(result);
  delete dnsMsg;
}

TEST(DNSMessageTest, ProcessQuestionsHeaderAnd2Question) {
  char* input;
  bool result;
  DNSMessage* dnsMsg;

  input = (char* )"\0\0\0\0\0\x01\0\0\0\0\0\0\x02""34\0\0\1\0\0\x10""0123456789abcdef\0\0\xc\1\0";
  dnsMsg = new DNSMessage(input, 42);
  result = dnsMsg->ProcessMessage();
  EXPECT_TRUE(result);
  delete dnsMsg;
}

TEST(DNSHeaderTest, ProcessHeaderRawMsgNull) {
  char* input;
  bool result;
  DNSHeader* dnsHeader;

  input = NULL;
  dnsHeader = new DNSHeader();
  result = dnsHeader->ProcessHeader(input, 0);
  EXPECT_FALSE(result);
  delete dnsHeader;
}

TEST(DNSHeaderTest, ProcessHeaderRawMsgNullPtr) {
  char* input;
  bool result;
  DNSHeader* dnsHeader;

  input = nullptr;
  dnsHeader = new DNSHeader();
  result = dnsHeader->ProcessHeader(input, 0);
  EXPECT_FALSE(result);
  delete dnsHeader;
}

TEST(DNSHeaderTest, ProcessHeaderRawMsgNullPtr13) {
  char* input;
  bool result;
  DNSHeader* dnsHeader;

  input = nullptr;
  dnsHeader = new DNSHeader();
  result = dnsHeader->ProcessHeader(input, 13);
  EXPECT_FALSE(result);
  delete dnsHeader;
}

TEST(DNSHeaderTest, ProcessHeaderRawMsgEmptyString) {
  char* input;
  bool result;
  DNSHeader* dnsHeader;

  input = (char* )"";
  dnsHeader = new DNSHeader();
  result = dnsHeader->ProcessHeader(input, 0);
  EXPECT_FALSE(result);
  delete dnsHeader;
}

TEST(DNSHeaderTest, ProcessHeaderRawMsg12Zeroes) {
  char* input;
  bool result;
  DNSHeader* dnsHeader;

  input = (char* )"000000000000";
  dnsHeader = new DNSHeader();
  result = dnsHeader->ProcessHeader(input, 12);
  EXPECT_TRUE(result);
  delete dnsHeader;
}

TEST(DNSHeaderTest, ProcessHeaderRawMsg11ZeroesAnd40Z) {
  char* input;
  bool result;
  DNSHeader* dnsHeader;

  input = (char* )"000\x40""000000000";
  dnsHeader = new DNSHeader();
  result = dnsHeader->ProcessHeader(input, 12);
  EXPECT_FALSE(result);
  delete dnsHeader;
}

TEST(DNSHeaderTest, ProcessHeaderRawMsg12Nulls) {
  char* input;
  bool result;
  DNSHeader* dnsHeader;

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
}

TEST(DNSHeaderTest, ProcessHeaderRawMsgAllFFExceptZ) {
  char* input;
  bool result;
  DNSHeader* dnsHeader;

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
}

TEST(DNSHeaderTest, ProcessHeaderRawMsgAllFF) {
  char* input;
  bool result;
  DNSHeader* dnsHeader;

  input = (char* )"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";
  dnsHeader = new DNSHeader();
  result = dnsHeader->ProcessHeader(input, 12);
  EXPECT_FALSE(result);
  delete dnsHeader;
}

TEST(DNSHeaderTest, ProcessHeaderRawMsgSpotted1s) {
  char* input;
  bool result;
  DNSHeader* dnsHeader;

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
}

TEST(DNSHeaderTest, ProcessHeaderRawMsgSetIDAndQRAndRDAndQDAndANAndARCounts) {
  char* input;
  bool result;
  DNSHeader* dnsHeader;

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

TEST(DNSQuestionTest, ParseQuestionLength1Label2) {
  char* input;
  bool result;
  DNSQuestion* dnsQuestion;
  std::size_t mlen;
  std::size_t offset;

  input = (char* )"12";
  mlen = 2;
  offset = 0;
  dnsQuestion = new DNSQuestion();
  result = dnsQuestion->ProcessQuestion(input, mlen, offset);
  EXPECT_FALSE(result);
  delete dnsQuestion;
}

TEST(DNSQuestionTest, ParseQuestionLength2Label2NullNull) {
  char* input;
  bool result;
  DNSQuestion* dnsQuestion;
  std::size_t mlen;
  std::size_t offset;

  input = (char* )"\x02""2\0\0";
  mlen = 1 + 2 + 2;
  offset = 0;
  dnsQuestion = new DNSQuestion();
  result = dnsQuestion->ProcessQuestion(input, mlen, offset);
  EXPECT_FALSE(result);
  delete dnsQuestion;
}

TEST(DNSQuestionTest, ParseQuestionLength2Label34NullNull) {
  char* input;
  bool result;
  DNSQuestion* dnsQuestion;
  std::size_t mlen;
  std::size_t offset;

  input = (char* )"\x02""34\0\0";
  mlen = 1 + 2 + 2;
  offset = 0;
  dnsQuestion = new DNSQuestion();
  result = dnsQuestion->ProcessQuestion(input, mlen, offset);
  EXPECT_FALSE(result);
  delete dnsQuestion;
}

TEST(DNSQuestionTest, ParseQuestionLength2Label34FourNulls) {
  char* input;
  bool result;
  DNSQuestion* dnsQuestion;
  std::size_t mlen;
  std::size_t offset;

  input = (char* )"\x02""34\0\0\0\0";
  mlen = 1 + 2 + 2 + 2;
  offset = 0;
  dnsQuestion = new DNSQuestion();
  result = dnsQuestion->ProcessQuestion(input, mlen, offset);
  EXPECT_FALSE(result);
  delete dnsQuestion;
}

TEST(DNSQuestionTest, ParseQuestionLength2Label345Nulls) {
  char* input;
  bool result;
  DNSQuestion* dnsQuestion;
  std::size_t mlen;
  std::size_t offset;

  input = (char* )"\x02""34\0\0\0\0\0";
  mlen = 1 + 2 + 1 + 2 + 2;
  offset = 0;
  dnsQuestion = new DNSQuestion();
  result = dnsQuestion->ProcessQuestion(input, mlen, offset);
  EXPECT_TRUE(result);
  EXPECT_EQ(dnsQuestion->GetQNames().at(0), std::string("34"));
  EXPECT_EQ(dnsQuestion->GetQCode(), 0);
  EXPECT_EQ(dnsQuestion->GetQClass(), 0);
  delete dnsQuestion;
}

TEST(DNSQuestionTest, ParseQuestionLength2Label34Length0Null1NullNullLength10) {
  char* input;
  bool result;
  DNSQuestion* dnsQuestion;
  std::size_t mlen;
  std::size_t offset;

  input = (char* )"\x02""34\0\0\1\0\0\x10""0123456789abcdef\0\0\xc\0\0";
  mlen = 1 + 2 + 1 + 2 + 2 + 1 + 0x10 + 1 + 2 + 2;
  offset = 0;
  dnsQuestion = new DNSQuestion();
  result = dnsQuestion->ProcessQuestion(input, mlen, offset);
  EXPECT_TRUE(result);
  EXPECT_EQ(dnsQuestion->GetQNames().at(0), std::string("34"));
  EXPECT_EQ(dnsQuestion->GetQCode(), 1);
  EXPECT_EQ(dnsQuestion->GetQClass(), 0);
  delete dnsQuestion;
}

TEST(DNSQuestionTest, ParseQuestionLength0x10label2Nulls0xc1Null) {
  char* input;
  bool result;
  DNSQuestion* dnsQuestion;
  std::size_t mlen;
  std::size_t offset;

  input = (char* )"\x10""0123456789abcdef\0\0\xc\1\0";
  mlen = 1 + 0x10 + 1 + 2 + 2;
  offset = 0;
  dnsQuestion = new DNSQuestion();
  result = dnsQuestion->ProcessQuestion(input, mlen, offset);
  EXPECT_TRUE(result);
  EXPECT_EQ(dnsQuestion->GetQNames().at(0), std::string("0123456789abcdef"));
  EXPECT_EQ(dnsQuestion->GetQCode(), 0x0c);
  EXPECT_EQ(dnsQuestion->GetQClass(), 0x01 << 8);
  delete dnsQuestion;
}

} // namespace testing
} // namespace dns_message
