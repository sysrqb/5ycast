#include <memory>

#include "gtest/gtest.h"
#include "mdns_message.h"


namespace dns_message {

namespace testing {

TEST(DNSMessageTest, GetRawMessageReturnsmRawMsg)
{
  char* input;
  std::string result;
  std::string expected;
  std::unique_ptr<DNSMessage> dnsMsg;

  input = (char* )"foo";
  expected = std::string("foo");
  dnsMsg.reset(new DNSMessage(input));
  result = dnsMsg->GetRawMessage();
  EXPECT_EQ(expected, result);
}
  
TEST(DNSMessageTest, GetRawMessageReturnsmRawMsgFoo)
{
  char* input;
  std::string result;
  std::string expected;
  std::unique_ptr<DNSMessage> dnsMsg;

  input = (char* )"foo\0";
  expected = std::string("foo\0", 5);
  dnsMsg.reset(new DNSMessage(input, 5));
  result = dnsMsg->GetRawMessage();
  EXPECT_EQ(expected, result);
}
  
TEST(DNSMessageTest, GetRawMessageReturnsmRawMsgFooAndBar)
{
  char* input;
  std::string result;
  std::string expected;
  std::unique_ptr<DNSMessage> dnsMsg;

  input = (char* )"foo\0bar";
  expected = std::string("foo\0bar", 8);
  dnsMsg.reset(new DNSMessage(input, 8));
  result = dnsMsg->GetRawMessage();
  EXPECT_EQ(expected, result);
}

TEST(DNSMessageTest, ProcessMessageRawMsgEmptyString) {
  char* input;
  bool result;
  std::unique_ptr<DNSMessage> dnsMsg;

  input = (char* )"";
  dnsMsg.reset(new DNSMessage(input));
  result = dnsMsg->ProcessMessage();
  EXPECT_FALSE(result);
}

TEST(DNSMessageTest, ProcessMessageRawMsgLessThan12) {
  char* input;
  bool result;
  std::unique_ptr<DNSMessage> dnsMsg;

  input = (char* )"lessthan12";
  dnsMsg.reset(new DNSMessage(input));
  result = dnsMsg->ProcessMessage();
  EXPECT_FALSE(result);
}

TEST(DNSMessageTest, ProcessMessageRawMsgMoreThan12Foo) {
  char* input;
  bool result;
  std::unique_ptr<DNSMessage> dnsMsg;

  input = (char* )"morethan12foo";
  dnsMsg.reset(new DNSMessage(input));
  result = dnsMsg->ProcessMessage();
  EXPECT_FALSE(result);
}

TEST(DNSMessageTest, ProcessMessageRawMsg12Null) {
  char* input;
  bool result;
  std::unique_ptr<DNSMessage> dnsMsg;

  input = (char* )"\0\0\0\0\0\0\0\0\0\0\0\0";
  dnsMsg.reset(new DNSMessage(input, 12));
  result = dnsMsg->ProcessMessage();
  EXPECT_TRUE(result);
}

TEST(DNSMessageTest, ProcessMessageRawMsg11NullAnd40Z) {
  char* input;
  bool result;
  std::unique_ptr<DNSMessage> dnsMsg;

  input = (char* )"\0\0\0\x40\0\0\0\0\0\0\0\0";
  dnsMsg.reset(new DNSMessage(input, 12));
  result = dnsMsg->ProcessMessage();
  EXPECT_FALSE(result);
}

TEST(DNSMessageTest, ProcessQuestionsHeaderAndQuestion) {
  char* input;
  bool result;
  std::unique_ptr<DNSMessage> dnsMsg;

  input = (char* )"\0\0\0\0\0\x01\0\0\0\0\0\0\x10""0123456789abcdef\0\0\xc\1\0";
  dnsMsg.reset(new DNSMessage(input, 34));
  result = dnsMsg->ProcessMessage();
  EXPECT_TRUE(result);
}

TEST(DNSMessageTest, ProcessQuestionsHeaderAnd2Question) {
  char* input;
  bool result;
  std::unique_ptr<DNSMessage> dnsMsg;

  input = (char* )"\0\0\0\0\0\x01\0\0\0\0\0\0\x02""34\0\0\1\0\0\x10""0123456789abcdef\0\0\xc\1\0";
  dnsMsg.reset(new DNSMessage(input, 42));
  result = dnsMsg->ProcessMessage();
  EXPECT_TRUE(result);
}

TEST(DNSHeaderTest, ProcessHeaderRawMsgNull) {
  char* input;
  bool result;
  std::unique_ptr<DNSHeader> dnsHeader;

  input = NULL;
  dnsHeader.reset(new DNSHeader());
  result = dnsHeader->ProcessHeader(input, 0);
  EXPECT_FALSE(result);
}

TEST(DNSHeaderTest, ProcessHeaderRawMsgNullPtr) {
  char* input;
  bool result;
  std::unique_ptr<DNSHeader> dnsHeader;

  input = nullptr;
  dnsHeader.reset(new DNSHeader());
  result = dnsHeader->ProcessHeader(input, 0);
  EXPECT_FALSE(result);
}

TEST(DNSHeaderTest, ProcessHeaderRawMsgNullPtr13) {
  char* input;
  bool result;
  std::unique_ptr<DNSHeader> dnsHeader;

  input = nullptr;
  dnsHeader.reset(new DNSHeader());
  result = dnsHeader->ProcessHeader(input, 13);
  EXPECT_FALSE(result);
}

TEST(DNSHeaderTest, ProcessHeaderRawMsgEmptyString) {
  char* input;
  bool result;
  std::unique_ptr<DNSHeader> dnsHeader;

  input = (char* )"";
  dnsHeader.reset(new DNSHeader());
  result = dnsHeader->ProcessHeader(input, 0);
  EXPECT_FALSE(result);
}

TEST(DNSHeaderTest, ProcessHeaderRawMsg12Zeroes) {
  char* input;
  bool result;
  std::unique_ptr<DNSHeader> dnsHeader;

  input = (char* )"000000000000";
  dnsHeader.reset(new DNSHeader());
  result = dnsHeader->ProcessHeader(input, 12);
  EXPECT_TRUE(result);
}

TEST(DNSHeaderTest, ProcessHeaderRawMsg11ZeroesAnd40Z) {
  char* input;
  bool result;
  std::unique_ptr<DNSHeader> dnsHeader;

  input = (char* )"000\x40""000000000";
  dnsHeader.reset(new DNSHeader());
  result = dnsHeader->ProcessHeader(input, 12);
  EXPECT_FALSE(result);
}

TEST(DNSHeaderTest, ProcessHeaderRawMsg12Nulls) {
  char* input;
  bool result;
  std::unique_ptr<DNSHeader> dnsHeader;

  input = (char* )"\0\0\0\0\0\0\0\0\0\0\0\0\0";
  dnsHeader.reset(new DNSHeader());
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
}

TEST(DNSHeaderTest, ProcessHeaderRawMsgAllFFExceptZ) {
  char* input;
  bool result;
  std::unique_ptr<DNSHeader> dnsHeader;

  /* If Z is non-zero, we return early */
  input = (char* )"\xff\xff\xff\x80\xff\xff\xff\xff\xff\xff\xff\xff";
  dnsHeader.reset(new DNSHeader());
  result = dnsHeader->ProcessHeader(input, 12);
  EXPECT_TRUE(result);
  EXPECT_EQ((1<<16)-1, dnsHeader->GetMsgID());
  EXPECT_EQ((1<<4)-1, dnsHeader->GetOpCode());
  EXPECT_TRUE(dnsHeader->GetQRField());
  EXPECT_TRUE(dnsHeader->GetAAField());
  EXPECT_TRUE(dnsHeader->GetTCField());
  EXPECT_TRUE(dnsHeader->GetRDField());
  EXPECT_TRUE(dnsHeader->GetRAField());
  EXPECT_EQ(0u, dnsHeader->GetRCode());
  EXPECT_EQ((1<<16)-1, dnsHeader->GetQDCount());
  EXPECT_EQ((1<<16)-1, dnsHeader->GetANCount());
  EXPECT_EQ((1<<16)-1, dnsHeader->GetNSCount());
  EXPECT_EQ((1<<16)-1, dnsHeader->GetARCount());
}

TEST(DNSHeaderTest, ProcessHeaderRawMsgAllFF) {
  char* input;
  bool result;
  std::unique_ptr<DNSHeader> dnsHeader;

  input = (char* )"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";
  dnsHeader.reset(new DNSHeader());
  result = dnsHeader->ProcessHeader(input, 12);
  EXPECT_FALSE(result);
}

TEST(DNSHeaderTest, ProcessHeaderRawMsgSpotted1s) {
  char* input;
  bool result;
  std::unique_ptr<DNSHeader> dnsHeader;

  input = (char* )"\1\0\0\0\0\1\1\0\0\0\0\0\1";
  dnsHeader.reset(new DNSHeader());
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
}

TEST(DNSHeaderTest, ProcessHeaderRawMsgSetIDAndQRAndRDAndQDAndANAndARCounts) {
  char* input;
  bool result;
  std::unique_ptr<DNSHeader> dnsHeader;

  input = (char* )"\0\4\x81""\0\2\0\0\x8""\0\0\1\0\1";
  dnsHeader.reset(new DNSHeader());
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
}

TEST(DNSQuestionTest, ParseQuestionLength1Label2) {
  char* input;
  bool result;
  std::unique_ptr<DNSQuestion> dnsQuestion;
  std::size_t mlen;
  std::size_t offset;

  input = (char* )"12";
  mlen = 2;
  offset = 0;
  dnsQuestion.reset(new DNSQuestion());
  result = dnsQuestion->ProcessQuestion(input, mlen, offset);
  EXPECT_FALSE(result);
}

TEST(DNSQuestionTest, ParseQuestionLength2Label2NullNull) {
  char* input;
  bool result;
  std::unique_ptr<DNSQuestion> dnsQuestion;
  std::size_t mlen;
  std::size_t offset;

  input = (char* )"\x02""2\0\0";
  mlen = 1 + 2 + 2;
  offset = 0;
  dnsQuestion.reset(new DNSQuestion());
  result = dnsQuestion->ProcessQuestion(input, mlen, offset);
  EXPECT_FALSE(result);
}

TEST(DNSQuestionTest, ParseQuestionLength2Label34NullNull) {
  char* input;
  bool result;
  std::unique_ptr<DNSQuestion> dnsQuestion;
  std::size_t mlen;
  std::size_t offset;

  input = (char* )"\x02""34\0\0";
  mlen = 1 + 2 + 2;
  offset = 0;
  dnsQuestion.reset(new DNSQuestion());
  result = dnsQuestion->ProcessQuestion(input, mlen, offset);
  EXPECT_FALSE(result);
}

TEST(DNSQuestionTest, ParseQuestionLength2Label34FourNulls) {
  char* input;
  bool result;
  std::unique_ptr<DNSQuestion> dnsQuestion;
  std::size_t mlen;
  std::size_t offset;

  input = (char* )"\x02""34\0\0\0\0";
  mlen = 1 + 2 + 2 + 2;
  offset = 0;
  dnsQuestion.reset(new DNSQuestion());
  result = dnsQuestion->ProcessQuestion(input, mlen, offset);
  EXPECT_FALSE(result);
}

TEST(DNSQuestionTest, ParseQuestionLength2Label345Nulls) {
  char* input;
  bool result;
  std::unique_ptr<DNSQuestion> dnsQuestion;
  std::size_t mlen;
  std::size_t offset;

  input = (char* )"\x02""34\0\0\0\0\0";
  mlen = 1 + 2 + 1 + 2 + 2;
  offset = 0;
  dnsQuestion.reset(new DNSQuestion());
  result = dnsQuestion->ProcessQuestion(input, mlen, offset);
  EXPECT_TRUE(result);
  EXPECT_EQ(dnsQuestion->GetQNames().at(0), std::string("34"));
  EXPECT_EQ(dnsQuestion->GetQType(), 0);
  EXPECT_EQ(dnsQuestion->GetQClass(), 0);
}

TEST(DNSQuestionTest, ParseQuestionLength2Label34Length0Null1NullNullLength10) {
  char* input;
  bool result;
  std::unique_ptr<DNSQuestion> dnsQuestion;
  std::size_t mlen;
  std::size_t offset;

  input = (char* )"\x02""34\0\0\1\0\0\x10""0123456789abcdef\0\0\xc\0\0";
  mlen = 1 + 2 + 1 + 2 + 2 + 1 + 0x10 + 1 + 2 + 2;
  offset = 0;
  dnsQuestion.reset(new DNSQuestion());
  result = dnsQuestion->ProcessQuestion(input, mlen, offset);
  EXPECT_TRUE(result);
  EXPECT_EQ(dnsQuestion->GetQNames().at(0), std::string("34"));
  EXPECT_EQ(dnsQuestion->GetQType(), 1);
  EXPECT_EQ(dnsQuestion->GetQClass(), 0);
}

TEST(DNSQuestionTest, TwiceIsBetterThanOnce) {
  char* input;
  bool result;
  DNSQuestion dnsQuestion;
  std::size_t mlen;
  std::size_t offset;

  input = const_cast<char*>(
    "\x10""0123456789abcdef\xc0\1\0\xc\1\0"
  );
  mlen = 1 + 0x10 + 2 + 2 + 2;
  offset = 0;
  result = dnsQuestion.ProcessQuestion(input, mlen, offset);
  ASSERT_TRUE(result);
  EXPECT_EQ(dnsQuestion.GetQNames().at(0), std::string("0123456789abcdef"));
  EXPECT_EQ(dnsQuestion.GetQType(), 0x0c);
  EXPECT_EQ(dnsQuestion.GetQClass(), 0x01 << 8);
}

TEST(DNSQuestionTest, TwiceIsBetterThanOnce2) {
  char* input;
  bool result;
  DNSQuestion dnsQuestion;
  std::size_t mlen;
  std::size_t offset;

  input = const_cast<char*>(
    "\x10""0123456789abcdef\0\0\xc\0\1\xc0\1\0\xc\0\1"
  );
  mlen = 1 + 0x10 + 1 + 2 + 2 + 2 + 2 + 2;
  offset = 0;
  result = dnsQuestion.ProcessQuestion(input, mlen, offset);
  EXPECT_TRUE(result);
  EXPECT_EQ(dnsQuestion.GetQNames().at(0), std::string("0123456789abcdef"));
  EXPECT_EQ(dnsQuestion.GetQType(), 0x0c);
  EXPECT_EQ(dnsQuestion.GetQClass(), 0x01);
}

TEST(DNSMessageTest, ProcessQuestionsHeaderAnd2QuestionWithPtr) {
  char* input;
  bool result;
  std::unique_ptr<DNSMessage> dnsMsg;

  input = const_cast<char*>(
    "\0\0\0\0\0\2\0\0\0\0\0\0\x10""0123456789abcdef\0\0\xc\0\1\xc0\1\0\xc\0\1"
  );
  dnsMsg.reset(new DNSMessage(input, 40));
  result = dnsMsg->ProcessMessage();
  EXPECT_TRUE(result);
}

TEST(DNSQuestionTest, ParseQuestionLength2Label345NullsStringify) {
  char* input;
  bool result;
  std::unique_ptr<DNSQuestion> dnsQuestion;
  std::size_t mlen;
  std::size_t offset;

  input = (char* )"\x02""34\0\0\0\0\0";
  mlen = 1 + 2 + 1 + 2 + 2;
  offset = 0;
  dnsQuestion.reset(new DNSQuestion());
  result = dnsQuestion->ProcessQuestion(input, mlen, offset);
  EXPECT_TRUE(result);

  std::string expect{
  "                                1  1  1  1  1  1\n"
  "  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|           2           |           3           |\n"
  "|           4           |           0           |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       0                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       0                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  };
  EXPECT_EQ(expect, dnsQuestion->Stringify());
}

TEST(DNSQuestionTest, ParseQuestion16CharsStringify) {
  char* input;
  bool result;
  std::unique_ptr<DNSQuestion> dnsQuestion;
  std::size_t mlen;
  std::size_t offset;

  input = (char* )"\x10""3456345634563456\0\0\0\0\0";
  mlen = 1 + 16 + 1 + 2 + 2;
  offset = 0;
  dnsQuestion.reset(new DNSQuestion());
  result = dnsQuestion->ProcessQuestion(input, mlen, offset);
  EXPECT_TRUE(result);

  std::string expect{
  "                                1  1  1  1  1  1\n"
  "  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|           16          |           3           |\n"
  "|           4           |           5           |\n"
  "|           6           |           3           |\n"
  "|           4           |           5           |\n"
  "|           6           |           3           |\n"
  "|           4           |           5           |\n"
  "|           6           |           3           |\n"
  "|           4           |           5           |\n"
  "|           6           |           0           |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       0                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       0                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  };
  EXPECT_EQ(expect, dnsQuestion->Stringify());

}

TEST(DNSQuestionTest, ParseQuestion17CharsStringify) {
  char* input;
  bool result;
  std::unique_ptr<DNSQuestion> dnsQuestion;
  std::size_t mlen;
  std::size_t offset;

  input = (char* )"\x11""34563456345634569\0\0\0\0\0";
  mlen = 1 + 17 + 1 + 2 + 2;
  offset = 0;
  dnsQuestion.reset(new DNSQuestion());
  result = dnsQuestion->ProcessQuestion(input, mlen, offset);
  EXPECT_TRUE(result);

  std::string expect{
  "                                1  1  1  1  1  1\n"
  "  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|           17          |           3           |\n"
  "|           4           |           5           |\n"
  "|           6           |           3           |\n"
  "|           4           |           5           |\n"
  "|           6           |           3           |\n"
  "|           4           |           5           |\n"
  "|           6           |           3           |\n"
  "|           4           |           5           |\n"
  "|           6           |           9           |\n"
  "|           0           |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       0                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       0                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  };
  EXPECT_EQ(expect, dnsQuestion->Stringify());
}

TEST(DNSQuestionTest, ParseQuestion2NamesStringify) {
  char* input;
  bool result;
  std::unique_ptr<DNSQuestion> dnsQuestion;
  std::size_t mlen;
  std::size_t offset;

  input = (char* )"\x05""34563""\xc""456345634569\0\0\0\0\0";
  mlen = 1 + 5 + 1+ 12 + 1 + 2 + 2;
  offset = 0;
  dnsQuestion.reset(new DNSQuestion());
  result = dnsQuestion->ProcessQuestion(input, mlen, offset);
  EXPECT_TRUE(result);

  std::string expect{
  "                                1  1  1  1  1  1\n"
  "  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|           5           |           3           |\n"
  "|           4           |           5           |\n"
  "|           6           |           3           |\n"
  "|           12          |           4           |\n"
  "|           5           |           6           |\n"
  "|           3           |           4           |\n"
  "|           5           |           6           |\n"
  "|           3           |           4           |\n"
  "|           5           |           6           |\n"
  "|           9           |           0           |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       0                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       0                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  };
  EXPECT_EQ(expect, dnsQuestion->Stringify());
}

TEST(DNSQuestionTest, ParseQuestionLengthPointerStringify) {
  char* input;
  bool result;
  std::unique_ptr<DNSQuestion> dnsQuestion;
  std::size_t mlen;
  std::size_t offset;

  input = (char* )"\xc0\0\0\0\0\0";
  mlen = 2 + 2 + 2;
  offset = 0;
  dnsQuestion.reset(new DNSQuestion());
  result = dnsQuestion->ProcessQuestion(input, mlen, offset);
  ASSERT_EQ(2u, dnsQuestion->GetQNames().back().size());

  EXPECT_TRUE(result);

  std::string expect{
  "                                1  1  1  1  1  1\n"
  "  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|           C0          |           0           |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       0                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       0                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  };
  EXPECT_EQ(expect, dnsQuestion->Stringify());
}

TEST(DNSRRTest, MalformedEmpty) {
  char* input;
  bool result;
  std::unique_ptr<DNSRR> rr;
  std::size_t mlen;
  std::size_t offset;

  input = (char* )"";
  mlen = 0;
  offset = 0;
  rr.reset(new DNSRR());
  result = rr->ProcessRR(input, mlen, offset);
  EXPECT_FALSE(result);
}

TEST(DNSRRTest, MalformedTooShort) {
  char* input;
  bool result;
  std::unique_ptr<DNSRR> rr;
  std::size_t mlen;
  std::size_t offset;

  input = const_cast<char*>("\x00\x01\x02\x03");
  mlen = 4;
  offset = 0;
  rr.reset(new DNSRR());
  result = rr->ProcessRR(input, mlen, offset);
  EXPECT_FALSE(result);
}

TEST(DNSRRTest, MalformedTooShort2) {
  char* input;
  bool result;
  std::unique_ptr<DNSRR> rr;
  std::size_t mlen;
  std::size_t offset;

  input = const_cast<char*>("\x01\x01\x02\x02\x03\x03\x04\x04\x05\x05");
  mlen = 10;
  offset = 0;
  rr.reset(new DNSRR());
  result = rr->ProcessRR(input, mlen, offset);
  EXPECT_FALSE(result);
}

TEST(DNSRRTest, MissingRData) {
  char* input;
  bool result;
  std::unique_ptr<DNSRR> rr;
  std::size_t mlen;
  std::size_t offset;

  input = const_cast<char*>("\x00\x01\x02\x02\x03\x03\x04\x04\x05\x05\x06");
  mlen = 11;
  offset = 0;
  rr.reset(new DNSRR());
  result = rr->ProcessRR(input, mlen, offset);
  EXPECT_FALSE(result);
}

TEST(DNSRRTest, MalformedRData) {
  char* input;
  bool result;
  std::unique_ptr<DNSRR> rr;
  std::size_t mlen;
  std::size_t offset;

  input = const_cast<char*>("\x01\x41\x00\x0c\x00\x01\x00\x00\x00\x05\x06");
  mlen = 11;
  offset = 0;
  rr.reset(new DNSRR());
  result = rr->ProcessRR(input, mlen, offset);
  EXPECT_FALSE(result);
}

TEST(DNSRRTest, MalformedRData2) {
  char* input;
  bool result;
  std::unique_ptr<DNSRR> rr;
  std::size_t mlen;
  std::size_t offset;

  input = const_cast<char*>("\x01\x41\x00\x0c\x00\x01\x00\x00\x00\x05\x01\x02\x03\x04");
  mlen = 15;
  offset = 0;
  rr.reset(new DNSRR());
  result = rr->ProcessRR(input, mlen, offset);
  EXPECT_FALSE(result);
}

TEST(DNSRRTest, MalformedRData3) {
  char* input;
  bool result;
  std::unique_ptr<DNSRR> rr;
  std::size_t mlen;
  std::size_t offset;

  input = const_cast<char*>("\x01\x41\x00\x0c\x00\x01\x00\x00\x00\x05\x04\x01\x02\x03\x04\x01");
  mlen = 16;
  offset = 0;
  rr.reset(new DNSRR());
  result = rr->ProcessRR(input, mlen, offset);
  EXPECT_FALSE(result);
}

TEST(DNSRRTest, MalformedRData4) {
  char* input;
  bool result;
  std::unique_ptr<DNSRR> rr;
  std::size_t mlen;
  std::size_t offset;

  input = const_cast<char*>("\x01\x41\x00\x00\x0c\x00\x01\x00\x00\x00\x04\x06\x04\x01\x02\x03\x04");
  mlen = 17;
  offset = 0;
  rr.reset(new DNSRR());
  result = rr->ProcessRR(input, mlen, offset);
  ASSERT_FALSE(result);
}

TEST(DNSRRTest, MalformedRData5) {
  char* input;
  bool result;
  std::unique_ptr<DNSRR> rr;
  std::size_t mlen;
  std::size_t offset;

  input = const_cast<char*>("\x01\x41\x00\x0c\x00\x01\x00\x00\x00\x04\x06\x04\x01\x02\x03\x04\x00");
  mlen = 17;
  offset = 0;
  rr.reset(new DNSRR());
  result = rr->ProcessRR(input, mlen, offset);
  ASSERT_FALSE(result);
}

TEST(DNSRRTest, MalformedRData6) {
  char* input;
  bool result;
  std::unique_ptr<DNSRR> rr;
  std::size_t mlen;
  std::size_t offset;

  input = const_cast<char*>("\x01\x41\x00\x0c\x00\x01\x00\x00\x00\x04\x06\x04\x01\x02\x03\x04");
  mlen = 16;
  offset = 0;
  rr.reset(new DNSRR());
  result = rr->ProcessRR(input, mlen, offset);
  ASSERT_FALSE(result);
}

TEST(DNSRRTest, WellformedRData) {
  char* input;
  bool result;
  std::unique_ptr<DNSRR> rr;
  std::size_t mlen;
  std::size_t offset;

  input = const_cast<char*>("\x01\x41\x00\x00\x0c\x00\x01\x00\x00\x00\x04\x00\x06\x04\x01\x02\x03\x04\x00");
  mlen = 19;
  offset = 0;
  rr.reset(new DNSRR());
  result = rr->ProcessRR(input, mlen, offset);
  ASSERT_TRUE(result);
  ASSERT_EQ(rr->GetName().size(), 1u);
  EXPECT_EQ(rr->GetName().at(0), std::string("A", 1));
  EXPECT_EQ(rr->GetRRType(), 0x0c);
  EXPECT_EQ(rr->GetRRClass(), 0x01);
  EXPECT_EQ(rr->GetTTL(), 0x04);
  EXPECT_EQ(rr->GetRDLength(), 0x06);
  const DNSPtrRData* ptr = static_cast<const DNSPtrRData*>(rr->GetRData());
  ASSERT_EQ(ptr->GetDName().size(), 1u);
  EXPECT_EQ(ptr->GetDName().at(0), std::string("\x01\x02\x03\x04", 4));
}

TEST(NameCompression, BadLength) {
  char* input;
  std::string compressedname;
  std::string uncompname;
  std::size_t mlen;

  input = const_cast<char*>("\x05\x00\x00\xc0\x00");
  compressedname.assign(input + 3, 2);
  mlen = 5;
  ASSERT_FALSE(DNSMessage::DecompressName(input, mlen, compressedname, uncompname));
}

TEST(NameCompression, BadLength2) {
  char* input;
  std::string compressedname;
  std::string uncompname;
  std::size_t mlen;

  input = const_cast<char*>("\x06\x02\x03\xc0\x00\x00");
  compressedname.assign(input + 3, 2);
  mlen = 6;
  ASSERT_FALSE(DNSMessage::DecompressName(input, mlen, compressedname, uncompname));
}

TEST(NameCompression, BadOffset) {
  char* input;
  std::string compressedname;
  std::string uncompname;
  std::size_t mlen;

  input = const_cast<char*>("\x05\x00\x00\xc0\x09");
  compressedname.assign(input + 3, 2);
  mlen = 5;
  ASSERT_FALSE(DNSMessage::DecompressName(input, mlen, compressedname, uncompname));
}

TEST(NameCompression, SmallOffset) {
  char* input;
  std::string expect;
  std::string compressedname;
  std::string uncompname;
  std::size_t mlen;

  input = const_cast<char*>("\x00\x00\x00\xc0\x00\x00");
  expect = "";
  compressedname.assign(input + 3, 2);
  mlen = 6;
  ASSERT_TRUE(DNSMessage::DecompressName(input, mlen, compressedname, uncompname));
  EXPECT_EQ(expect, uncompname);
}

TEST(NameCompression, SmallOffset2) {
  char* input;
  std::string expect;
  std::string compressedname;
  std::string uncompname;
  std::size_t mlen;

  input = const_cast<char*>("\x00\x00\x00\xc0\x02\x00");
  expect = "";
  compressedname.assign(input + 3, 2);
  mlen = 6;
  ASSERT_TRUE(DNSMessage::DecompressName(input, mlen, compressedname, uncompname));
  EXPECT_EQ(expect, uncompname);
}

TEST(NameCompression, LessSmallOffset) {
  char* input;
  std::string expect;
  std::string compressedname;
  std::string uncompname;
  std::size_t mlen;

  input = const_cast<char*>("\x00\x00\x00\x00\x00\x03\x46\x4F\x4F\x00\x00\x00\x00\xc0\x05\x00");
  expect = "FOO";
  compressedname.assign(input + 13, 2);
  mlen = 16;
  ASSERT_TRUE(DNSMessage::DecompressName(input, mlen, compressedname, uncompname));
  EXPECT_EQ(expect, uncompname);
}

TEST(HeaderStringifyTest, Format) {
  char* input;
  bool result;
  std::unique_ptr<DNSHeader> dnsHeader;

  input = (char* )"\0\0\0\0\0\0\0\0\0\0\0\0\0";
  dnsHeader.reset(new DNSHeader());
  result = dnsHeader->ProcessHeader(input, 12);
  ASSERT_TRUE(result);
  std::string expect{
  "                                1  1  1  1  1  1\n"
  "  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       0                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "| 0|     0     | 0| 0| 0| 0| 0| 0| 0|     0     |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       0                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       0                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       0                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       0                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  };
  EXPECT_EQ(expect, dnsHeader->Stringify());
}

TEST(HeaderStringifyTest, Format1) {
  char* input;
  bool result;
  std::unique_ptr<DNSHeader> dnsHeader;

  input = (char* )"\0\1\1\0\1\0\0\0\0\0\0\0\0";
  dnsHeader.reset(new DNSHeader());
  result = dnsHeader->ProcessHeader(input, 12);
  ASSERT_TRUE(result);
  std::string expect{
  "                                1  1  1  1  1  1\n"
  "  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       1                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "| 0|     0     | 0| 0| 1| 0| 0| 0| 0|     0     |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                      256                      |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       0                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       0                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       0                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  };
  EXPECT_EQ(expect, dnsHeader->Stringify());
}

TEST(HeaderStringifyTest, Format2) {
  char* input;
  bool result;
  std::unique_ptr<DNSHeader> dnsHeader;

  input = (char* )"\0\1\201\200\1\0\0\2\0\0\1\1";
  dnsHeader.reset(new DNSHeader());
  result = dnsHeader->ProcessHeader(input, 13);
  ASSERT_TRUE(result);
  std::string expect{
  "                                1  1  1  1  1  1\n"
  "  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       1                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "| 1|     0     | 0| 0| 1| 1| 0| 0| 0|     0     |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                      256                      |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       2                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       0                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                      257                      |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  };
  EXPECT_EQ(expect, dnsHeader->Stringify());
}

TEST(DNSMessageStringifyTest, Format1Question) {
  char* input;
  bool result;
  std::unique_ptr<DNSMessage> dnsMsg;

  input = const_cast<char*>(
    "\0\1\1\0\0\1\0\0\0\0\0\0"
    "\x10""3456345634563456\0\0\xc\0\1"
  );

  dnsMsg.reset(new DNSMessage(input, 12 + 22));
  result = dnsMsg->ProcessMessage();
  ASSERT_TRUE(result);
  std::string expect{
  "                                1  1  1  1  1  1\n"
  "  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       1                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "| 0|     0     | 0| 0| 1| 0| 0| 0| 0|     0     |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       1                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       0                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       0                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       0                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "                                1  1  1  1  1  1\n"
  "  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|           16          |           3           |\n"
  "|           4           |           5           |\n"
  "|           6           |           3           |\n"
  "|           4           |           5           |\n"
  "|           6           |           3           |\n"
  "|           4           |           5           |\n"
  "|           6           |           3           |\n"
  "|           4           |           5           |\n"
  "|           6           |           0           |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       12                      |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       1                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  };
  EXPECT_EQ(expect, dnsMsg->Stringify());
}

TEST(DNSMessageStringifyTest, Format3Questions) {
  char* input;
  bool result;
  std::unique_ptr<DNSMessage> dnsMsg;

  input = const_cast<char*>(
    "\0\1\1\0\0\3\0\0\0\0\0\0"
    "\x10""3456345634563456\0\0\xc\0\1"
    "\3""345\0\0\xc\0\1"
    "\xc0\xd\0\xc\0\1"
  );

  dnsMsg.reset(new DNSMessage(input, 12 + 22 + 9 + 6));
  result = dnsMsg->ProcessMessage();
  ASSERT_TRUE(result);
  std::string expect{
  "                                1  1  1  1  1  1\n"
  "  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       1                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "| 0|     0     | 0| 0| 1| 0| 0| 0| 0|     0     |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       3                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       0                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       0                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       0                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "                                1  1  1  1  1  1\n"
  "  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|           16          |           3           |\n"
  "|           4           |           5           |\n"
  "|           6           |           3           |\n"
  "|           4           |           5           |\n"
  "|           6           |           3           |\n"
  "|           4           |           5           |\n"
  "|           6           |           3           |\n"
  "|           4           |           5           |\n"
  "|           6           |           0           |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       12                      |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       1                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "                                1  1  1  1  1  1\n"
  "  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|           3           |           3           |\n"
  "|           4           |           5           |\n"
  "|           0           |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       12                      |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       1                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "                                1  1  1  1  1  1\n"
  "  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|           C0          |           13          |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       12                      |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       1                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  };
  EXPECT_EQ(expect, dnsMsg->Stringify());
  //"|           0           |\n"
}

TEST(DNSMessageStringifyTest, Format1QuestionWithPointer) {
  char* input;
  bool result;
  std::unique_ptr<DNSMessage> dnsMsg;

  input = const_cast<char*>(
    "\0\1\1\0\0\1\0\0\0\0\0\0"
    "\xc0\xd\0\xc\0\1"
  );

  dnsMsg.reset(new DNSMessage(input, 12 + 6));
  result = dnsMsg->ProcessMessage();
  ASSERT_TRUE(result);
  std::string expect{
  "                                1  1  1  1  1  1\n"
  "  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       1                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "| 0|     0     | 0| 0| 1| 0| 0| 0| 0|     0     |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       1                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       0                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       0                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       0                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "                                1  1  1  1  1  1\n"
  "  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|           C0          |           13          |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       12                      |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  "|                       1                       |\n"
  "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+\n"
  };
  EXPECT_EQ(expect, dnsMsg->Stringify());
}


} // namespace testing
} // namespace dns_message
