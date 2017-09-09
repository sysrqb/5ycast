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

#ifndef MDNS_MESSAGE_H
#define MDNS_MESSAGE_H

#include <memory>
#include <string>
#include <vector>

namespace dns_message {

class DNSHeader;
class DNSQuestion;
class DNSRR;
class DNSRData;
class DNSPtrRData;
class DNSMessage;

class DNSHeader {
private:
  /* The header contains the following fields:

                                  1  1  1  1  1  1
    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                      ID                       |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                    QDCOUNT                    |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                    ANCOUNT                    |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                    NSCOUNT                    |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                    ARCOUNT                    |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  */

  /* RFC 1035:
       A 16 bit identifier assigned by the program that generates any
       kind of query. This identifier is copied the corresponding
       reply and can be used by the requester to match up replies to
       outstanding queries.

     RFC 6762:
       In multicast query messages, the Query Identifier SHOULD be
       set to zero on transmission.

       In multicast responses, including unsolicited multicast
       responses, the Query Identifier MUST be set to zero on
       transmission, and MUST be ignored on reception.

       In legacy unicast response messages generated specifically in
       response to a particular (unicast or multicast) query, the
       Query Identifier MUST match the ID from the query message.
  */
  std::uint16_t mMsgID;

  /* Fields opcode and qr_field are in opposite order for
     convenience only */
  /* RFC 1035:
       A four bit field that specifies kind of query in this
       message. This value is set by the originator of a query
       and copied into the response. The values are:

         0      a standard query (QUERY)
         1      an inverse query (IQUERY)
         2      a server status request (STATUS)
         3-15   reserved for future use

     RFC 6762:
       In both multicast query and multicast response messages, the
       OPCODE MUST be zero on transmission (only standard queries
       are currently supported over multicast).  Multicast DNS
       messages received with an OPCODE other than zero MUST be
       silently ignored.
    */
  std::uint16_t mOpCode;

  struct {
    /* RFC 1035:
         A one bit field that specifies whether this message is a
         query (0), or a response (1).

       RFC 6762:
         In query messages the QR bit MUST be zero.
         In response messages the QR bit MUST be one.
    */
    bool mQRField:1;

    /* RFC 1035:
         Authoritative Answer - this bit is valid in responses,
         and specifies that the responding name server is an
         authority for the domain name in question section.

         Note that the contents of the answer section may have
         multiple owner names because of aliases. The AA bit
         corresponds to the name which matches the query name, or
         the first owner name in the answer section.

       RFC 6762:
         In query messages, the Authoritative Answer bit MUST be zero
         on transmission, and MUST be ignored on reception.

         In response messages for Multicast domains, the
         Authoritative Answer bit MUST be set to one (not setting
         this bit would imply there's some other place where "better"
         information may be found) and MUST be ignored on reception.
    */
    bool mAAField:1;

    /* RFC 1035:
         TrunCation - specifies that this message was truncated
         due to length greater than that permitted on the
         transmission channel.

       RFC 6762:
         In query messages, if the TC bit is set, it means that
         additional Known-Answer records may be following shortly.
         A responder SHOULD record this fact, and wait for those
         additional Known-Answer records, before deciding whether to
         respond. If the TC bit is clear, it means that the querying
         host has no additional Known Answers.

         In multicast response messages, the TC bit MUST be zero on
         transmission, and MUST be ignored on reception.

         In legacy unicast response messages, the TC bit has the same
         meaning as in conventional Unicast DNS: it means that the
         response was too large to fit in a single packet, so the
         querier SHOULD reissue its query using TCP in order to
         receive the larger response.
    */
    bool mTCField:1;

    /* RFC 1035:
         Recursion Desired - this bit may be set in a query and
         is copied into the response. If RD is set, it directs
         the name server to pursue the query recursively.
         Recursive query support is optional.

       RFC 6762:
         In both multicast query and multicast response messages, the
         Recursion Desired bit SHOULD be zero on transmission, and
         MUST be ignored on reception.
    */
    bool mRDField:1;

    /* RFC 1035:
         Recursion Available - this be is set or cleared in a
         response, and denotes whether recursive query support is
         available in the name server.

       RFC 6762:
         In both multicast query and multicast response messages, the
         Recursion Available bit MUST be zero on transmission, and
         MUST be ignored on reception.
    */
    bool mRAField:1;
  } mBits;

  /* We assert this field is zero. */
  /* RFC 1035:
       Reserved for future use. Must be zero in all queries
       and responses.

     RFC 6762:
       In both query and response messages, the Zero bit MUST be
       zero on transmission, and MUST be ignored on reception.

       AD (Authentic Data) Bit
       In both multicast query and multicast response messages, the
       Authentic Data bit [RFC2535] MUST be zero on transmission,
       and MUST be ignored on reception.

       CD (Checking Disabled) Bit
       In both multicast query and multicast response messages, the
       Checking Disabled bit [RFC2535] MUST be zero on transmission,
       and MUST be ignored on reception.

     RFC 2535:
       Two previously unused bits are allocated out of the DNS
       query/response format header. The AD (authentic data) bit
       indicates in a response that all the data included in the
       answer and authority portion of the response has been
       authenticated by the server according to the policies of that
       server. The CD (checking disabled) bit indicates in a query
       that Pending (non-authenticated) data is acceptable to the
       resolver sending the query.
          +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
          |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
          +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  */
  const std::uint8_t mkZField = 0;

  /* RFC 1035:
       Response code - this 4 bit field is set as part of responses.
       The values have the following interpretation:
         0               No error condition
         1               Format error
         2               Server failure
         3               Name Error
         4               Not Implemented
         5               Refused
         6-15            Reserved for future use.

     RFC 6762:
       In both multicast query and multicast response messages, the
       Response Code MUST be zero on transmission. Multicast DNS
       messages received with non-zero Response Codes MUST be
       silently ignored.
  */
  std::uint8_t mRcode;

  /* RFC 1035:
       an unsigned 16 bit integer specifying the number of entries
       in the question section.
  */
  std::uint16_t mQDCount;

  /* an unsigned 16 bit integer specifying the number of resource
     records in the answer section.
  */
  std::uint16_t mANCount;

  /* an unsigned 16 bit integer specifying the number of name server
     resource records in the authority records section.
  */
  std::uint16_t mNSCount;

  /* an unsigned 16 bit integer specifying the number of resource
     records in the additional records section.
  */
  std::uint16_t mARCount;

public:
  DNSHeader() = default;
  bool ProcessHeader(const char* const m, const std::size_t mlen);
  bool ProcessHeader(const char* const m);
  std::uint16_t GetMsgID() const { return mMsgID; }
  std::uint16_t GetOpCode() const { return mOpCode; }
  bool GetQRField() const { return mBits.mQRField; }
  bool GetAAField() const { return mBits.mAAField; }
  bool GetTCField() const { return mBits.mTCField; }
  bool GetRDField() const { return mBits.mRDField; }
  bool GetRAField() const { return mBits.mRAField; }
  std::uint8_t GetRCode() const { return mRcode; }
  std::uint16_t GetQDCount() const { return mQDCount; }
  std::uint16_t GetANCount() const { return mANCount; }
  std::uint16_t GetNSCount() const { return mNSCount; }
  std::uint16_t GetARCount() const { return mARCount; }
};

class DNSQuestion {
private:
  /* The question section is used to carry the "question" in most
     queries, i.e., the parameters that define what is being asked.
     The section contains QDCOUNT (usually 1) entries, each of the
     following format:

                                  1  1  1  1  1  1
    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                                               |
  /                     QNAME                     /
  /                                               /
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                     QTYPE                     |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                     QCLASS                    |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  */

  /* RFC 1035:
       a domain name represented as a sequence of labels, where
       each label consists of a length octet followed by that
       number of octets. The domain name terminates with the
       zero length octet for the null label of the root. Note
       that this field may be an odd number of octets; no
       padding is used.
  */
  std::vector<std::string> mQNames;

  /* RFC 1035:
       a two octet code which specifies the type of the query.
       The values for this field include all codes valid for a
       TYPE field, together with some more general codes which
       can match more than one type of RR.

       TYPE fields are used in resource records. Note that these
       types are a subset of QTYPEs.

       TYPE        value and meaning
       A           1 a host address
       NS          2 an authoritative name server
       MD          3 a mail destination (Obsolete - use MX)
       MF          4 a mail forwarder (Obsolete - use MX)
       CNAME       5 the canonical name for an alias
       SOA         6 marks the start of a zone of authority
       MB          7 a mailbox domain name (EXPERIMENTAL)
       MG          8 a mail group member (EXPERIMENTAL)
       MR          9 a mail rename domain name (EXPERIMENTAL)
       NULL        10 a null RR (EXPERIMENTAL)
       WKS         11 a well known service description
       PTR         12 a domain name pointer
       HINFO       13 host information
       MINFO       14 mailbox or mail list information
       MX          15 mail exchange
       TXT         16 text strings

       QTYPE fields appear in the question part of a query.  QTYPES
       are a superset of TYPEs, hence all TYPEs are valid QTYPEs.
       In addition, the following QTYPEs are defined:

       AXFR        252 A request for a transfer of an entire zone
       MAILB       253 A request for mailbox-related records
                       (MB, MG or MR)
       MAILA       254 A request for mail agent RRs (Obsolete - see
                       MX)
       *           255 A request for all records

     RFC 6762:
       In the Question Section of a Multicast DNS query, the top
       bit of the qclass field is used to indicate that unicast
       responses are preferred for this particular question.
  */
  std::uint16_t mQType;

  /* RFC 1035:
       a two octet code that specifies the class of the query.
       For example, the QCLASS field is IN for the Internet.

       CLASS fields appear in resource records.  The following
       CLASS mnemonics and values are defined:

       IN          1 the Internet
       CS          2 the CSNET class (Obsolete - used only for
                     examples in some obsolete RFCs)
       CH          3 the CHAOS class
       HS          4 Hesiod [Dyer 87]

       QCLASS fields appear in the question section of a query.
       QCLASS values are a superset of CLASS values; every CLASS is
       a valid QCLASS. In addition to CLASS values, the following
       QCLASSes are defined:

       *           255 any class

     RFC 6762:
       In the Resource Record Sections of a Multicast DNS response,
       the top bit of the rrclass field is used to indicate that the
       record is a member of a unique RRSet, and the entire RRSet has
       been sent together (in the same packet, or in consecutive
       packets if there are too many records to fit in a single
       packet).
  */
  std::uint16_t mQClass;

public:
  DNSQuestion() = default;
  DNSQuestion(DNSQuestion&&);
  bool ProcessQuestion(const char* const m, std::size_t mlen,
                       std::size_t& offset);
  std::vector<std::string> GetQNames() const { return mQNames; }
  std::uint16_t GetQType() const { return mQType; }
  std::uint16_t GetQClass() const { return mQClass; }
};

class DNSRData {
public:
  DNSRData() = default;
};

class DNSPtrRData final : public DNSRData {
private:
  std::vector<std::string> mPtrDNames;

public:
  void AddPtrNames(const std::vector<std::string>&&);
};

class DNSRR {
public:
  enum eRRType : std::uint16_t {
    /* a host address */
    RR_A = 1,
    /* an authoritative name server */
    RR_NS,
    /* a mail destination (Obsolete - use MX) */
    RR_MD,
    /* a mail forwarder (Obsolete - use MX) */
    RR_MF,
    /* the canonical name for an alias */
    RR_CNAME,
    /* marks the start of a zone of authority */
    RR_SOA,
    /* a mailbox domain name (EXPERIMENTAL) */
    RR_MB,
    /* a mail group member (EXPERIMENTAL) */
    RR_MG,
    /* a mail rename domain name (EXPERIMENTAL) */
    RR_MR,
    /* a null RR (EXPERIMENTAL) */
    RR_NULL,
    /* a well known service description */
    RR_WKS,
    /* a domain name pointer */
    RR_PTR,
    /* host information */
    RR_HINFO,
    /* mailbox or mail list information */
    RR_MINFO,
    /* mail exchange */
    RR_MX,
    /* text strings */
    RR_TXT,
  };

private:
  /* The answer, authority, and additional sections all share the same
     format: a variable number of resource records, where the number
     of records is specified in the corresponding count field in the
     header. Each resource record has the following format:
                                  1  1  1  1  1  1
    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                                               |
  /                                               /
  /                      NAME                     /
  |                                               |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                      TYPE                     |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                     CLASS                     |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                      TTL                      |
  |                                               |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                   RDLENGTH                    |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
  /                     RDATA                     /
  /                                               /
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  */

  /* RFC 1035:
       a domain name to which this resource record pertains.
  */
  std::vector<std::string> mName;

  /* RFC 1035:
       two octets containing one of the RR type codes. This field
       specifies the meaning of the data in the RDATA field.

    See comment documenting qtype for values.
  */
  enum eRRType mRRType;

  /* RFC 1035:
       two octets which specify the class of the data in the RDATA
       field.

     RFC 6762:
       In the Resource Record Sections of a Multicast DNS response,
       the top bit of the rrclass field is used to indicate that the
       record is a member of a unique RRSet, and the entire RRSet has
       been sent together (in the same packet, or in consecutive
       packets if there are too many records to fit in a single
       packet).
  */
  std::uint16_t mRRClass;

  /* RFC 1035:
       a 32 bit unsigned integer that specifies the time interval (in
       seconds) that the resource record may be cached before it
       should be discarded. Zero values are interpreted to mean that
       the RR can only be used for the transaction in progress, and
       should not be cached.
  */
  std::uint32_t mTTL;

  /* RFC 1035:
       an unsigned 16 bit integer that specifies the length in octets
       of the RDATA field.
  */
  std::uint16_t mRDLength;

  /* RFC 1035:
       a variable length string of octets that describes the
       resource. The format of this information varies according to
       the TYPE and CLASS of the resource record. For example, the
       if the TYPE is A and the CLASS is IN, the RDATA field is a 4
       octet ARPA Internet address.
  */
  DNSRData mRData;

public:
  std::vector<std::string> GetName() const { return mName; }
  std::uint16_t GetRRType() const { return mRRType; }
  std::uint16_t GetRRClass() const { return mRRClass; }
  std::uint16_t GetTTL() const { return mTTL; }
  std::uint16_t GetRDLength() const { return mRDLength; }
  DNSRData GetRData() const { return mRData; }
  bool ProcessRR(const char* const m, std::size_t mlen,
                 std::size_t& offset);
};

class DNSMessage {
private:
  std::unique_ptr<DNSHeader> mHeader;
  std::vector<DNSQuestion> mQuestions;
  std::vector<DNSRR> mRRSection[3];
  std::string mRawMsg;

protected:
  bool ProcessQuestions(const char* const m, std::size_t mlen,
                        std::uint16_t qcount, std::size_t& offset);
  bool ProcessRRs(const char* const m, std::size_t mlen,
                  std::uint16_t ancount, std::size_t& offset,
                  std::uint8_t section);

public:
  // Throws std::bad_alloc when allocation fails
  // m MUST not be NULL or nullptr, undefined behavior
  DNSMessage(const char* const m, const std::size_t mlen);
  DNSMessage(const char* const m);
  ~DNSMessage() = default;
  const std::string GetRawMessage() const { return mRawMsg; }
  bool ProcessMessage();
  static bool ProcessName(const char* const m, std::size_t mlen,
                          std::string& name, std::uint8_t &nlen);
};

} // namespace dns_message

#endif // MDNS_MESSAGE_H
