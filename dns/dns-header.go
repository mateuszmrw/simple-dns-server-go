package dns

import (
	bytepacketbuffer "dns-client-go/byte-packet-buffer"
	resultcode "dns-client-go/result-code"
	util "dns-client-go/util"
)

type DnsHeader struct {
	ID                  uint16
	RecursionDesired    bool  // 1 bit
	TruncatedMessage    bool  // 1 bit
	AuthoritativeAnswer bool  // 1 bit
	Opcode              uint8 // 4 bits
	Response            bool  // 1 bit

	Rescode            resultcode.ResultCode // 4 bits
	CheckingDisabled   bool                  // 1 bit
	AuthedData         bool                  // 1 bit
	Z                  bool                  // 1 bit
	RecursionAvailable bool                  // 1 bit

	Questions          uint16 // 16 bits
	Answers            uint16 // 16 bits
	AuthoritiveEntries uint16 // 16 bits
	ResourceEntries    uint16 // 16 bits
}

func NewHeader() *DnsHeader {
	return &DnsHeader{
		ID:                  0,
		RecursionDesired:    false,
		TruncatedMessage:    false,
		AuthoritativeAnswer: false,
		Opcode:              0,
		Response:            false,

		Rescode:            resultcode.NOERROR,
		CheckingDisabled:   false,
		AuthedData:         false,
		Z:                  false,
		RecursionAvailable: false,

		Questions:          0,
		Answers:            0,
		AuthoritiveEntries: 0,
		ResourceEntries:    0,
	}
}

func (dh *DnsHeader) Read(buffer *bytepacketbuffer.BytePacketBuffer) *DnsHeader {
	dh.ID, _ = buffer.Read_u16()
	flags, _ := buffer.Read_u16()

	// The Recursion Desired (RD) flag. This is set to true if the client desires the server to perform a recursive query.
	// RD is the highest bit (bit 15) of the flags.
	dh.RecursionDesired = (flags>>15)&0x1 == 1

	// The Truncated Message (TC) flag. This is set to true if the message was longer than permitted on the transmission channel.
	// TC is the second highest bit (bit 14).
	dh.TruncatedMessage = (flags>>14)&0x1 == 1

	// The Opcode field. This specifies kind of query in this message. This value is a 4-bit field between bits 11-14.
	dh.Opcode = uint8((flags >> 11) & 0xf)

	// The Authoritative Answer (AA) flag. This indicates that the responding name server is an authority for the domain name in question section.
	// AA is the fifth bit from the top (bit 10).
	dh.AuthoritativeAnswer = (flags>>10)&0x1 == 1

	// The Response (QR) flag. This indicates whether this message is a query (0) or a response (1).
	// QR is the bit just past the middle (bit 7).
	dh.Response = (flags>>7)&0x1 == 1

	// The Response Code (RCODE) field. This is a 4-bit field that is set as part of responses.
	// The RCODE specifies the outcome of the query, and is found in the lowest four bits.
	dh.Rescode = resultcode.ResultCode(flags & 0xf)

	// The Checking Disabled (CD) flag. This is used in DNSSEC (DNS Security Extensions). It indicates that the security
	// processing is disabled for this message. CD is the fourth lowest bit (bit 4).
	dh.CheckingDisabled = (flags>>4)&0x1 == 1

	// The Authenticated Data (AD) flag. This is also used in DNSSEC as an indication that all the data included
	// in the answer and authority portion of the response have been authenticated by the server. AD is the third lowest bit (bit 3).
	dh.AuthedData = (flags>>3)&0x1 == 1

	// The Zero (Z) flag. Reserved for future use. Must be zero in all queries and responses. This is the second lowest bit (bit 2).
	dh.Z = (flags>>2)&0x1 == 1

	// The Recursion Available (RA) flag. This is set or cleared in a response, and denotes whether recursive query support is available in the name server.
	// RA is the second lowest bit (bit 1).
	dh.RecursionAvailable = (flags>>1)&0x1 == 1

	dh.Questions, _ = buffer.Read_u16()
	dh.Answers, _ = buffer.Read_u16()
	dh.AuthoritiveEntries, _ = buffer.Read_u16()
	dh.ResourceEntries, _ = buffer.Read_u16()

	return dh
}

func (dh *DnsHeader) Write(buffer *bytepacketbuffer.BytePacketBuffer) *DnsHeader {
	buffer.Write_uint16(dh.ID)
	buffer.Write_uint8(util.B2i8(dh.RecursionDesired) | (util.B2i8(dh.TruncatedMessage) << 1) | (util.B2i8(dh.AuthoritativeAnswer) << 2) | (dh.Opcode << 3) | uint8((util.B2i8(dh.Response) << 7)))
	buffer.Write_uint8((uint8(dh.Rescode)) | (util.B2i8(dh.CheckingDisabled) << 4) | (util.B2i8(dh.AuthedData) << 5) | (util.B2i8(dh.Z) << 6) | (util.B2i8(dh.RecursionAvailable) << 7))
	buffer.Write_uint16(dh.Questions)
	buffer.Write_uint16(dh.Answers)
	buffer.Write_uint16(dh.AuthoritiveEntries)
	buffer.Write_uint16(dh.ResourceEntries)
	return dh
}
