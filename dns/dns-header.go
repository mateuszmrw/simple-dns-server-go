package dns

import (
	bytepacketbuffer "dns-client-go/byte-packet-buffer"
	resultcode "dns-client-go/result-code"
	util "dns-client-go/util"
)

type DnsHeader struct {
	ID                   uint16
	Recursion_desired    bool  // 1 bit
	truncated_message    bool  // 1 bit
	authoritative_answer bool  // 1 bit
	opcode               uint8 // 4 bits
	response             bool  // 1 bit

	rescode             resultcode.ResultCode // 4 bits
	checking_disabled   bool                  // 1 bit
	authed_data         bool                  // 1 bit
	z                   bool                  // 1 bit
	recursion_available bool                  // 1 bit

	Questions             uint16 // 16 bits
	answers               uint16 // 16 bits
	authoritative_entries uint16 // 16 bits
	resource_entries      uint16 // 16 bits
}

func NewHeader() *DnsHeader {
	return &DnsHeader{
		ID:                   0,
		Recursion_desired:    false,
		truncated_message:    false,
		authoritative_answer: false,
		opcode:               0,
		response:             false,

		rescode:             resultcode.NOERROR,
		checking_disabled:   false,
		authed_data:         false,
		z:                   false,
		recursion_available: false,

		Questions:             0,
		answers:               0,
		authoritative_entries: 0,
		resource_entries:      0,
	}
}

func (dh *DnsHeader) Read(buffer *bytepacketbuffer.BytePacketBuffer) *DnsHeader {
	dh.ID, _ = buffer.Read_u16()
	flags, _ := buffer.Read_u16()

	// The Recursion Desired (RD) flag. This is set to true if the client desires the server to perform a recursive query.
	// RD is the highest bit (bit 15) of the flags.
	dh.Recursion_desired = (flags>>15)&0x1 == 1

	// The Truncated Message (TC) flag. This is set to true if the message was longer than permitted on the transmission channel.
	// TC is the second highest bit (bit 14).
	dh.truncated_message = (flags>>14)&0x1 == 1

	// The Opcode field. This specifies kind of query in this message. This value is a 4-bit field between bits 11-14.
	dh.opcode = uint8((flags >> 11) & 0xf)

	// The Authoritative Answer (AA) flag. This indicates that the responding name server is an authority for the domain name in question section.
	// AA is the fifth bit from the top (bit 10).
	dh.authoritative_answer = (flags>>10)&0x1 == 1

	// The Response (QR) flag. This indicates whether this message is a query (0) or a response (1).
	// QR is the bit just past the middle (bit 7).
	dh.response = (flags>>7)&0x1 == 1

	// The Response Code (RCODE) field. This is a 4-bit field that is set as part of responses.
	// The RCODE specifies the outcome of the query, and is found in the lowest four bits.
	dh.rescode = resultcode.ResultCode(flags & 0xf)

	// The Checking Disabled (CD) flag. This is used in DNSSEC (DNS Security Extensions). It indicates that the security
	// processing is disabled for this message. CD is the fourth lowest bit (bit 4).
	dh.checking_disabled = (flags>>4)&0x1 == 1

	// The Authenticated Data (AD) flag. This is also used in DNSSEC as an indication that all the data included
	// in the answer and authority portion of the response have been authenticated by the server. AD is the third lowest bit (bit 3).
	dh.authed_data = (flags>>3)&0x1 == 1

	// The Zero (Z) flag. Reserved for future use. Must be zero in all queries and responses. This is the second lowest bit (bit 2).
	dh.z = (flags>>2)&0x1 == 1

	// The Recursion Available (RA) flag. This is set or cleared in a response, and denotes whether recursive query support is available in the name server.
	// RA is the second lowest bit (bit 1).
	dh.recursion_available = (flags>>1)&0x1 == 1

	dh.Questions, _ = buffer.Read_u16()
	dh.answers, _ = buffer.Read_u16()
	dh.authoritative_entries, _ = buffer.Read_u16()
	dh.resource_entries, _ = buffer.Read_u16()

	return dh
}

func (dh *DnsHeader) Write(buffer *bytepacketbuffer.BytePacketBuffer) *DnsHeader {
	buffer.Write_uint16(dh.ID)
	buffer.Write_uint8(util.B2i8(dh.Recursion_desired) | (util.B2i8(dh.truncated_message) << 1) | (util.B2i8(dh.authoritative_answer) << 2) | (dh.opcode << 3) | uint8((util.B2i8(dh.response) << 7)))
	buffer.Write_uint8((uint8(dh.rescode)) | (util.B2i8(dh.checking_disabled) << 4) | (util.B2i8(dh.authed_data) << 5) | (util.B2i8(dh.z) << 6) | (util.B2i8(dh.recursion_available) << 7))
	buffer.Write_uint16(dh.Questions)
	buffer.Write_uint16(dh.answers)
	buffer.Write_uint16(dh.authoritative_entries)
	buffer.Write_uint16(dh.resource_entries)
	return dh
}
