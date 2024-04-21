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

	rescode             resultcode.ResultCode
	checking_disabled   bool // 1 bit
	authed_data         bool // 1 bit
	z                   bool // 1 bit
	recursion_available bool // 1 bit

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

	dh.Recursion_desired = (flags>>15)&0x1 == 1
	dh.truncated_message = (flags>>14)&0x1 == 1

	dh.authoritative_answer = (flags>>10)&0x1 == 1
	dh.opcode = uint8((flags >> 11) & 0xf)
	dh.response = (flags>>7)&0x1 == 1

	dh.rescode = resultcode.ResultCode(flags & 0xf)
	dh.checking_disabled = (flags>>4)&0x1 == 1
	dh.authed_data = (flags>>3)&0x1 == 1
	dh.z = (flags>>2)&0x1 == 1
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
