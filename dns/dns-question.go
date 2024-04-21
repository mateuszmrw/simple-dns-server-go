package dns

import (
	bytepacketbuffer "dns-client-go/byte-packet-buffer"
	querytype "dns-client-go/query-type"
)

type DnsQuestion struct {
	name  string
	qtype querytype.QueryType
}

func NewQuestion(name string, qtype querytype.QueryType) *DnsQuestion {
	return &DnsQuestion{
		name:  name,
		qtype: qtype,
	}
}

func (dn *DnsQuestion) Read(buffer *bytepacketbuffer.BytePacketBuffer) {
	dn.name, _ = buffer.ReadQname(dn.name)
	qtBuffer, _ := buffer.Read_u16()
	dn.qtype = querytype.QueryType(qtBuffer) // qtype
	_, _ = buffer.Read_u16()                 // class
}

func (dn *DnsQuestion) Write(buffer *bytepacketbuffer.BytePacketBuffer) *DnsQuestion {
	buffer.Write_qname(dn.name)

	buffer.Write_uint16(uint16(dn.qtype))
	buffer.Write_uint16(1)

	return dn
}
