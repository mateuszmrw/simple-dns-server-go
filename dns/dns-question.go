package dns

import (
	bytepacketbuffer "dns-client-go/byte-packet-buffer"
	querytype "dns-client-go/query-type"
)

type DnsQuestion struct {
	Name  string
	Qtype querytype.QueryType
}

func NewQuestion(name string, qtype querytype.QueryType) *DnsQuestion {
	return &DnsQuestion{
		Name:  name,
		Qtype: qtype,
	}
}

func (dn *DnsQuestion) Read(buffer *bytepacketbuffer.BytePacketBuffer) {
	dn.Name, _ = buffer.ReadQname(dn.Name)
	qtBuffer, _ := buffer.Read_u16()
	dn.Qtype = querytype.QueryType(qtBuffer) // qtype
	_, _ = buffer.Read_u16()                 // class
}

func (dn *DnsQuestion) Write(buffer *bytepacketbuffer.BytePacketBuffer) *DnsQuestion {
	buffer.Write_qname(dn.Name)

	buffer.Write_uint16(uint16(dn.Qtype))
	buffer.Write_uint16(1)

	return dn
}
