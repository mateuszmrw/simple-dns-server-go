package dns

import (
	bytepacketbuffer "dns-client-go/byte-packet-buffer"
	queryType "dns-client-go/query-type"
)

type DnsPacket struct {
	Header      DnsHeader
	Question    []DnsQuestion
	Answers     []DnsRecord
	Authorities []DnsRecord
	Resources   []DnsRecord
}

func NewPacket() *DnsPacket {
	header := NewHeader()
	return &DnsPacket{
		Header:      *header,
		Question:    []DnsQuestion{},
		Answers:     []DnsRecord{},
		Authorities: []DnsRecord{},
		Resources:   []DnsRecord{},
	}
}

func (dp *DnsPacket) FromBuffer(buffer *bytepacketbuffer.BytePacketBuffer) *DnsPacket {
	packet := NewPacket()
	packet.Header.Read(buffer)

	for i := 0; i < int(packet.Header.Questions); i++ {
		question := DnsQuestion{name: "", qtype: queryType.QueryType(0)}
		question.Read(buffer)
		packet.Question = append(packet.Question, question)
	}

	for i := 0; i < int(packet.Header.answers); i++ {
		record := DnsRecord{}
		answer := record.Read(buffer)
		packet.Answers = append(packet.Answers, answer)
	}

	for i := 0; i < int(packet.Header.authoritative_entries); i++ {
		record := DnsRecord{}
		record.Read(buffer)
		packet.Authorities = append(packet.Authorities, record)
	}

	for i := 0; i < int(packet.Header.resource_entries); i++ {
		record := DnsRecord{}
		record.Read(buffer)
		packet.Authorities = append(packet.Authorities, record)
	}

	return packet

}

func (dp *DnsPacket) Write(buffer *bytepacketbuffer.BytePacketBuffer) *DnsPacket {
	dp.Header.Questions = uint16(len(dp.Question))
	dp.Header.answers = uint16(len(dp.Answers))
	dp.Header.authoritative_entries = uint16(len(dp.Authorities))
	dp.Header.resource_entries = uint16(len(dp.Resources))

	dp.Header.Write(buffer)

	for _, question := range dp.Question {
		question.Write(buffer)
	}

	for _, rec := range dp.Answers {
		rec.Write(buffer)
	}

	for _, rec := range dp.Authorities {
		rec.Write(buffer)
	}

	for _, rec := range dp.Resources {
		rec.Write(buffer)
	}

	return dp
}
