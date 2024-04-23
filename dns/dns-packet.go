package dns

import (
	bytepacketbuffer "dns-client-go/packetbuffer"
	queryType "dns-client-go/query-type"
	"net"
	"strings"
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

func (dp *DnsPacket) FromBuffer(buffer *bytepacketbuffer.PacketBuffer) *DnsPacket {
	packet := NewPacket()
	packet.Header.Read(buffer)

	for i := 0; i < int(packet.Header.Questions); i++ {
		question := DnsQuestion{Name: "", Qtype: queryType.QueryType(0)}
		question.Read(buffer)
		packet.Question = append(packet.Question, question)
	}

	for i := 0; i < int(packet.Header.Answers); i++ {
		record := DnsRecord{}
		answer := record.Read(buffer)
		packet.Answers = append(packet.Answers, answer)
	}

	for i := 0; i < int(packet.Header.AuthoritiveEntries); i++ {
		record := DnsRecord{}
		record.Read(buffer)
		packet.Authorities = append(packet.Authorities, record)
	}

	for i := 0; i < int(packet.Header.ResourceEntries); i++ {
		record := DnsRecord{}
		record.Read(buffer)
		packet.Authorities = append(packet.Authorities, record)
	}

	return packet

}

func (dp *DnsPacket) Write(buffer *bytepacketbuffer.PacketBuffer) *DnsPacket {
	dp.Header.Questions = uint16(len(dp.Question))
	dp.Header.Answers = uint16(len(dp.Answers))
	dp.Header.AuthoritiveEntries = uint16(len(dp.Authorities))
	dp.Header.ResourceEntries = uint16(len(dp.Resources))

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

func (dp *DnsPacket) GetRandomA() net.IP {
	for _, record := range dp.Answers {
		if record.A != nil {
			return net.ParseIP(record.A.addr)
		}
	}

	return nil
}

func (dp *DnsPacket) GetNS(qname string) []NSRecord {
	var nsRecords []NSRecord
	for _, record := range dp.Authorities {
		if record.NS != nil && strings.HasSuffix(qname, record.NS.domain) {
			nsRecords = append(nsRecords, *record.NS)
		}
	}

	return nsRecords
}

func (dp *DnsPacket) GetResolvedNS(qname string) net.IP {
	nsRecords := dp.GetNS(qname)
	for _, ns := range nsRecords {
		for _, res := range dp.Resources {
			if res.A != nil && res.A.domain == ns.domain {
				return net.ParseIP(res.A.addr)
			}
		}
	}

	return nil
}

func (dp *DnsPacket) GetUnresolvedNS(qname string) string {
	nsRecords := dp.GetNS(qname)
	if len(nsRecords) > 0 {
		return nsRecords[0].host
	}

	return ""
}
