package dns

import (
	bytepacketbuffer "dns-client-go/byte-packet-buffer"
	querytype "dns-client-go/query-type"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type UnknownDnsRecord struct {
	domain     string
	qtype      uint16
	dataLength uint16
	ttl        uint32
}

type ADnsRecord struct {
	domain string
	addr   string
	ttl    uint32
}

type DnsRecord struct {
	Unknown *UnknownDnsRecord
	A       *ADnsRecord
}

var UnknownDnsRecordMap map[querytype.QueryType]UnknownDnsRecord
var ADnsRecordMap map[querytype.QueryType]ADnsRecord

func (dr *DnsRecord) Read(buffer *bytepacketbuffer.BytePacketBuffer) DnsRecord {
	domain := ""
	domain, _ = buffer.ReadQname(domain)

	qtypeNumber, _ := buffer.Read_u16()
	qtype := querytype.QueryType(qtypeNumber)
	_, _ = buffer.Read_u16()
	ttl, _ := buffer.Read_u32()
	dataLength, _ := buffer.Read_u16()

	switch qtype {
	case querytype.A:
		rawAddress, _ := buffer.Read_u32()
		ipAddress := net.IPv4(byte(rawAddress>>24&0xFF), byte(rawAddress>>16&0xFF), byte(rawAddress>>8&0xFF), byte(rawAddress>>0&0xFF))

		return DnsRecord{
			A: &ADnsRecord{
				domain: domain,
				addr:   ipAddress.String(),
				ttl:    ttl,
			},
		}
	case querytype.UNKNOWN:
		buffer.Step(uint(dataLength))

		return DnsRecord{
			Unknown: &UnknownDnsRecord{
				domain:     domain,
				qtype:      qtypeNumber,
				dataLength: dataLength,
				ttl:        ttl,
			},
		}
	}

	return DnsRecord{}

}

func (dr *DnsRecord) Write(buffer *bytepacketbuffer.BytePacketBuffer) (uint, error) {
  startPos := buffer.Pos()

  if dr.A != nil {
    buffer.Write_qname(dr.A.domain)
    buffer.Write_uint16(uint16(querytype.A))
    buffer.Write_uint16(1)
    buffer.Write_uint32(dr.A.ttl)
    buffer.Write_uint16(4)
    
    ip := strings.Split(dr.A.addr, ".")
    ips := []uint8{}

    for _, i := range ip {
      num, _ := strconv.Atoi(i)
      num8 := uint8(num)
      ips = append(ips, num8)
    }
    buffer.Write_uint8(ips[0])
    buffer.Write_uint8(ips[1])
    buffer.Write_uint8(ips[2])
    buffer.Write_uint8(ips[3])

  } else if dr.Unknown != nil {
    fmt.Println("Skipping records for unknown")
  } else {
    return 0, errors.New("record contains no known DNS record data")
  }

  return buffer.Pos() - startPos, nil
}
