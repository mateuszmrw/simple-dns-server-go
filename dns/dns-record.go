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

type WriteableRecord interface {
	Write(buffer *bytepacketbuffer.BytePacketBuffer)
}

type UnknownRecord struct {
	domain     string
	qtype      uint16
	dataLength uint16
	ttl        uint32
}

type ARecord struct {
	domain string
	addr   string
	ttl    uint32
}

type NSRecord struct {
	domain string
	host   string
	ttl    uint32
}

type CNAMERecord struct {
	domain string
	host   string
	ttl    uint32
}

type MXRecord struct {
	domain   string
	host     string
	priority uint16
	ttl      uint32
}

type AAAARecord struct {
	domain string
	addr   string
	ttl    uint32
}

type DnsRecord struct {
	Unknown *UnknownRecord
	A       *ARecord
	NS      *NSRecord
	CNAME   *CNAMERecord
	MX      *MXRecord
	AAAA    *AAAARecord
}

func (dr *DnsRecord) Read(buffer *bytepacketbuffer.BytePacketBuffer) DnsRecord {
	domain := ""
	domain, _ = buffer.ReadQname(domain)

	qtypeNumber, _ := buffer.Read_u16()
	qtype := querytype.QueryType(qtypeNumber)
	_, _ = buffer.Read_u16()
	ttl, _ := buffer.Read_u32()
	dataLength, _ := buffer.Read_u16()

	switch qtype {
	case querytype.NS:
		ns := ""
		ns, _ = buffer.ReadQname(ns)
		return DnsRecord{
			NS: &NSRecord{
				domain: domain,
				host:   ns,
				ttl:    ttl,
			},
		}
	case querytype.CNAME:
		cname := ""
		cname, _ = buffer.ReadQname(cname)

		return DnsRecord{
			CNAME: &CNAMERecord{
				domain: domain,
				host:   cname,
				ttl:    ttl,
			},
		}
	case querytype.MX:
		priority, _ := buffer.Read_u16()
		mx := ""
		mx, _ = buffer.ReadQname(mx)

		return DnsRecord{
			MX: &MXRecord{
				domain:   domain,
				priority: priority,
				host:     mx,
				ttl:      ttl,
			},
		}
	case querytype.A:
		rawAddress, _ := buffer.Read_u32()
		ipAddress := net.IPv4(byte(rawAddress>>24&0xFF), byte(rawAddress>>16&0xFF), byte(rawAddress>>8&0xFF), byte(rawAddress>>0&0xFF))

		return DnsRecord{
			A: &ARecord{
				domain: domain,
				addr:   ipAddress.String(),
				ttl:    ttl,
			},
		}
	case querytype.AAAA:
		rawAddr_1, _ := buffer.Read_u32()
		rawAddr_2, _ := buffer.Read_u32()
		rawAddr_3, _ := buffer.Read_u32()
		rawAddr_4, _ := buffer.Read_u32()

		addr := net.IP{
			byte(rawAddr_1 >> 24), byte(rawAddr_1 >> 16), byte(rawAddr_1 >> 8), byte(rawAddr_1),
			byte(rawAddr_2 >> 24), byte(rawAddr_2 >> 16), byte(rawAddr_2 >> 8), byte(rawAddr_2),
			byte(rawAddr_3 >> 24), byte(rawAddr_3 >> 16), byte(rawAddr_3 >> 8), byte(rawAddr_3),
			byte(rawAddr_4 >> 24), byte(rawAddr_4 >> 16), byte(rawAddr_4 >> 8), byte(rawAddr_4),
		}

		return DnsRecord{
			AAAA: &AAAARecord{
				domain: domain,
				addr:   addr.String(),
				ttl:    ttl,
			},
		}
	case querytype.UNKNOWN:
		buffer.Step(uint(dataLength))

		return DnsRecord{
			Unknown: &UnknownRecord{
				domain:     domain,
				qtype:      qtypeNumber,
				dataLength: dataLength,
				ttl:        ttl,
			},
		}
	default:
		buffer.Step(uint(dataLength))

		return DnsRecord{
			Unknown: &UnknownRecord{
				domain:     domain,
				qtype:      qtypeNumber,
				dataLength: dataLength,
				ttl:        ttl,
			},
		}
	}

	return DnsRecord{}
}

func (a *ARecord) Write(buffer *bytepacketbuffer.BytePacketBuffer) {
	buffer.Write_qname(a.domain)
	buffer.Write_uint16(uint16(querytype.A))
	buffer.Write_uint16(1) // IN Class
	buffer.Write_uint32(a.ttl)
	buffer.Write_uint16(4) // Length of IPv4

	ip := strings.Split(a.addr, ".")
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
}

func (ns *NSRecord) Write(buffer *bytepacketbuffer.BytePacketBuffer) {
	buffer.Write_qname(ns.domain)
	buffer.Write_uint16(uint16(querytype.NS))
	buffer.Write_uint16(1) // IN Class

	pos := buffer.Pos()

	buffer.Write_uint16(0) // Set Placeholder for the NS Host length

	buffer.Write_qname(ns.host)

	size := buffer.Pos() - (pos + 2)
	buffer.SetValue_u16(pos, uint16(size)) // Update Placeholder
}

func (mx *MXRecord) Write(buffer *bytepacketbuffer.BytePacketBuffer) {
	buffer.Write_qname(mx.domain)
	buffer.Write_uint16(uint16(querytype.MX))
	buffer.Write_uint16(1) // IN Class
	buffer.Write_uint32(mx.ttl)

	pos := buffer.Pos()
	buffer.Write_uint32(0) // Set Placeholder for MX data length

	buffer.Write_uint16(mx.priority)
	buffer.Write_qname(mx.host)

	size := buffer.Pos() - (pos + 2)
	buffer.SetValue_u16(pos, uint16(size)) // Update placeholder
}

func (cn *CNAMERecord) Write(buffer *bytepacketbuffer.BytePacketBuffer) {
	buffer.Write_qname(cn.domain)
	buffer.Write_uint16(uint16(querytype.CNAME))
	buffer.Write_uint16(1) // IN Class
	buffer.Write_uint32(cn.ttl)

	pos := buffer.Pos()
	buffer.Write_uint16(0) // Allocate a placeholder for CNAME length

	buffer.Write_qname(cn.host)

	size := buffer.Pos() - (pos + 2)
	buffer.SetValue_u16(pos, uint16(size)) // Update placeholder with CNAME length
}

func (aaaa *AAAARecord) Write(buffer *bytepacketbuffer.BytePacketBuffer) {
	buffer.Write_qname(aaaa.domain)
	buffer.Write_uint16(uint16(querytype.AAAA))
	buffer.Write_uint16(1) // IN Class
	buffer.Write_uint32(aaaa.ttl)
	buffer.Write_uint16(16) // length of IPv6

	for i := 0; i < len(aaaa.addr); i += 2 {
		val := uint16(aaaa.addr[i])<<8 | uint16(aaaa.addr[i+1])
		buffer.Write_uint16(val)
	}
}

func (dr *DnsRecord) Write(buffer *bytepacketbuffer.BytePacketBuffer) (uint, error) {
	startPos := buffer.Pos()

	switch {
	case dr.A != nil:
		dr.A.Write(buffer)
	case dr.NS != nil:
		dr.NS.Write(buffer)
	case dr.MX != nil:
		dr.MX.Write(buffer)
	case dr.CNAME != nil:
		dr.CNAME.Write(buffer)
	case dr.AAAA != nil:
		dr.AAAA.Write(buffer)
	case dr.Unknown != nil:
		fmt.Printf("Omitting the unknown DNS Record")
	default:
		return 0, errors.New("record contains no known DNS record data")

	}

	return buffer.Pos() - startPos, nil
}
