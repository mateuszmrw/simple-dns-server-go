package dns

import (
	bytepacketbuffer "dns-client-go/packetbuffer"
	querytype "dns-client-go/query-type"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type WriteableRecord interface {
	Write(buffer *bytepacketbuffer.PacketBuffer)
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

func (dr *DnsRecord) Read(buffer *bytepacketbuffer.PacketBuffer) DnsRecord {
	domain, _ := buffer.ReadQname()

	qtypeNumber, _ := buffer.Read_u16()
	qtype := querytype.QueryType(qtypeNumber)
	_, _ = buffer.Read_u16()
	ttl, _ := buffer.Read_u32()
	dataLength, _ := buffer.Read_u16()

	switch qtype {
	case querytype.NS:
		ns, _ := buffer.ReadQname()
		dr.NS = &NSRecord{
			domain: domain,
			host:   ns,
			ttl:    ttl,
		}
		return *dr
	case querytype.CNAME:
		cname, _ := buffer.ReadQname()
		dr.CNAME = &CNAMERecord{
			domain: domain,
			host:   cname,
			ttl:    ttl,
		}
		return *dr
	case querytype.MX:
		priority, _ := buffer.Read_u16()
		mx, _ := buffer.ReadQname()
		dr.MX = &MXRecord{
			domain:   domain,
			priority: priority,
			host:     mx,
			ttl:      ttl,
		}
		return *dr

	case querytype.A:
		rawAddress, _ := buffer.Read_u32()
		ipAddress := net.IPv4(byte(rawAddress>>24&0xFF), byte(rawAddress>>16&0xFF), byte(rawAddress>>8&0xFF), byte(rawAddress>>0&0xFF))
		dr.A = &ARecord{
			domain: domain,
			addr:   ipAddress.String(),
			ttl:    ttl,
		}
		return *dr

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
		dr.AAAA = &AAAARecord{
			domain: domain,
			addr:   addr.String(),
			ttl:    ttl,
		}
		return *dr
	case querytype.UNKNOWN:
		buffer.Step(uint(dataLength))
		dr.Unknown = &UnknownRecord{
			domain:     domain,
			qtype:      qtypeNumber,
			dataLength: dataLength,
			ttl:        ttl,
		}

		return *dr
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

}

func (a *ARecord) Write(buffer *bytepacketbuffer.PacketBuffer) {
	buffer.WriteQname(a.domain)
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

func (ns *NSRecord) Write(buffer *bytepacketbuffer.PacketBuffer) {
	buffer.WriteQname(ns.domain)
	buffer.Write_uint16(uint16(querytype.NS))
	buffer.Write_uint16(1) // IN Class
	buffer.Write_uint32(ns.ttl)

	pos := buffer.Pos()
	buffer.Write_uint16(0) // Set Placeholder for the NS Host length

	buffer.WriteQname(ns.host)

	size := buffer.Pos() - (pos + 2)
	buffer.SetValue_u16(pos, uint16(size)) // Update Placeholder
}

func (mx *MXRecord) Write(buffer *bytepacketbuffer.PacketBuffer) {
	buffer.WriteQname(mx.domain)
	buffer.Write_uint16(uint16(querytype.MX))
	buffer.Write_uint16(1) // IN Class
	buffer.Write_uint32(mx.ttl)

	pos := buffer.Pos()
	buffer.Write_uint16(0) // Set Placeholder for MX host and priority length

	buffer.Write_uint16(mx.priority)
	buffer.WriteQname(mx.host)

	size := buffer.Pos() - (pos + 2)
	buffer.SetValue_u16(pos, uint16(size)) // Update placeholder
}

func (cn *CNAMERecord) Write(buffer *bytepacketbuffer.PacketBuffer) {
	buffer.WriteQname(cn.domain)
	buffer.Write_uint16(uint16(querytype.CNAME))
	buffer.Write_uint16(1) // IN Class
	buffer.Write_uint32(cn.ttl)

	pos := buffer.Pos()
	buffer.Write_uint16(0) // Allocate a placeholder for CNAME length

	buffer.WriteQname(cn.host)

	size := buffer.Pos() - (pos + 2)
	buffer.SetValue_u16(pos, uint16(size)) // Update placeholder with CNAME length
}

func (aaaa *AAAARecord) Write(buffer *bytepacketbuffer.PacketBuffer) {
	buffer.WriteQname(aaaa.domain)
	buffer.Write_uint16(uint16(querytype.AAAA))
	buffer.Write_uint16(1) // IN Class
	buffer.Write_uint32(aaaa.ttl)
	buffer.Write_uint16(16) // length of IPv6

	ip := net.ParseIP(aaaa.addr)
	ip = ip.To16()

	for i := 0; i < len(ip); i += 2 {
		val := uint16(ip[i])<<8 | uint16(ip[i+1])
		buffer.Write_uint16(val)
	}

}

func (dr *DnsRecord) Write(buffer *bytepacketbuffer.PacketBuffer) (uint, error) {
	startPos := buffer.Pos()

	switch {
	case dr.A != nil:
		dr.A.Write(buffer)
	case dr.NS != nil:
		dr.NS.Write(buffer)
	case dr.CNAME != nil:
		dr.CNAME.Write(buffer)
	case dr.MX != nil:
		dr.MX.Write(buffer)
	case dr.AAAA != nil:
		dr.AAAA.Write(buffer)
	case dr.Unknown != nil:
		fmt.Printf("Omitting the unknown DNS Record")
	default:
		return 0, errors.New("record contains no known DNS record data")

	}

	return buffer.Pos() - startPos, nil
}
