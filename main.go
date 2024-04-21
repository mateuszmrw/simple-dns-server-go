package main

import (
	"dns-client-go/dns"
	packetbuffer "dns-client-go/packetbuffer"
	querytype "dns-client-go/query-type"
	"fmt"
	"net"
)

func lookup(qname string, qtype querytype.QueryType) (*dns.DnsPacket, error) {
	server := "8.8.8.8:53"

	conn, err := net.Dial("udp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	rawPacket := &dns.DnsPacket{}

	rawPacket.Header.ID = 1
	rawPacket.Header.RecursionDesired = true
	question := dns.NewQuestion(qname, qtype)
	rawPacket.Question = append(rawPacket.Question, *question)
	rawPacket.Header.Questions = 1

	requestBuffer := packetbuffer.NewPacketBuffer()
	rawPacket.Write(&requestBuffer)

	conn.Write(requestBuffer.Buffer)

	bpb := packetbuffer.NewPacketBuffer()

	_, err = conn.Read(bpb.Buffer)
	if err != nil {
		return nil, err
	}

	return rawPacket.FromBuffer(&bpb), nil
}

func main() {
	name := "yahoo.com"
	qtype := querytype.NS

	server := "8.8.8.8:53"

	conn, err := net.Dial("udp", server)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()

	rawPacket := &dns.DnsPacket{}

	rawPacket.Header.ID = 1
	rawPacket.Header.RecursionDesired = true
	question := dns.NewQuestion(name, qtype)
	rawPacket.Question = append(rawPacket.Question, *question)
	rawPacket.Header.Questions = 1

	requestBuffer := packetbuffer.NewPacketBuffer()
	rawPacket.Write(&requestBuffer)

	conn.Write(requestBuffer.Buffer)

	bpb := packetbuffer.NewPacketBuffer()

	_, err = conn.Read(bpb.Buffer)
	if err != nil {
		fmt.Println(err)
		return
	}

	packet := rawPacket.FromBuffer(&bpb)

	fmt.Printf("%+v\n", packet.Header)
	for _, rec := range packet.Question {
		fmt.Printf("%+v\n", rec)
	}

	for _, rec := range packet.Answers {
		fmt.Printf("%+v\n", rec)
	}

	for _, rec := range packet.Authorities {
		fmt.Printf("%+v\n", rec)
	}

	for _, rec := range packet.Resources {
		fmt.Printf("%+v\n", rec)
	}

}
