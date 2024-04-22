package main

import (
	"dns-client-go/dns"
	packetbuffer "dns-client-go/packetbuffer"
	querytype "dns-client-go/query-type"
	resultcode "dns-client-go/result-code"
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

func handleQuery(conn *net.UDPConn) error {
	requestBuffer := packetbuffer.NewPacketBuffer()
	_, src, err := conn.ReadFromUDP(requestBuffer.Buffer)

	if err != nil {
		return fmt.Errorf("failed to read from UDP Socket: %w", err)
	}

	reqPacket := dns.NewPacket()
	request := reqPacket.FromBuffer(&requestBuffer)

	response := dns.NewPacket()
	response.Header.ID = request.Header.ID
	response.Header.RecursionDesired = true
	response.Header.RecursionAvailable = true
	response.Header.Response = true

	if len(request.Question) > 0 {
		question := request.Question[0]

		result, err := lookup(question.Name, question.Qtype)
		if err != nil {
			response.Header.Rescode = resultcode.SERVFAIL
		} else {
			response.Question = append(response.Question, question)
			response.Header.Rescode = result.Header.Rescode
			response.Answers = result.Answers
			response.Authorities = result.Authorities
			response.Resources = result.Resources
		}
	} else {
		response.Header.Rescode = resultcode.FORMERR
	}

	resBuffer := packetbuffer.NewPacketBuffer()
	response.Write(&resBuffer)

	len := resBuffer.Pos()
	data, err := resBuffer.GetRange(0, len)
	if err != nil {
		return fmt.Errorf("failed to serialize response packet: %w", err)
	}

	_, err = conn.WriteToUDP(data, src)
	if err != nil {
		return fmt.Errorf("failed to send response: %w", err)
	}

	return nil
}

func main() {
	addr := net.UDPAddr{
		Port: 2053,
		IP:   net.ParseIP("0.0.0.0"),
	}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	fmt.Println("DNS server listening on port 2053")
	for {
		if err := handleQuery(conn); err != nil {
			fmt.Println("Error handling query:", err)
		}
	}
}
