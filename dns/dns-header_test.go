package dns

import (
	bytepacketbuffer "dns-client-go/byte-packet-buffer"
	resultcode "dns-client-go/result-code"
	"testing"
)

func TestDnsHeader_Read(t *testing.T) {
	data := []byte{
		0x33, 0x33, // Transaction ID
		0x81, 0x80, // Flags
		0x00, 0x01, // Questions
		0x00, 0x01, // Answers
		0x00, 0x00, // Authority RRs
		0x00, 0x00, // Additional RRs
	}

	buffer := bytepacketbuffer.NewPacketBuffer()
	buffer.Buffer = data

	header := &DnsHeader{}
	header.Read(&buffer)

	if header.ID != 13107 {
		t.Errorf("expected header.id to be 13107, but got %d", header.ID)
	}

	if header.Opcode != 0x0 {
		t.Errorf("expected header.opcode to be 0x0, but got %x", header.Opcode)
	}

	if header.Response != true {
		t.Error("expected header.response to be true, but got false")
	}

	if header.RecursionDesired != true {
		t.Error("expected header.recursion_desired to be true, but got false")
	}

	if header.TruncatedMessage != false {
		t.Error("expected header.truncated_message to be false, but got true")
	}

	if header.AuthoritativeAnswer != false {
		t.Error("expected header.authoritative_answer to be false, but got true")
	}

	if header.Rescode != resultcode.NOERROR {
		t.Errorf("expected header.rescode to be NOERROR, but got %v", header.Rescode)
	}

	if header.CheckingDisabled != false {
		t.Error("expected header.checking_disabled to be false, but got true")
	}

	if header.AuthedData != false {
		t.Error("expected header.authed_data to be false, but got true")
	}

	if header.Z != false {
		t.Error("expected header.z to be false, but got true")
	}

	if header.RecursionAvailable != false {
		t.Error("expected header.recursion_available to be false, but got true")
	}

	if header.Questions != 1 {
		t.Errorf("expected header.questions to be 1, but got %d", header.Questions)
	}

	if header.Answers != 1 {
		t.Errorf("expected header.answers to be 1, but got %d", header.Answers)
	}

	if header.AuthoritiveEntries != 0 {
		t.Errorf("expected header.authoritative_entries to be 0, but got %d", header.AuthoritiveEntries)
	}

	if header.ResourceEntries != 0 {
		t.Errorf("expected header.resource_entries to be 0, but got %d", header.ResourceEntries)
	}
}
