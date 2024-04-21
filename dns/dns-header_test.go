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

	if header.opcode != 0x0 {
		t.Errorf("expected header.opcode to be 0x0, but got %x", header.opcode)
	}

	if header.response != true {
		t.Error("expected header.response to be true, but got false")
	}

	if header.Recursion_desired != true {
		t.Error("expected header.recursion_desired to be true, but got false")
	}

	if header.truncated_message != false {
		t.Error("expected header.truncated_message to be false, but got true")
	}

	if header.authoritative_answer != false {
		t.Error("expected header.authoritative_answer to be false, but got true")
	}

	if header.rescode != resultcode.NOERROR {
		t.Errorf("expected header.rescode to be NOERROR, but got %v", header.rescode)
	}

	if header.checking_disabled != false {
		t.Error("expected header.checking_disabled to be false, but got true")
	}

	if header.authed_data != false {
		t.Error("expected header.authed_data to be false, but got true")
	}

	if header.z != false {
		t.Error("expected header.z to be false, but got true")
	}

	if header.recursion_available != false {
		t.Error("expected header.recursion_available to be false, but got true")
	}

	if header.Questions != 1 {
		t.Errorf("expected header.questions to be 1, but got %d", header.Questions)
	}

	if header.answers != 1 {
		t.Errorf("expected header.answers to be 1, but got %d", header.answers)
	}

	if header.authoritative_entries != 0 {
		t.Errorf("expected header.authoritative_entries to be 0, but got %d", header.authoritative_entries)
	}

	if header.resource_entries != 0 {
		t.Errorf("expected header.resource_entries to be 0, but got %d", header.resource_entries)
	}
}
