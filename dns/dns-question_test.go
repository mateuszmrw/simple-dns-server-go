package dns

import (
	"testing"

	bytepacketbuffer "dns-client-go/byte-packet-buffer"
	querytype "dns-client-go/query-type"

	"github.com/stretchr/testify/assert"
)

func TestDnsQuestion_Read(t *testing.T) {
	testCases := []struct {
		name          string
		input         []byte
		expectedName  string
		expectedQType querytype.QueryType
	}{
		{
			name: "www.google.com",
			input: []byte{
				0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
				0x00, 0x00, 0x01, 0x00, 0x01,
			},
			expectedName:  "www.google.com",
			expectedQType: querytype.A,
		},
		{
			name: "jump",
			input: []byte{
				0x03, 'w', 'w', 'w', 0x01, 'a', 0x03, 'f', 'o', 'o',
				0x03, 'b', 'a', 'r', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
				0x00, 0x01, 0x00, 0x01,
			},
			expectedName:  "www.a.foo.bar.example.com",
			expectedQType: querytype.A,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buffer := bytepacketbuffer.NewPacketBuffer()
			buffer.Buffer = tc.input
			dq := &DnsQuestion{}
			dq.Read(&buffer)

			assert.Equal(t, tc.expectedName, dq.Name)
			assert.Equal(t, tc.expectedQType, dq.Qtype)

		})
	}
}

func TestDnsQuestion_Write(t *testing.T) {
	buffer := bytepacketbuffer.NewPacketBuffer()

	qname := "google.com"
	qtype := querytype.A
	question := DnsQuestion{
		Name:  qname,
		Qtype: qtype,
	}

	question.Write(&buffer)

	expected := []byte{
		6, 'g', 'o', 'o', 'g', 'l', 'e',
		3, 'c', 'o', 'm',
		0,                    // End of the QNAME
		0, byte(querytype.A), // QTYPE is A, typically value 1
		0, 1, // QCLASS is IN, typically value 1
	}

	if !byteSliceEqual(buffer.Buffer[:buffer.Pos()], expected) {
		t.Errorf("Buffer contents incorrect, got %v, want %v", buffer.Buffer[:buffer.Pos()], expected)
	}
}

func byteSliceEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
