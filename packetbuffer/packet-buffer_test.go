package packetbuffer

import (
	"reflect"
	"testing"
)

func TestBytePacketBuffer_Read(t *testing.T) {
	data := []byte{0x12, 0x34, 0x56, 0x78}
	bpb := PacketBuffer{
		Buffer:   data,
		position: 0,
	}

	b, err := bpb.Read()
	if err != nil {
		t.Fatalf("Error reading byte: %v", err)
	}
	if b != 0x12 {
		t.Errorf("Unexpected byte read: expected=0x12, actual=0x%x", b)
	}

	b, err = bpb.Read()
	if err != nil {
		t.Fatalf("Error reading byte: %v", err)
	}
	if b != 0x34 {
		t.Errorf("Unexpected byte read: expected=0x34, actual=0x%x", b)
	}
}

func TestReadQname(t *testing.T) {

	data := []byte{
		0x03, 'w', 'w', 'w', 0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
	}
	buffer1 := PacketBuffer{
		Buffer:   data,
		position: 0,
	}

	expectedName1 := "www.google.com"
	var outstr1 string
	outstr1, err := buffer1.ReadQname(outstr1)
	if err != nil {
		t.Errorf("Unexpected error while reading qname: %v", err)
	}

	if outstr1 != expectedName1 {
		t.Errorf("Unexpected qname: expected %v, actual %v", expectedName1, outstr1)
	}
}

func TestReadQnameWithJump(t *testing.T) {
	packet := []byte{
		0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x03, 0x77, 0x77, 0x77, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
		0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
		0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
		0x7f, 0x00, 0x00, 0x01,
	}

	bpb := NewPacketBuffer()

	copy(bpb.Buffer, packet)

	// Set the position to the start of the QNAME in the question section
	bpb.SetPosition(12)

	parsedQname, err := bpb.ReadQname("")

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	expectedQname := "www.example.com"
	if parsedQname != expectedQname {
		t.Errorf("Expected QNAME: %s, got: %s", expectedQname, parsedQname)
	}
}

func TestReadQnameWithTwoJumps(t *testing.T) {
	packet := []byte{
		0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x03, 'a', 'p', 'i', 0x03, 'w', 'e', 'b', 0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
		0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
		0x7f, 0x00, 0x00, 0x01,
	}

	bpb := NewPacketBuffer()
	copy(bpb.Buffer, packet)

	// Set the position to the start of the QNAME in the question section
	bpb.SetPosition(12)

	parsedQname, err := bpb.ReadQname("")

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	expectedQname := "api.web.com"
	if parsedQname != expectedQname {
		t.Errorf("Expected QNAME: %s, got: %s", expectedQname, parsedQname)
	}
}

func TestReadQnameWithThreeJumps(t *testing.T) {
	packet := []byte{
		0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x03, 'w', 'w', 'w', 0x03, 'f', 'o', 'o', 0x03, 'b', 'a', 'r',
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
		0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
		0x7f, 0x00, 0x00, 0x01,
	}

	bpb := NewPacketBuffer()
	copy(bpb.Buffer, packet)

	// Set the position to the start of the QNAME in the question section
	bpb.SetPosition(12)

	parsedQname, err := bpb.ReadQname("")

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	expectedQname := "www.foo.bar.example.com"
	if parsedQname != expectedQname {
		t.Errorf("Expected QNAME: %s, got: %s", expectedQname, parsedQname)
	}
}

func TestReadQnameWithFourJumps(t *testing.T) {
	packet := []byte{
		0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x03, 'w', 'w', 'w', 0x01, 'a', 0x03, 'f', 'o', 'o',
		0x03, 'b', 'a', 'r', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
		0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
		0x7f, 0x00, 0x00, 0x01,
	}

	bpb := NewPacketBuffer()
	copy(bpb.Buffer, packet)

	// Set the position to the start of the QNAME in the question section
	bpb.SetPosition(12)

	parsedQname, err := bpb.ReadQname("")

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	expectedQname := "www.a.foo.bar.example.com"
	if parsedQname != expectedQname {
		t.Errorf("Expected QNAME: %s, got: %s", expectedQname, parsedQname)
	}
}

func TestBytePacketBuffer_Write_qname(t *testing.T) {
	tests := []struct {
		name     string
		qname    string
		expected []byte
		wantErr  bool
	}{
		{
			name:     "simple domain",
			qname:    "example.com",
			expected: []byte{0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00},
			wantErr:  false,
		},
		{
			name:    "exceeds label length",
			qname:   "thislabeliswaytoolongforanydnssystemtounderstandandshoulderrornow.com",
			wantErr: true,
		},
		{
			name:     "nested domain",
			qname:    "www.example.com",
			expected: []byte{0x03, 'w', 'w', 'w', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00},
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bpb := NewPacketBuffer()
			err := bpb.WriteQname(tt.qname)
			if (err != nil) != tt.wantErr {
				t.Errorf("Write_qname() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if !reflect.DeepEqual(bpb.Buffer[:len(tt.expected)], tt.expected) {
					t.Errorf("Write_qname() got = %v, want %v", bpb.Buffer[:len(tt.expected)], tt.expected)
				}
			}
		})
	}
}
