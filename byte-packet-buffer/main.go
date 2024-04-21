package bytepacketbuffer

import (
	"errors"
	"strings"
)

const bufferSize = 512

var errEndOfBuffer = errors.New("end of buffer")

type BytePacketBuffer struct {
	Buffer   []byte
	position uint
}

func NewPacketBuffer() BytePacketBuffer {
	return BytePacketBuffer{
		Buffer:   make([]byte, bufferSize),
		position: 0,
	}
}

func (bpb BytePacketBuffer) Pos() uint {
	return bpb.position
}

func (bpb *BytePacketBuffer) Step(steps uint) {
	bpb.position += steps
}

func (bpb *BytePacketBuffer) Set(pos uint) {
	bpb.position = pos
}

// Read single byte and move the position one step forward
func (bpb *BytePacketBuffer) Read() (byte, error) {
	if bpb.Pos() >= bufferSize {
		newError := errEndOfBuffer
		return 0, newError
	}

	response := bpb.Buffer[bpb.position]
	bpb.position += 1
	return response, nil
}

// Get a single byte, without changing the buffer position
func (bpb BytePacketBuffer) Get(pos uint) (byte, error) {
	if bpb.Pos() >= bufferSize {
		newError := errEndOfBuffer
		return 0, newError
	}
	return bpb.Buffer[pos], nil
}

func (bpb BytePacketBuffer) GetRange(start uint, len uint) ([]byte, error) {
	if start+len >= bufferSize {
		return nil, errEndOfBuffer
	}
	buffer := bpb.Buffer[start : start+len]
	return buffer, nil
}

func (bpb *BytePacketBuffer) Read_u16() (uint16, error) {
	hi, err := bpb.Read()
	if err != nil {
		return 0, err
	}
	lo, err := bpb.Read()
	if err != nil {
		return 0, err
	}
	result := uint16(hi)<<8 | uint16(lo)
	return result, nil
}

func (bpb *BytePacketBuffer) Read_u32() (uint32, error) {
	hi1, err := bpb.Read()
	if err != nil {
		return 0, err
	}
	hi2, err := bpb.Read()
	if err != nil {
		return 0, err
	}
	lo1, err := bpb.Read()
	if err != nil {
		return 0, err
	}
	lo2, err := bpb.Read()
	if err != nil {
		return 0, err
	}
	result := uint32(hi1)<<24 | uint32(hi2)<<16 | uint32(lo1)<<8 | uint32(lo2)<<0
	return result, nil
}

func (bpb *BytePacketBuffer) ReadQname(name string) (string, error) {
	var labels []string
	var returnPos *uint

	parseData := bpb.Buffer
	pos := bpb.position
	largestPos := len(bpb.Buffer)

	for {
		if len(parseData) <= int(pos) {
			return "", errors.New("unexpected EOF")
		}

		length := parseData[pos]
		pos++

		if length&0xC0 == 0xC0 {
			if len(parseData) < int(pos+2) {
				return "", errors.New("unexpected EOF")
			}

			offset := int(parseData[pos-1]&0x3F)<<8 | int(parseData[pos])
			if offset >= len(bpb.Buffer) {
				return "", errors.New("unexpected EOF")
			}

			if returnPos == nil {
				val := pos - 1
				returnPos = &val
			}

			if offset >= largestPos {
				return "", errors.New("bad pointer")
			}

			largestPos = offset
			pos = 0
			parseData = bpb.Buffer[offset:]
		} else if length&0xC0 == 0 {
			end := int(pos) + int(length)
			if len(parseData) < end {
				return "", errors.New("unexpected EOF")
			}

			labels = append(labels, string(parseData[pos:end]))
			pos = uint(end)

			if len(parseData) <= int(pos) {
				return "", errors.New("unexpected EOF")
			}
		} else {
			return "", errors.New("unknown label format")
		}

		if parseData[pos] == 0 {
			break
		}
	}

	if returnPos != nil {
		bpb.position = *returnPos + 2
	} else {
		bpb.position = pos + 1
	}

	return strings.Join(labels, "."), nil
}

func (b *BytePacketBuffer) Write(val uint8) error {
	if b.Pos() >= bufferSize {
		newError := errEndOfBuffer
		return newError
	}
	b.Buffer[b.Pos()] = val
	b.position += 1
	return nil
}

func (b *BytePacketBuffer) Write_uint8(val uint8) error {
	return b.Write(val)
}

func (bpb *BytePacketBuffer) Write_uint16(val uint16) error {
	bpb.Write(uint8(val >> 8))
	bpb.Write(uint8(val & 0xFF))
	return nil
}

func (b *BytePacketBuffer) Write_uint32(val uint32) error {
	b.Write(uint8(((val >> 24) & 0xFF)))
	b.Write(uint8(((val >> 16) & 0xFF)))
	b.Write(uint8(((val >> 8) & 0xFF)))
	b.Write(uint8(((val >> 0) & 0xFF)))
	return nil
}

func (b *BytePacketBuffer) Write_qname(qname string) error {
	for _, label := range strings.Split(qname, ".") {
		len := len(label)
		if len > 0x3F {
			return errors.New("Single label exceeds 63 characters of length")
		}

		e := b.Write_uint8(uint8(len))
		if e != nil {
			return e
		}
		for _, byteVal := range []byte(label) {
			e := b.Write_uint8(byteVal)
			if e != nil {
				return e
			}
		}
	}
	err := b.Write_uint8(uint8(0))
	if err != nil {
		return err
	}

	return nil
}
