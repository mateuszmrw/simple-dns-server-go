package packetbuffer

import (
	"errors"
	"strings"
)

const bufferSize = 512

var errEndOfBuffer = errors.New("end of buffer")

type PacketBuffer struct {
	Buffer   []byte
	position uint
}

func NewPacketBuffer() PacketBuffer {
	return PacketBuffer{
		Buffer:   make([]byte, bufferSize),
		position: 0,
	}
}

func (pb PacketBuffer) Pos() uint {
	return pb.position
}

func (pb *PacketBuffer) Step(steps uint) {
	pb.position += steps
}

func (pb *PacketBuffer) SetPosition(pos uint) {
	pb.position = pos
}

func (pb *PacketBuffer) SetValue_u8(pos uint, val uint8) {
	pb.Buffer[pos] = val
}

func (pb *PacketBuffer) SetValue_u16(pos uint, val uint16) {
	pb.SetValue_u8(pos, uint8(val>>8))
	pb.SetValue_u8(pos+1, uint8(val&0xFF))
}

// Read single byte and move the position one step forward
func (pb *PacketBuffer) Read() (byte, error) {
	if pb.Pos() >= bufferSize {
		newError := errEndOfBuffer
		return 0, newError
	}

	response := pb.Buffer[pb.position]
	pb.position += 1
	return response, nil
}

// Get a single byte, without changing the buffer position
func (pb PacketBuffer) Get(pos uint) (byte, error) {
	if pb.Pos() >= bufferSize {
		newError := errEndOfBuffer
		return 0, newError
	}
	return pb.Buffer[pos], nil
}

func (pb PacketBuffer) GetRange(start uint, len uint) ([]byte, error) {
	if start+len >= bufferSize {
		return nil, errEndOfBuffer
	}
	buffer := pb.Buffer[start : start+len]
	return buffer, nil
}

func (pb *PacketBuffer) Read_u16() (uint16, error) {
	hi, err := pb.Read()
	if err != nil {
		return 0, err
	}
	lo, err := pb.Read()
	if err != nil {
		return 0, err
	}
	result := uint16(hi)<<8 | uint16(lo)
	return result, nil
}

func (pb *PacketBuffer) Read_u32() (uint32, error) {
	hi1, err := pb.Read()
	if err != nil {
		return 0, err
	}
	hi2, err := pb.Read()
	if err != nil {
		return 0, err
	}
	lo1, err := pb.Read()
	if err != nil {
		return 0, err
	}
	lo2, err := pb.Read()
	if err != nil {
		return 0, err
	}
	result := uint32(hi1)<<24 | uint32(hi2)<<16 | uint32(lo1)<<8 | uint32(lo2)<<0
	return result, nil
}

func (pb *PacketBuffer) ReadQname() (string, error) {
	var labels []string
	var returnPos *uint

	parseData := pb.Buffer
	pos := pb.position
	largestPos := len(pb.Buffer)

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
			if offset >= len(pb.Buffer) {
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
			parseData = pb.Buffer[offset:]
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
		pb.position = *returnPos + 2
	} else {
		pb.position = pos + 1
	}

	return strings.Join(labels, "."), nil
}

func (pb *PacketBuffer) Write(val uint8) error {
	if pb.Pos() >= bufferSize {
		newError := errEndOfBuffer
		return newError
	}
	pb.Buffer[pb.Pos()] = val
	pb.position += 1
	return nil
}

func (pb *PacketBuffer) Write_uint8(val uint8) error {
	return pb.Write(val)
}

func (pb *PacketBuffer) Write_uint16(val uint16) error {
	pb.Write(uint8(val >> 8))
	pb.Write(uint8(val & 0xFF))
	return nil
}

func (pb *PacketBuffer) Write_uint32(val uint32) error {
	pb.Write(uint8(((val >> 24) & 0xFF)))
	pb.Write(uint8(((val >> 16) & 0xFF)))
	pb.Write(uint8(((val >> 8) & 0xFF)))
	pb.Write(uint8(((val >> 0) & 0xFF)))
	return nil
}

func (pb *PacketBuffer) WriteQname(qname string) error {
	for _, label := range strings.Split(qname, ".") {
		len := len(label)
		if len > 0x3F {
			return errors.New("single label exceeds 63 characters of length")
		}

		e := pb.Write_uint8(uint8(len))
		if e != nil {
			return e
		}
		for _, byteVal := range []byte(label) {
			e := pb.Write_uint8(byteVal)
			if e != nil {
				return e
			}
		}
	}
	err := pb.Write_uint8(uint8(0))
	if err != nil {
		return err
	}

	return nil
}
