package tcp

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"

	"github.com/maxcelant/tcp-from-scratch/internal/checksum"
)

const HeaderMinLength = 20

type Header struct {
	SourcePort, DestPort uint16
	SeqNumber, AckNumber uint32
	DataOffset           uint8
	Flags                uint8
	Window               uint16
	Checksum             uint16
	Urgent               uint16
	Kind, Length         uint8
	MSS                  uint16
}

var (
	ErrTooShort = errors.New("tcp: buffer too short")
)

func Parse(b []byte) (*Header, []byte, error) {
	if len(b) < HeaderMinLength {
		return nil, nil, ErrTooShort
	}
	h := &Header{}
	h.SourcePort = binary.BigEndian.Uint16(b[:2])
	h.DestPort = binary.BigEndian.Uint16(b[2:4])
	h.SeqNumber = binary.BigEndian.Uint32(b[4:8])
	h.AckNumber = binary.BigEndian.Uint32(b[8:12])
	h.DataOffset = (offsetMask & b[12]) >> 4
	if h.DataOffset*4 < HeaderMinLength {
		return nil, nil, ErrTooShort
	}
	h.Flags = FlagsMask & b[13]
	h.Window = binary.BigEndian.Uint16(b[14:16])
	h.Checksum = binary.BigEndian.Uint16(b[16:18])
	h.Urgent = binary.BigEndian.Uint16(b[18:20])
	// Data offset tells us when the payload starts
	if h.DataOffset > 5 {
		h.Kind = b[20]
		if h.Kind == 2 {
			h.Length = b[21]
			h.MSS = binary.BigEndian.Uint16(b[22 : h.DataOffset*4])
		}
	}
	return h, b[h.DataOffset*4:], nil
}

func (h Header) Marshal(dst []byte, sourceIp, destIp netip.Addr, payload []byte) (int, error) {
	headerSize := int(h.DataOffset * 4)
	if headerSize < HeaderMinLength {
		return 0, ErrTooShort
	}
	if len(dst) < HeaderMinLength {
		return 0, ErrTooShort
	}
	binary.BigEndian.PutUint16(dst[0:2], h.SourcePort)
	binary.BigEndian.PutUint16(dst[2:4], h.DestPort)
	binary.BigEndian.PutUint32(dst[4:8], h.SeqNumber)
	binary.BigEndian.PutUint32(dst[8:12], h.AckNumber)
	dst[12] = h.DataOffset << 4
	dst[13] = h.Flags
	binary.BigEndian.PutUint16(dst[14:16], h.Window)
	dst[16] = 0 // Zero the checksum
	dst[17] = 0 // Zero the checksum
	dst[18] = 0
	dst[19] = 0
	if h.DataOffset > 5 {
		dst[20] = h.Kind
		if h.MSS != 0 {
			dst[21] = h.Length
			binary.BigEndian.PutUint16(dst[22:24], h.MSS)
		}
	}

	pseudo := make([]byte, 12)
	// IP source address
	addr4 := sourceIp.As4()
	pseudo[0] = addr4[0]
	pseudo[1] = addr4[1]
	pseudo[2] = addr4[2]
	pseudo[3] = addr4[3]
	// IP destination address
	addr4 = destIp.As4()
	pseudo[4] = addr4[0]
	pseudo[5] = addr4[1]
	pseudo[6] = addr4[2]
	pseudo[7] = addr4[3]
	pseudo[8] = 0
	// PTCL
	pseudo[9] = 6
	// TCP Length
	tcpLen := uint16(headerSize) + uint16(len(payload))
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(tcpLen))

	checksum := checksum.Sum(slices.Concat(pseudo, dst[:headerSize], payload))
	binary.BigEndian.PutUint16(dst[16:18], checksum)
	return headerSize, nil
}

func (h Header) AppendMarshal(dst []byte, sourceIp, destIp netip.Addr, payload []byte) ([]byte, error) {
	headerSize := int(h.DataOffset * 4)
	if headerSize < HeaderMinLength {
		return dst, ErrTooShort
	}
	start := len(dst)
	dst = append(dst, make([]byte, headerSize)...)
	b := dst[start:] // window over the TCP region we just added; dst stays the full packet
	binary.BigEndian.PutUint16(b[0:2], h.SourcePort)
	binary.BigEndian.PutUint16(b[2:4], h.DestPort)
	binary.BigEndian.PutUint32(b[4:8], h.SeqNumber)
	binary.BigEndian.PutUint32(b[8:12], h.AckNumber)
	b[12] = h.DataOffset << 4
	b[13] = h.Flags
	binary.BigEndian.PutUint16(b[14:16], h.Window)
	b[16] = 0 // Zero the checksum
	b[17] = 0 // Zero the checksum
	b[18] = 0
	b[19] = 0
	if h.DataOffset > 5 {
		b[20] = h.Kind
		if h.MSS != 0 {
			b[21] = h.Length
			binary.BigEndian.PutUint16(b[22:24], h.MSS)
		}
	}

	pseudo := make([]byte, 12)
	// IP source address
	addr4 := sourceIp.As4()
	pseudo[0] = addr4[0]
	pseudo[1] = addr4[1]
	pseudo[2] = addr4[2]
	pseudo[3] = addr4[3]
	// IP destination address
	addr4 = destIp.As4()
	pseudo[4] = addr4[0]
	pseudo[5] = addr4[1]
	pseudo[6] = addr4[2]
	pseudo[7] = addr4[3]
	pseudo[8] = 0
	// PTCL
	pseudo[9] = 6
	// TCP Length
	tcpLen := uint16(headerSize) + uint16(len(payload))
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(tcpLen))

	checksum := checksum.Sum(slices.Concat(pseudo, b[:headerSize], payload))
	binary.BigEndian.PutUint16(b[16:18], checksum)
	return dst, nil
}
