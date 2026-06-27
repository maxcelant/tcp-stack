package tcp

import "github.com/maxcelant/tcp-from-scratch/internal/tcb"

const (
	FlagFIN = 1 << 0
	FlagSYN = 1 << 1
	FlagRST = 1 << 2
	FlagPSH = 1 << 3
	FlagACK = 1 << 4
	FlagURG = 1 << 5
)

const HeaderMinLength = 20
const FlagsMask = 0b0011_1111 // We only care about the low 6 bits for flags
const offsetMask = 0b1111_0000

// tcpOutFlags allows us to resolve the baseline flags for a segment
// We can add additional flags on top of these depending on conditions
var tcpOutFlags = map[tcb.State]uint8{
	tcb.StateSynReceived: FlagSYN | FlagACK,
	tcb.StateEstablished: FlagACK,
}
