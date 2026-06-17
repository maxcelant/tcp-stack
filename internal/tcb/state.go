package tcb

import "fmt"

type State int

const (
	StateClosed State = iota
	StateListen
	StateSynSent
	StateSynReceived
	StateEstablished
	StateFinWait1
	StateFinWait2
	StateClosing
	StateCloseWait
	StateLastAck
	StateTimeWait
)

var states = map[State]string{
	StateClosed:      "CLOSED",
	StateListen:      "LISTEN",
	StateSynSent:     "SYN-SENT",
	StateSynReceived: "SYN-RECEIVED",
	StateEstablished: "ESTABLISHED",
	StateFinWait1:    "FIN-WAIT-1",
	StateFinWait2:    "FIN-WAIT-2",
	StateClosing:     "CLOSING",
	StateCloseWait:   "CLOSE-WAIT",
	StateLastAck:     "LAST-ACK",
	StateTimeWait:    "TIME-WAIT",
}

func (s State) String() string {
	st, ok := states[s]
	if !ok {
		return fmt.Sprintf("State(%d)", int(s))
	}
	return st
}
