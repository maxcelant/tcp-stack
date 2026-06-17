package tcb

import (
	"fmt"
	"net/netip"
	"strings"
)

type Send struct {
	UNA uint32 // Oldest unacked
	NXT uint32 // Next to send
	WND uint16 // Send window
	ISS uint32 // Initial send sequence
}

type Receive struct {
	NXT uint32 // Next expected
	WND uint16 // Receive window size
	IRS uint32 // Initial receive sequence
}

// Transfer control block for one connection
type TCB struct {
	State  State
	Snd    Send
	Recv   Receive
	Local  netip.AddrPort
	Remote netip.AddrPort
}

func (t TCB) String() string {
	b := strings.Builder{}
	b.WriteRune('{')
	fmt.Fprintf(&b, "State=%s", t.State.String())
	fmt.Fprintf(&b, "Local=%s", t.Local.String())
	fmt.Fprintf(&b, "Remote=%s", t.Remote.String())
	b.WriteRune('}')
	return b.String()
}
