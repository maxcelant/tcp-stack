package tcp

import (
	"log"
	"net/netip"
	"slices"
	"strconv"

	"github.com/maxcelant/tcp-from-scratch/internal/ipv4"
	"github.com/maxcelant/tcp-from-scratch/internal/tcb"
	"github.com/maxcelant/tcp-from-scratch/internal/tun"
)

type Conn struct {
	TCB *tcb.TCB
	buf []byte
}

func (c *Conn) marshalTCP(dst []byte, flags uint8, payload []byte) ([]byte, error) {
	return (Header{
		SourcePort: c.TCB.Local.Port(),
		DestPort:   c.TCB.Remote.Port(),
		Flags:      flags,
		Window:     c.TCB.Snd.WND,
		SeqNumber:  c.TCB.Snd.NXT,
		AckNumber:  c.TCB.Recv.NXT,
		DataOffset: 5,
	}).AppendMarshal(dst, c.TCB.Local.Addr(), c.TCB.Remote.Addr(), payload)
}

func (c *Conn) marshalIP(dst []byte, payloadSize uint16) ([]byte, error) {
	i, err := (&ipv4.Header{
		Version: 4,
		IHL:     5,
		// 20 bytes for IP header + 20 bytes for TCP header + payload
		// TODO Make dynamic in a clean way
		TotalLength: 40 + payloadSize,
		TTL:         64,
		Protocol:    ipv4.ProtoStrToUInt8[ipv4.ProtoTCP],
		SourceAddr:  c.TCB.Local.Addr(),
		DestAddr:    c.TCB.Remote.Addr(),
		// + Identification, Flags/FragOffset=0, header checksum
	}).Marshal(dst)
	if err != nil {
		return dst[:i], err
	}
	return dst[:i], nil

}

func (c *Conn) send(flags uint8, payload []byte, f func([]byte) error) error {
	buf := make([]byte, 20)
	buf, err := c.marshalIP(buf, uint16(len(payload)))
	if err != nil {
		return err
	}
	buf, err = c.marshalTCP(buf, flags, payload)
	if err != nil {
		return err
	}
	return f(slices.Concat(buf, payload))
}

type Listener struct {
	local  netip.AddrPort
	demux  *demux
	device *tun.Device
	connCh chan *Conn
}

func Listen(local netip.AddrPort) (*Listener, error) {
	d, err := tun.Open("tun0")
	if err != nil {
		return nil, err
	}

	l := &Listener{
		local:  local,
		demux:  NewDemux(),
		device: d,
		connCh: make(chan *Conn, 100),
	}

	buf := make([]byte, 1500)
	go func() {
		for {
			i, err := l.device.Read(buf)
			if err != nil {
				log.Printf("listener(error): failed to read for device: %s: %s\n", l.device.Name(), err.Error())
				return
			}
			ip, payload, err := ipv4.Parse(buf[:i])
			if err != nil {
				log.Printf("listener(error): error occured while parsing buffer: %s\n", err.Error())
				continue
			}
			if !ip.IsProtocol(ipv4.ProtoTCP) {
				log.Println("listener(error): protocol for packet is not TCP, skipping")
				continue
			}
			seg, payload, err := Parse(payload[:i])
			if err != nil {
				log.Printf("listener(error): failure occured while parsing buffer: %s\n", err.Error())
				continue
			}
			localAddrPort := netip.MustParseAddrPort(ip.DestAddr.String() + ":" + strconv.Itoa(int(seg.DestPort)))
			remoteAddrPort := netip.MustParseAddrPort(ip.SourceAddr.String() + ":" + strconv.Itoa(int(seg.SourcePort)))
			connKey := connKey{
				local:  localAddrPort,
				remote: remoteAddrPort,
			}
			var conn *Conn
			conn, exists := l.demux.Get(connKey)
			if !exists {
				if localAddrPort != l.local {
					continue // not addressed to us; ignore (later: RST)
				}
				if seg.Flags != FlagSYN {
					// TODO Send RST
					log.Println("listener(warning): received new connection without SYN flag")
					continue
				}
				conn = &Conn{
					TCB: &tcb.TCB{
						State: tcb.StateSynReceived,
						Snd: tcb.Send{
							ISS: 0, // TODO Make this a random number
							UNA: 0,
							WND: 1460,
							NXT: 0,
						},
						Recv: tcb.Receive{
							NXT: seg.SeqNumber + 1,
							WND: seg.Window,
							IRS: seg.SeqNumber,
						},
						Local:  localAddrPort,
						Remote: remoteAddrPort,
					},
				}
				if ok := l.demux.Set(connKey, conn); !ok {
					log.Printf("listener(info): connection already exists in demux map :%v\n", connKey)
				}
				if err := conn.send(FlagSYN|FlagACK, nil, func(b []byte) error {
					_, err := l.device.Write(b)
					return err
				}); err != nil {
					log.Printf("listener(error): failed during write to device: %s", err.Error())
					continue
				}
				conn.TCB.Snd.NXT = conn.TCB.Snd.ISS + 1
			} else {
				// if seg.AckNumber != conn.TCB.Snd.NXT {
				// 	log.Printf("listener(error): ACK does not equal SND.NXT %d!=%d\n", seg.AckNumber, conn.TCB.Snd.NXT)
				// 	continue
				// }
				// conn.TCB.Snd.UNA = seg.AckNumber
				// conn.TCB.State = tcb.StateEstablished
				// l.connCh <- conn
			}

		}
	}()
	return l, nil
}

func (l *Listener) Accept() (*Conn, error) {
	return <-l.connCh, nil
}

func (l *Listener) Close() error {
	log.Println("listener: closing device")
	return l.device.Close()
}
