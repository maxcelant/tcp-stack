package tcp

import (
	"encoding/hex"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/maxcelant/tcp-from-scratch/internal/ipv4"
)

func TestHeaderParseBasic(t *testing.T) {
	raw, err := os.ReadFile(path.Join("..", "..", "testdata", "syn.hex"))
	if err != nil {
		t.Fatal(err)
	}
	stripped := strings.Join(strings.Fields(string(raw)), "")
	decoded, err := hex.DecodeString(stripped)
	if err != nil {
		t.Fatal(err)
	}
	_, tcpPayload, err := ipv4.Parse(decoded)
	if err != nil {
		t.Fatal(err)
	}
	tcpHeader, _, err := Parse(tcpPayload)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		got  uint32
		want uint32
	}{
		{"SourcePort", uint32(tcpHeader.SourcePort), 49152},
		{"DestPort", uint32(tcpHeader.DestPort), 7777},
		{"SeqNumber", tcpHeader.SeqNumber, 0x11223344},
		{"AckNumber", tcpHeader.AckNumber, 0},
		{"Window", uint32(tcpHeader.Window), 64240},
		{"Urgent", uint32(tcpHeader.Urgent), 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("%s=%d, want %d", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestHeaderMarshalBasic(t *testing.T) {
	raw, err := os.ReadFile(path.Join("..", "..", "testdata", "syn.hex"))
	if err != nil {
		t.Fatal(err)
	}
	stripped := strings.Join(strings.Fields(string(raw)), "")
	decoded, err := hex.DecodeString(stripped)
	if err != nil {
		t.Fatal(err)
	}
	ipHeader, tcpPayload, err := ipv4.Parse(decoded)
	if err != nil {
		t.Fatal(err)
	}
	tcpHeader, payload, err := Parse(tcpPayload)
	if err != nil {
		t.Fatal(err)
	}
	output := make([]byte, 24)
	_, err = tcpHeader.Marshal(output, ipHeader.SourceAddr, ipHeader.DestAddr, payload)
	if err != nil {
		t.Fatal(err)
	}
	for i := range output {
		if output[i] != tcpPayload[i] {
			t.Fatalf("payload=%d and output=%d\n", output[i], tcpPayload[i])
		}
	}
}

func TestHeaderSynAckParse(t *testing.T) {
	raw, err := os.ReadFile(path.Join("..", "..", "testdata", "synack.hex"))
	if err != nil {
		t.Fatal(err)
	}
	stripped := strings.Join(strings.Fields(string(raw)), "")
	decoded, err := hex.DecodeString(stripped)
	if err != nil {
		t.Fatal(err)
	}
	_, tcpPayload, err := ipv4.Parse(decoded)
	if err != nil {
		t.Fatal(err)
	}
	tcpHeader, _, err := Parse(tcpPayload)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		got  uint32
		want uint32
	}{
		{"SourcePort", uint32(tcpHeader.SourcePort), 7777},
		{"DestPort", uint32(tcpHeader.DestPort), 49152},
		{"SeqNumber", tcpHeader.SeqNumber, 0x55667788},
		{"AckNumber", tcpHeader.AckNumber, 0x11223345},
		{"Flags", uint32(tcpHeader.Flags), FlagsMask & (FlagSYN | FlagACK)},
		{"Window", uint32(tcpHeader.Window), 65535},
		{"Urgent", uint32(tcpHeader.Urgent), 0},
		{"MSS", uint32(tcpHeader.MSS), 1460},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("%s=%d, want %d", tt.name, tt.got, tt.want)
			}
		})
	}
}
