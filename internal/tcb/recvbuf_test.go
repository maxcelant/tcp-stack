package tcb

import (
	"bytes"
	"testing"
	"time"
)

func TestBufferWrite(t *testing.T) {
	b := NewRecvBuffer()
	client := make([]byte, 2)
	received := []byte{0xFF, 0xFE}
	b.Write(received)
	i, err := b.Read(client)
	if err != nil {
		t.Fatalf("error occured: %s", err.Error())
	}
	for i := range len(client[:i]) {
		if client[i] != received[i] {
			t.Fatalf("client=%b, want=%b", client[i], received[i])
		}
	}
}

func TestPartialBufferWrite(t *testing.T) {
	b := NewRecvBuffer()
	client := make([]byte, 2)
	received := []byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB}
	b.Write(received)
	i, err := b.Read(client)
	if err != nil {
		t.Fatalf("error occured: %s", err.Error())
	}
	if i != 2 {
		t.Fatalf("got=%d, want=%d", i, 2)
	}
	// Client only read 2 bytes
	for i := range len(client[:i]) {
		if client[i] != received[i] {
			t.Fatalf("client=%b, want=%b", client[i], received[i])
		}
	}
	// Check whats still in the buffer
	remaining := received[i:]
	for i := range len(b.buf) {
		if b.buf[i] != remaining[i] {
			t.Fatalf("client=%b, want=%b", b.buf[i], remaining[i])
		}
	}
}

func TestBlockedReadAwakes(t *testing.T) {
	type result struct {
		buf []byte
		err error
	}
	sent := []byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB}

	done := make(chan result, 1)
	b := NewRecvBuffer()

	go func() {
		buf := make([]byte, len(sent))
		i, err := b.Read(buf)
		done <- result{buf[:i], err}
	}()

	select {
	case r := <-done:
		t.Fatalf("Read returned before any Write (did not block): %+v", r)
	case <-time.After(50 * time.Millisecond):
		// still parked in Wait — good
	}

	b.Write(sent)

	select {
	case res := <-done:
		if res.err != nil {
			t.Fatal(res.err)
		}
		if !bytes.Equal(res.buf, sent) {
			t.Fatal("bytes in output to equal sent")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout reached for Read")
	}
}
