package tcb

import "sync"

type SendBuffer struct {
	buf   []byte
	start uint32

	mu sync.RWMutex
}

func NewSendBuffer(start uint32) *SendBuffer {
	return &SendBuffer{
		buf:   make([]byte, 0),
		start: start,
	}
}

func (s *SendBuffer) Write(p []byte) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf = append(s.buf, p...)
	return len(p)
}

func (s *SendBuffer) Acked(ack uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := ack - s.start
	s.buf = s.buf[i:]
	s.start = ack
}

func (s *SendBuffer) NextChunk(size uint16) ([]byte, uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if size > uint16(len(s.buf)) {
		size = uint16(len(s.buf))
	}
	return s.buf[:size], size
}
