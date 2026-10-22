package shadowaead_2022

import (
	"context"
	"net"
	"sync"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

// Closing a server connection from another goroutine while its first Write
// sends the response header must not race (run with -race).
func TestServerConnCloseDuringFirstWrite(t *testing.T) {
	f := newReplayFixture(t)
	h := &connHandler{countingHandler: newCountingHandler(), conns: make(chan net.Conn, 1)}
	f.service.handler = h
	if err := f.serveTCP(f.tcpRequest()); err != nil {
		t.Fatal(err)
	}
	conn := <-h.conns
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = conn.Write([]byte("reply")) }()
	go func() { defer wg.Done(); _ = conn.Close() }()
	wg.Wait()
}

type connHandler struct {
	*countingHandler
	conns chan net.Conn
}

func (h *connHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	h.conns <- conn
	return nil
}
