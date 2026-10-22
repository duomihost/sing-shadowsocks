package shadowaead_2022

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type stalledPacketHandler struct {
	*countingHandler
	ended chan struct{}
}

func (h *stalledPacketHandler) NewPacketConnection(ctx context.Context, _ N.PacketConn, _ M.Metadata) error {
	<-ctx.Done()
	close(h.ended)
	return ctx.Err()
}
func TestBoundedUDPQueueAndCancellation(t *testing.T) {
	f := newReplayFixture(t)
	h := &stalledPacketHandler{countingHandler: newCountingHandler(), ended: make(chan struct{})}
	f.service.handler = h
	f.service.SetUDPPolicy(UDPPolicy{MaxSessions: 1, MaxReplayEntries: 1, QueuePackets: 1, MaxQueuedBytes: 4, MaxQueuedBytesPerUser: 4})
	packets := f.udpPackets(3)
	for _, packet := range packets {
		start := time.Now()
		if err := f.serveUDP(packet); err != nil {
			t.Fatal(err)
		}
		if time.Since(start) > time.Second {
			t.Fatal("shared receiver blocked on a full queue")
		}
	}
	if got := f.service.UDPDrops(); got != 2 {
		t.Fatalf("queue drops=%d", got)
	}
	f.service.queueBudget.mu.Lock()
	queued := f.service.queueBudget.total
	f.service.queueBudget.mu.Unlock()
	if queued != 4 {
		t.Fatalf("queued bytes=%d", queued)
	}
	if f.service.retention() < 60*time.Second {
		t.Fatal("replay retention too short")
	}
	if err := f.service.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-h.ended:
	case <-time.After(time.Second):
		t.Fatal("revocation did not cancel pending routing")
	}
	f.service.queueBudget.mu.Lock()
	queued = f.service.queueBudget.total
	f.service.queueBudget.mu.Unlock()
	if queued != 0 {
		t.Fatal("queued buffer budget leaked on close")
	}
}

type fragmentHeader struct {
	reader io.Reader
	calls  int
}

func (r *fragmentHeader) Read(p []byte) (int, error) {
	r.calls++
	if len(p) > 8 {
		p = p[:8]
	}
	return r.reader.Read(p)
}
func TestFirstHeaderRemainsSingleReadWithCallback(t *testing.T) {
	f := newReplayFixture(t)
	wire := f.tcpRequest()
	reader := &fragmentHeader{reader: &replayConn{r: bytes.NewReader(wire)}}
	calls := 0
	err := f.service.NewConnection0(context.Background(), &replayConn{r: bytes.NewReader(wire)}, M.Metadata{}, reader, func() { calls++ })
	if err == nil || reader.calls != 1 || calls != 0 {
		t.Fatalf("fragmented first header accepted or accumulated: %v reads=%d callback=%d", err, reader.calls, calls)
	}
}
func TestExactUserKeyAndSnapshotCopy(t *testing.T) {
	f := newReplayFixture(t)
	key := append([]byte(nil), f.client.pskList[1]...)
	if _, err := f.service.PrepareUsers([]string{"user"}, [][]byte{append(key, 1)}, 3); err == nil {
		t.Fatal("oversized user key accepted")
	}
	prepared, err := f.service.PrepareUsers([]string{"user"}, [][]byte{key}, 4)
	if err != nil {
		t.Fatal(err)
	}
	prepared.Publish()
	key[0] ^= 1
	if err = f.serveTCP(f.tcpRequest()); err != nil {
		t.Fatalf("caller key mutation altered published credentials: %v", err)
	}
}
