package shadowaead_2022

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Regression tests for the replay-protection order (final plan T15). They
// reproduce UnauthenticatedTCPSaltStored and BadTimestampConsumesUDPWindow
// against the old code and pass once salts and packet IDs are only recorded
// after the whole request has been validated.

const replayTestMethod = "2022-blake3-aes-128-gcm"

type replayFixture struct {
	t       *testing.T
	service *MultiService[string]
	client  *Method
	skew    atomic.Int64 // seconds added to the server clock
	handler *countingHandler
}

func newReplayFixture(t *testing.T) *replayFixture {
	t.Helper()
	iPSK, uPSK := testKey(16), testKey(16)
	f := &replayFixture{t: t, handler: newCountingHandler()}
	service, err := NewMultiService[string](replayTestMethod, iPSK, 300, f.handler, func() time.Time {
		return time.Now().Add(time.Duration(f.skew.Load()) * time.Second)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = service.UpdateUsers([]string{"user"}, [][]byte{uPSK}); err != nil {
		t.Fatal(err)
	}
	client, err := New(replayTestMethod, [][]byte{iPSK, uPSK}, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.service, f.client = service, client.(*Method)
	return f
}

// tcpRequest records the bytes a client sends for one request.
func (f *replayFixture) tcpRequest() []byte {
	capture := &captureConn{}
	conn := f.client.DialEarlyConn(capture, M.ParseSocksaddr("test.com:443"))
	if _, err := conn.Write([]byte("hello")); err != nil {
		f.t.Fatal(err)
	}
	return capture.joined()
}

func (f *replayFixture) serveTCP(request []byte) error {
	return f.service.NewConnection(context.Background(), &replayConn{r: bytes.NewReader(request)}, M.Metadata{})
}

// udpPackets records n packets of one client session.
func (f *replayFixture) udpPackets(n int) [][]byte {
	capture := &captureConn{}
	pc := f.client.DialPacketConn(capture)
	target := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}
	for i := 0; i < n; i++ {
		if _, err := pc.WriteTo([]byte("ping"), target); err != nil {
			f.t.Fatal(err)
		}
	}
	return capture.writes
}

func (f *replayFixture) serveUDP(packet []byte) error {
	buffer := buf.As(append([]byte(nil), packet...))
	return f.service.NewPacket(context.Background(), discardPacketConn{}, buffer, M.Metadata{})
}

func TestUnauthenticatedTCPSaltNotStored(t *testing.T) {
	f := newReplayFixture(t)
	request := f.tcpRequest()

	// Same salt and identity header, but the AEAD of the fixed header fails.
	forged := append([]byte(nil), request...)
	forged[16+16+1] ^= 0xff
	if err := f.serveTCP(forged); err == nil {
		t.Fatal("request with a broken header AEAD was accepted")
	}
	if err := f.serveTCP(request); err != nil {
		t.Fatalf("genuine request rejected after a forged one used its salt: %v", err)
	}
	if err := f.serveTCP(request); !errors.Is(err, ErrSaltNotUnique) {
		t.Fatalf("replayed request: err = %v, want ErrSaltNotUnique", err)
	}
	if got := f.handler.connections.Load(); got != 1 {
		t.Fatalf("handler saw %d connections, want 1", got)
	}
}

func TestConcurrentSameSaltAcceptedOnce(t *testing.T) {
	f := newReplayFixture(t)
	request := f.tcpRequest()

	const parallel = 8
	var (
		start    sync.WaitGroup
		done     sync.WaitGroup
		accepted atomic.Int64
		replayed atomic.Int64
	)
	start.Add(1)
	for i := 0; i < parallel; i++ {
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait()
			switch err := f.serveTCP(request); {
			case err == nil:
				accepted.Add(1)
			case errors.Is(err, ErrSaltNotUnique):
				replayed.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	start.Done()
	done.Wait()
	if accepted.Load() != 1 || replayed.Load() != parallel-1 {
		t.Fatalf("accepted %d and rejected %d as replays, want 1 and %d", accepted.Load(), replayed.Load(), parallel-1)
	}
}

func TestBadTimestampDoesNotConsumeUDPWindow(t *testing.T) {
	f := newReplayFixture(t)
	packets := f.udpPackets(2)

	// Packet 0 opens the session.
	if err := f.serveUDP(packets[0]); err != nil {
		t.Fatal(err)
	}
	// Packet 1 arrives while the server clock is two minutes ahead, so its
	// timestamp is out of range and it is rejected.
	f.skew.Store(120)
	if err := f.serveUDP(packets[1]); !errors.Is(err, ErrBadTimestamp) {
		t.Fatalf("stale packet: err = %v, want ErrBadTimestamp", err)
	}
	// With the clock back in range the same packet ID must still be usable.
	f.skew.Store(0)
	if err := f.serveUDP(packets[1]); err != nil {
		t.Fatalf("packet rejected after a bad-timestamp copy used its ID: %v", err)
	}
	if err := f.serveUDP(packets[1]); !errors.Is(err, ErrPacketIdNotUnique) {
		t.Fatalf("replayed packet: err = %v, want ErrPacketIdNotUnique", err)
	}
	if got := f.handler.waitPackets(2); got != 2 {
		t.Fatalf("handler received %d packets, want 2", got)
	}
}

func TestRejectedPacketDoesNotExtendUDPSession(t *testing.T) {
	f := newReplayFixture(t)
	packets := f.udpPackets(3)
	if err := f.serveUDP(packets[0]); err != nil {
		t.Fatal(err)
	}
	f.service.udpMu.Lock()
	var record *multiSession
	for _, session := range f.service.sessions {
		record = session
	}
	before := record.lastValid
	f.service.udpMu.Unlock()
	f.skew.Store(120)
	if err := f.serveUDP(packets[1]); err == nil {
		t.Fatal("stale packet accepted")
	}
	f.service.udpMu.Lock()
	after := record.lastValid
	f.service.udpMu.Unlock()
	if after != before {
		t.Fatalf("rejected packet moved expiry: %v -> %v", before, after)
	}
	f.skew.Store(0)
	if err := f.serveUDP(packets[2]); err != nil {
		t.Fatal(err)
	}
	f.service.udpMu.Lock()
	after = record.lastValid
	f.service.udpMu.Unlock()
	if !after.After(before) {
		t.Fatal("valid packet did not extend lifetime")
	}

}

// countingHandler counts connections and UDP packets handed to it.
type countingHandler struct {
	connections atomic.Int64
	packets     chan struct{}
}

func newCountingHandler() *countingHandler {
	return &countingHandler{packets: make(chan struct{}, 64)}
}

func (h *countingHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	h.connections.Add(1)
	return nil
}

func (h *countingHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	for {
		buffer := buf.NewPacket()
		_, err := conn.ReadPacket(buffer)
		buffer.Release()
		if err != nil {
			return err
		}
		h.packets <- struct{}{}
	}
}

func (h *countingHandler) NewError(ctx context.Context, err error) {}

// waitPackets waits briefly for want packets and returns how many arrived.
func (h *countingHandler) waitPackets(want int) int {
	got := 0
	timeout := time.After(2 * time.Second)
	for got < want {
		select {
		case <-h.packets:
			got++
		case <-timeout:
			return got
		}
	}
	// Give an unexpected extra packet a moment to show up.
	select {
	case <-h.packets:
		got++
	case <-time.After(50 * time.Millisecond):
	}
	return got
}

// captureConn records every Write as one message.
type captureConn struct {
	mu     sync.Mutex
	writes [][]byte
}

func (c *captureConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (c *captureConn) joined() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Join(c.writes, nil)
}

func (c *captureConn) Read(p []byte) (int, error)         { return 0, net.ErrClosed }
func (c *captureConn) Close() error                       { return nil }
func (c *captureConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (c *captureConn) RemoteAddr() net.Addr               { return &net.UDPAddr{} }
func (c *captureConn) SetDeadline(t time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(t time.Time) error { return nil }

// replayConn serves recorded client bytes to the server.
type replayConn struct {
	captureConn
	r *bytes.Reader
}

func (c *replayConn) Read(p []byte) (int, error) { return c.r.Read(p) }

type discardPacketConn struct{}

func (discardPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	return M.Socksaddr{}, net.ErrClosed
}

func (discardPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	buffer.Release()
	return nil
}
func (discardPacketConn) Close() error                       { return nil }
func (discardPacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (discardPacketConn) SetDeadline(t time.Time) error      { return nil }
func (discardPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (discardPacketConn) SetWriteDeadline(t time.Time) error { return nil }

func testKey(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}
