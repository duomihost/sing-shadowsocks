package shadowaead_2022

import (
	"bytes"
	"context"
	"net"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-shadowsocks"
	M "github.com/sagernet/sing/common/metadata"
)

// HandshakeCallbackBeforeAEAD (final plan T7): handshakeSuccess ran as soon as
// the identity header matched a user, before the header AEAD, the timestamp
// and the replay check, so it could not be used to mark a request as
// authenticated. Neither it nor the authenticated signal may fire for a
// request that is then rejected.
func TestAuthenticatedSignalOnlyAfterFullValidation(t *testing.T) {
	f := newReplayFixture(t)
	request := f.tcpRequest()

	serve := func(request []byte) (callbacks, signals int64, err error) {
		var cb, sig atomic.Int64
		ctx := shadowsocks.ContextWithAuthenticated(context.Background(), func() { sig.Add(1) })
		// The handshake reader and the connection share one stream.
		conn := &replayConn{r: bytes.NewReader(request)}
		err = f.service.NewConnection0(ctx, conn, M.Metadata{}, conn, func() { cb.Add(1) })
		return cb.Load(), sig.Load(), err
	}

	forged := append([]byte(nil), request...)
	forged[16+16+1] ^= 0xff
	if cb, sig, err := serve(forged); err == nil || cb != 0 || sig != 0 {
		t.Fatalf("broken header AEAD: err=%v handshakeSuccess=%d authenticated=%d, want an error and no signal", err, cb, sig)
	}

	f.skew.Store(120)
	if cb, sig, err := serve(request); err == nil || cb != 0 || sig != 0 {
		t.Fatalf("bad timestamp: err=%v handshakeSuccess=%d authenticated=%d, want an error and no signal", err, cb, sig)
	}
	f.skew.Store(0)

	if cb, sig, err := serve(request); err != nil || cb != 1 || sig != 1 {
		t.Fatalf("valid request: err=%v handshakeSuccess=%d authenticated=%d, want nil, 1, 1", err, cb, sig)
	}
	if cb, sig, err := serve(request); err == nil || cb != 0 || sig != 0 {
		t.Fatalf("replayed request: err=%v handshakeSuccess=%d authenticated=%d, want an error and no signal", err, cb, sig)
	}
	if got := f.handler.connections.Load(); got != 1 {
		t.Fatalf("handler saw %d connections, want 1", got)
	}
}

func TestAuthenticatedSignalPrecedesHandler(t *testing.T) {
	f := newReplayFixture(t)
	var signalled atomic.Bool
	order := &orderHandler{countingHandler: newCountingHandler(), signalled: &signalled}
	f.service.handler = order
	ctx := shadowsocks.ContextWithAuthenticated(context.Background(), func() { signalled.Store(true) })
	request := f.tcpRequest()
	if err := f.service.NewConnection(ctx, &replayConn{r: bytes.NewReader(request)}, M.Metadata{}); err != nil {
		t.Fatal(err)
	}
	if !order.sawSignal.Load() {
		t.Fatal("handler ran before the authenticated signal")
	}
}

type orderHandler struct {
	*countingHandler
	signalled *atomic.Bool
	sawSignal atomic.Bool
}

func (h *orderHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	h.sawSignal.Store(h.signalled.Load())
	return nil
}
