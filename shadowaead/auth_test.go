package shadowaead_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestLegacyAuthenticatedSignal(t *testing.T) {
	const method = "aes-128-gcm"
	service, err := shadowaead.NewMultiService[string](method, 300, nopHandler{})
	if err != nil {
		t.Fatal(err)
	}
	if err = service.UpdateUsersWithPasswords([]string{"user"}, []string{"password"}); err != nil {
		t.Fatal(err)
	}
	client, err := shadowaead.New(method, nil, "password")
	if err != nil {
		t.Fatal(err)
	}
	capture := &bufConn{}
	conn := client.DialEarlyConn(capture, M.ParseSocksaddr("test.com:443"))
	if _, err = conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}

	serve := func(request []byte) (int64, error) {
		var signals atomic.Int64
		ctx := shadowsocks.ContextWithAuthenticated(context.Background(), func() { signals.Add(1) })
		err := service.NewConnection(ctx, &bufConn{r: bytes.NewReader(request)}, M.Metadata{})
		return signals.Load(), err
	}
	probe := make([]byte, 64)
	_, _ = rand.Read(probe)
	if n, err := serve(probe); err == nil || n != 0 {
		t.Fatalf("random probe: err=%v signals=%d, want an error and no signal", err, n)
	}
	if n, err := serve(capture.w.Bytes()); err != nil || n != 1 {
		t.Fatalf("valid request: err=%v signals=%d, want nil and 1", err, n)
	}
}

type nopHandler struct{}

func (nopHandler) NewConnection(context.Context, net.Conn, M.Metadata) error           { return nil }
func (nopHandler) NewPacketConnection(context.Context, N.PacketConn, M.Metadata) error { return nil }
func (nopHandler) NewError(context.Context, error)                                     {}

type bufConn struct {
	r *bytes.Reader
	w bytes.Buffer
}

func (c *bufConn) Read(p []byte) (int, error) {
	if c.r == nil {
		return 0, net.ErrClosed
	}
	return c.r.Read(p)
}
func (c *bufConn) Write(p []byte) (int, error)      { return c.w.Write(p) }
func (c *bufConn) Close() error                     { return nil }
func (c *bufConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *bufConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *bufConn) SetDeadline(time.Time) error      { return nil }
func (c *bufConn) SetReadDeadline(time.Time) error  { return nil }
func (c *bufConn) SetWriteDeadline(time.Time) error { return nil }
