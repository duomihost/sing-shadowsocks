package shadowaead_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-shadowsocks/shadowaead"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// TestMultiServiceConcurrentUpdate runs handshakes while the user list is
// replaced over and over, including with a shorter list. Before user tables
// were swapped atomically this crashed with "concurrent map iteration and map
// write" or a nil reader within a second.
func TestMultiServiceConcurrentUpdate(t *testing.T) {
	const (
		method     = "aes-128-gcm"
		fullUsers  = 300
		shortUsers = 50
		target     = 7
	)
	ids := make([]int, fullUsers)
	passwords := make([]string, fullUsers)
	for i := range ids {
		ids[i] = i
		passwords[i] = randomPassword()
	}

	handler := &userHandler{want: target}
	service, err := shadowaead.NewMultiService[int](method, 300, handler)
	if err != nil {
		t.Fatal(err)
	}
	if err = service.UpdateUsersWithPasswords(ids, passwords); err != nil {
		t.Fatal(err)
	}

	client, err := shadowaead.New(method, nil, passwords[target])
	if err != nil {
		t.Fatal(err)
	}
	valid := clientHandshake(t, client.DialEarlyConn)

	duration := time.Second
	if testing.Short() {
		duration = 200 * time.Millisecond
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			n := fullUsers
			if i%2 == 1 {
				n = shortUsers
			}
			if err := service.UpdateUsersWithPasswords(ids[:n], passwords[:n]); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	var accepted int64
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			probe := randomBytes(16 + 2 + 16 + 64)
			packet := randomBytes(1200)
			for {
				select {
				case <-stop:
					return
				default:
				}
				if err := service.NewConnection(context.Background(), &memConn{r: bytes.NewReader(valid)}, M.Metadata{}); err != nil {
					t.Error(E.Cause(err, "valid handshake"))
					return
				}
				atomic.AddInt64(&accepted, 1)
				if service.NewConnection(context.Background(), &memConn{r: bytes.NewReader(probe)}, M.Metadata{}) == nil {
					t.Error("random probe accepted")
					return
				}
				buffer := buf.As(append([]byte(nil), packet...))
				if service.NewPacket(context.Background(), nil, buffer, M.Metadata{}) == nil {
					t.Error("random packet accepted")
					return
				}
			}
		}()
	}
	time.Sleep(duration)
	close(stop)
	wg.Wait()
	if atomic.LoadInt64(&accepted) == 0 {
		t.Fatal("no handshake completed")
	}
	if atomic.LoadInt64(&handler.wrongUser) != 0 {
		t.Fatalf("%d handshakes were attributed to the wrong user", atomic.LoadInt64(&handler.wrongUser))
	}
}

func clientHandshake(t *testing.T, dial func(net.Conn, M.Socksaddr) net.Conn) []byte {
	t.Helper()
	capture := &memConn{r: bytes.NewReader(nil)}
	conn := dial(capture, M.ParseSocksaddr("test.com:443"))
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	return capture.w.Bytes()
}

type userHandler struct {
	want      int
	wrongUser int64
}

func (h *userHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	user, _ := auth.UserFromContext[int](ctx)
	if user != h.want || metadata.Destination.String() != "test.com:443" {
		atomic.AddInt64(&h.wrongUser, 1)
	}
	return nil
}

func (h *userHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	return nil
}

func (h *userHandler) NewError(ctx context.Context, err error) {}

// memConn serves pre-recorded client bytes to the server and records writes.
type memConn struct {
	r *bytes.Reader
	w bytes.Buffer
}

func (c *memConn) Read(p []byte) (int, error)         { return c.r.Read(p) }
func (c *memConn) Write(p []byte) (int, error)        { return c.w.Write(p) }
func (c *memConn) Close() error                       { return nil }
func (c *memConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *memConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *memConn) SetDeadline(t time.Time) error      { return nil }
func (c *memConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *memConn) SetWriteDeadline(t time.Time) error { return nil }

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func randomPassword() string {
	return hex.EncodeToString(randomBytes(16))
}
