package shadowaead_2022_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// TestMultiServiceConcurrentUpdate runs handshakes while the user list is
// replaced over and over, including with a shorter list, and checks that every
// accepted connection is attributed to the user whose key it used. Run it with
// -race: before the user tables were published as one snapshot, the three maps
// were reassigned separately while handshakes read them.
func TestMultiServiceConcurrentUpdate(t *testing.T) {
	const (
		method     = "2022-blake3-aes-128-gcm"
		fullUsers  = 300
		shortUsers = 50
		target     = 7
	)
	iPSK := randomKey(16)
	names := make([]string, fullUsers)
	keys := make([][]byte, fullUsers)
	for i := range names {
		names[i] = fmt.Sprintf("user-%d", i)
		keys[i] = randomKey(16)
	}

	handler := &userHandler{want: names[target]}
	service, err := shadowaead_2022.NewMultiService[string](method, iPSK, 300, handler, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = service.UpdateUsers(names, keys); err != nil {
		t.Fatal(err)
	}
	client, err := shadowaead_2022.New(method, [][]byte{iPSK, keys[target]}, nil)
	if err != nil {
		t.Fatal(err)
	}

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
			if err := service.UpdateUsers(names[:n], keys[:n]); err != nil {
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
			for {
				select {
				case <-stop:
					return
				default:
				}
				// Every handshake needs a fresh salt because of the replay filter.
				capture := &memConn{r: bytes.NewReader(nil)}
				conn := client.DialEarlyConn(capture, M.ParseSocksaddr("test.com:443"))
				if _, err := conn.Write([]byte("hello")); err != nil {
					t.Error(err)
					return
				}
				if err := service.NewConnection(context.Background(), &memConn{r: bytes.NewReader(capture.w.Bytes())}, M.Metadata{}); err != nil {
					t.Error(E.Cause(err, "valid handshake"))
					return
				}
				atomic.AddInt64(&accepted, 1)
				probe := randomKey(16 + 16 + 16 + 11 + 16)
				if service.NewConnection(context.Background(), &memConn{r: bytes.NewReader(probe)}, M.Metadata{}) == nil {
					t.Error("random probe accepted")
					return
				}
				if service.NewPacket(context.Background(), nil, buf.As(randomKey(1200)), M.Metadata{}) == nil {
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

type userHandler struct {
	want      string
	wrongUser int64
}

func (h *userHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	user, _ := auth.UserFromContext[string](ctx)
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

func randomKey(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}
