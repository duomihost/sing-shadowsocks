package shadowaead_2022

import (
	"context"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"
)

type multiCredential struct {
	ctx        context.Context
	cancel     context.CancelFunc
	generation uint64
}
type multiSessionKey[U comparable] struct {
	key     [16]byte
	session uint64
}
type multiSession struct {
	protocol   *serverUDPSession
	lastValid  time.Time
	nat        *boundedPacketConn
	generation uint64
	user       any
	budgetUser any
}

// New capacities are opt-in (zero disables them). QueuePackets=0 preserves the
// existing per-session queue depth of 64, but enqueue is now nonblocking.
// Replay capacity is shared with sessions and never evicts retained state.
type UDPPolicy struct {
	MaxQueuedBytes                                int64
	MaxQueuedBytesPerUser                         int64
	MaxSessions, MaxSessionsPerUser, QueuePackets int
	QueueBytes                                    int
	MaxReplayEntries                              int
}

// SetUDPPolicy is a startup-only setting; apply before admitting any packet.
func (s *MultiService[U]) SetUDPPolicy(p UDPPolicy) {
	s.udpMu.Lock()
	s.policy = p
	s.queueBudget = &queueBudget{max: p.MaxQueuedBytes, perUser: p.MaxQueuedBytesPerUser, users: make(map[any]int64)}
	s.udpMu.Unlock()
}
func (s *MultiService[U]) UDPDrops() uint64 { return s.drops.Load() }
func (s *MultiService[U]) retention() time.Duration {
	if s.udpTimeout < 60 {
		return 60 * time.Second
	}
	return time.Duration(s.udpTimeout) * time.Second
}
func (s *MultiService[U]) sweep(now time.Time) {
	if !s.lastSweep.IsZero() && now.Sub(s.lastSweep) < time.Second {
		return
	}
	s.lastSweep = now
	for key, session := range s.sessions {
		if now.Sub(session.lastValid) >= s.retention() {
			if session.nat != nil {
				session.nat.Close()
			}
			delete(s.sessions, key)
		}
	}
}
func (s *MultiService[U]) canCreate(user any) bool {
	if s.policy.MaxSessions > 0 && len(s.sessions) >= s.policy.MaxSessions {
		return false
	}
	if s.policy.MaxReplayEntries > 0 && len(s.sessions) >= s.policy.MaxReplayEntries {
		return false
	}
	if s.policy.MaxSessionsPerUser > 0 {
		n := 0
		for _, record := range s.sessions {
			if record.budgetUser == user {
				n++
			}
		}
		if n >= s.policy.MaxSessionsPerUser {
			return false
		}
	}
	return true
}

type queuedPacket struct {
	buffer      *buf.Buffer
	destination M.Socksaddr
}
type boundedPacketConn struct {
	mu          sync.Mutex
	ctx         context.Context
	cancel      context.CancelFunc
	data        chan queuedPacket
	peer        M.Socksaddr
	writer      N.PacketWriter
	queuedBytes int
	maxBytes    int
	deadline    pipe.Deadline
	closed      bool
	budget      *queueBudget
	owner       any
}

func newBoundedPacketConn(ctx context.Context, peer M.Socksaddr, packets, maxBytes int) *boundedPacketConn {
	if packets <= 0 {
		packets = 64
	}
	ctx, cancel := context.WithCancel(ctx)
	return &boundedPacketConn{ctx: ctx, cancel: cancel, data: make(chan queuedPacket, packets), peer: peer, maxBytes: maxBytes, deadline: pipe.MakeDeadline()}
}
func (c *boundedPacketConn) isClosed() bool           { c.mu.Lock(); defer c.mu.Unlock(); return c.closed }
func (c *boundedPacketConn) setPeer(peer M.Socksaddr) { c.mu.Lock(); c.peer = peer; c.mu.Unlock() }
func (c *boundedPacketConn) enqueue(b *buf.Buffer, dest M.Socksaddr) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.ctx.Err() != nil || c.maxBytes > 0 && c.queuedBytes+b.Len() > c.maxBytes {
		return false
	}
	if c.budget != nil && !c.budget.reserve(c.owner, b.Len()) {
		return false
	}
	select {
	case c.data <- queuedPacket{b, dest}:
		c.queuedBytes += b.Len()
		return true
	default:
		if c.budget != nil {
			c.budget.release(c.owner, b.Len())
		}
		return false
	}
}
func (c *boundedPacketConn) ReadPacket(b *buf.Buffer) (M.Socksaddr, error) {
	select {
	case p := <-c.data:
		c.mu.Lock()
		c.queuedBytes -= p.buffer.Len()
		if c.budget != nil {
			c.budget.release(c.owner, p.buffer.Len())
		}
		closed := c.closed
		c.mu.Unlock()
		defer p.buffer.Release()
		if closed {
			return M.Socksaddr{}, net.ErrClosed
		}
		_, err := b.Write(p.buffer.Bytes())
		return p.destination, err
	case <-c.ctx.Done():
		return M.Socksaddr{}, io.ErrClosedPipe
	case <-c.deadline.Wait():
		return M.Socksaddr{}, os.ErrDeadlineExceeded
	}
}
func (c *boundedPacketConn) WritePacket(b *buf.Buffer, d M.Socksaddr) error {
	if c.isClosed() {
		b.Release()
		return net.ErrClosed
	}
	return c.writer.WritePacket(b, d)
}
func (c *boundedPacketConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.cancel()
	for {
		select {
		case p := <-c.data:
			c.queuedBytes -= p.buffer.Len()
			if c.budget != nil {
				c.budget.release(c.owner, p.buffer.Len())
			}
			p.buffer.Release()
		default:
			return nil
		}
	}
}
func (c *boundedPacketConn) LocalAddr() net.Addr               { c.mu.Lock(); defer c.mu.Unlock(); return c.peer }
func (c *boundedPacketConn) SetDeadline(t time.Time) error     { return c.SetReadDeadline(t) }
func (c *boundedPacketConn) SetReadDeadline(t time.Time) error { c.deadline.Set(t); return nil }
func (c *boundedPacketConn) SetWriteDeadline(time.Time) error  { return nil }

type udpPolicyKey struct{}

func ContextWithUDPPolicy(ctx context.Context, p UDPPolicy) context.Context {
	return context.WithValue(ctx, udpPolicyKey{}, p)
}
func UDPPolicyFromContext(ctx context.Context) UDPPolicy {
	p, _ := ctx.Value(udpPolicyKey{}).(UDPPolicy)
	return p
}

func (c *boundedPacketConn) FrontHeadroom() int {
	if v, ok := c.writer.(interface{ FrontHeadroom() int }); ok {
		return v.FrontHeadroom()
	}
	return 0
}
func (c *boundedPacketConn) RearHeadroom() int {
	if v, ok := c.writer.(interface{ RearHeadroom() int }); ok {
		return v.RearHeadroom()
	}
	return 0
}

func (s *MultiService[U]) Close() error {
	// Listener shutdown must leave authenticated TCP streams available for drain.
	s.udpMu.Lock()
	defer s.udpMu.Unlock()
	for _, session := range s.sessions {
		if session.nat != nil {
			_ = session.nat.Close()
		}
	}
	return nil
}

type queueBudget struct {
	mu                  sync.Mutex
	max, perUser, total int64
	users               map[any]int64
}

func (b *queueBudget) reserve(user any, size int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := int64(size)
	if b.max > 0 && b.total+n > b.max || b.perUser > 0 && b.users[user]+n > b.perUser {
		return false
	}
	b.total += n
	b.users[user] += n
	return true
}
func (b *queueBudget) release(user any, size int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.total -= int64(size)
	b.users[user] -= int64(size)
	if b.users[user] == 0 {
		delete(b.users, user)
	}
}
