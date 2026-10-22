package shadowaead_2022

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
	"math"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/rw"

	"lukechampine.com/blake3"
)

var _ shadowsocks.MultiService[int] = (*MultiService[int])(nil)

type MultiService[U comparable] struct {
	*Service

	// users holds a *multiUserTable[U]. UpdateUsers publishes a complete new
	// table at once, and every connection or packet reads a single snapshot, so
	// a concurrent update can never pair a user from one table with a key from
	// another.
	users          atomic.Value
	udpMu          sync.Mutex
	sessions       map[multiSessionKey[U]]*multiSession
	policy         UDPPolicy
	nextGeneration atomic.Uint64
	drops          atomic.Uint64
	lastSweep      time.Time
	queueBudget    *queueBudget
}

type multiUserTable[U comparable] struct {
	// epoch labels the table for callers that track which table
	// authenticated a request (see shadowsocks.UserEpochFromContext); zero
	// means unlabelled.
	credentials map[U]*multiCredential
	epoch       uint64
	uPSK        map[U][]byte
	uPSKHash    map[[aes.BlockSize]byte]U
	uCipher     map[U]cipher.Block
}

func (s *MultiService[U]) loadUsers() *multiUserTable[U] {
	return s.users.Load().(*multiUserTable[U])
}

func NewMultiServiceWithPassword[U comparable](method string, password string, udpTimeout int64, handler shadowsocks.Handler, timeFunc func() time.Time) (*MultiService[U], error) {
	if password == "" {
		return nil, ErrMissingPSK
	}
	iPSK, err := base64.StdEncoding.DecodeString(password)
	if err != nil {
		return nil, E.Cause(err, "decode psk")
	}
	return NewMultiService[U](method, iPSK, udpTimeout, handler, timeFunc)
}

func NewMultiService[U comparable](method string, iPSK []byte, udpTimeout int64, handler shadowsocks.Handler, timeFunc func() time.Time) (*MultiService[U], error) {
	switch method {
	case "2022-blake3-aes-128-gcm":
	case "2022-blake3-aes-256-gcm":
	default:
		return nil, os.ErrInvalid
	}

	ss, err := NewService(method, iPSK, udpTimeout, handler, timeFunc)
	if err != nil {
		return nil, err
	}

	s := &MultiService[U]{
		Service:  ss.(*Service),
		sessions: make(map[multiSessionKey[U]]*multiSession),
	}
	s.users.Store(&multiUserTable[U]{
		uPSK:        make(map[U][]byte),
		uPSKHash:    make(map[[aes.BlockSize]byte]U),
		uCipher:     make(map[U]cipher.Block),
		credentials: make(map[U]*multiCredential),
	})
	return s, nil
}

var _ shadowsocks.UserPreparer[int] = (*MultiService[int])(nil)

// preparedUsers is a complete, validated user table waiting to be published.
type preparedUsers[U comparable] struct {
	service *MultiService[U]
	table   *multiUserTable[U]
}

// Publish makes the table the one every later request authenticates against.
func (p *preparedUsers[U]) Publish() {
	old := p.service.loadUsers()
	p.service.users.Store(p.table)
	for user, credential := range old.credentials {
		if p.table.credentials[user] != credential {
			credential.cancel()
		}
	}
}

// PrepareUsers validates userList and keyList and builds the complete user
// table, including every key schedule, without publishing it. It rejects a
// list with a duplicate user or a duplicate key: two users with the same key
// would share an identity hash, and one of them would silently be served as
// the other. A failed preparation leaves the published table untouched.
func (s *MultiService[U]) PrepareUsers(userList []U, keyList [][]byte, epoch uint64) (shadowsocks.UserCommit, error) {
	if len(userList) != len(keyList) {
		return nil, E.New("users and keys length mismatch")
	}
	table := &multiUserTable[U]{
		epoch:       epoch,
		uPSK:        make(map[U][]byte, len(userList)),
		uPSKHash:    make(map[[aes.BlockSize]byte]U, len(userList)),
		uCipher:     make(map[U]cipher.Block, len(userList)),
		credentials: make(map[U]*multiCredential, len(userList)),
	}
	old := s.loadUsers()
	for i, user := range userList {
		key := append([]byte(nil), keyList[i]...)
		if len(key) != s.keySaltLength {
			return nil, shadowsocks.ErrBadKey
		}
		if _, loaded := table.uPSK[user]; loaded {
			return nil, E.New("duplicate user at index ", i)
		}

		var hash [aes.BlockSize]byte
		hash512 := blake3.Sum512(key)
		copy(hash[:], hash512[:])
		if _, loaded := table.uPSKHash[hash]; loaded {
			return nil, E.New("duplicate user key at index ", i)
		}

		block, err := s.blockConstructor(key)
		if err != nil {
			return nil, err
		}
		table.uPSKHash[hash] = user
		table.uPSK[user] = key
		table.uCipher[user] = block
		if credential := old.credentials[user]; credential != nil && bytes.Equal(old.uPSK[user], key) {
			table.credentials[user] = credential
		} else {
			ctx, cancel := context.WithCancel(context.Background())
			table.credentials[user] = &multiCredential{ctx: ctx, cancel: cancel, generation: s.nextGeneration.Add(1)}
		}
	}
	return &preparedUsers[U]{service: s, table: table}, nil
}

// PrepareUsersWithPasswords is PrepareUsers with Base64 keys.
func (s *MultiService[U]) PrepareUsersWithPasswords(userList []U, passwordList []string, epoch uint64) (shadowsocks.UserCommit, error) {
	keyList := make([][]byte, 0, len(passwordList))
	for _, password := range passwordList {
		if password == "" {
			return nil, shadowsocks.ErrMissingPassword
		}
		uPSK, err := base64.StdEncoding.DecodeString(password)
		if err != nil {
			return nil, E.Cause(err, "decode psk")
		}
		keyList = append(keyList, uPSK)
	}
	return s.PrepareUsers(userList, keyList, epoch)
}

func (s *MultiService[U]) UpdateUsers(userList []U, keyList [][]byte) error {
	prepared, err := s.PrepareUsers(userList, keyList, 0)
	if err != nil {
		return err
	}
	prepared.Publish()
	return nil
}

func (s *MultiService[U]) UpdateUsersWithPasswords(userList []U, passwordList []string) error {
	prepared, err := s.PrepareUsersWithPasswords(userList, passwordList, 0)
	if err != nil {
		return err
	}
	prepared.Publish()
	return nil
}

func (s *MultiService[U]) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	err := s.NewConnection0(ctx, conn, metadata, conn, nil)
	if err != nil {
		err = &shadowsocks.ServerConnError{Conn: conn, Source: metadata.Source, Cause: err}
	}
	return err
}

func (s *MultiService[U]) NewConnection0(ctx context.Context, conn net.Conn, metadata M.Metadata, handshakeReader io.Reader, handshakeSuccess func()) error {
	requestHeader := make([]byte, s.keySaltLength+aes.BlockSize+shadowaead.Overhead+RequestHeaderFixedChunkLength)
	var (
		n   int
		err error
	)
	n, err = handshakeReader.Read(requestHeader)
	if err != nil {
		return err
	} else if n < len(requestHeader) {
		return shadowaead.ErrBadHeader
	}
	requestSalt := requestHeader[:s.keySaltLength]

	var _eiHeader [aes.BlockSize]byte
	eiHeader := _eiHeader[:]
	copy(eiHeader, requestHeader[s.keySaltLength:s.keySaltLength+aes.BlockSize])

	keyMaterial := make([]byte, s.keySaltLength*2)
	copy(keyMaterial, s.psk)
	copy(keyMaterial[s.keySaltLength:], requestSalt)
	identitySubkey := buf.NewSize(s.keySaltLength)
	identitySubkey.Extend(identitySubkey.FreeLen())
	blake3.DeriveKey(identitySubkey.Bytes(), "shadowsocks 2022 identity subkey", keyMaterial)
	b, err := s.blockConstructor(identitySubkey.Bytes())
	identitySubkey.Release()
	if err != nil {
		return err
	}
	b.Decrypt(eiHeader, eiHeader)

	users := s.loadUsers()
	var user U
	var uPSK []byte
	if u, loaded := users.uPSKHash[_eiHeader]; loaded {
		user = u
		uPSK = users.uPSK[u]
	} else {
		return ErrInvalidRequest
	}

	// Finding the user by the identity header does not authenticate the
	// request: the header AEAD below can still fail. handshakeSuccess and the
	// authenticated signal are only raised once everything has been checked.
	requestKey := SessionKey(uPSK, requestSalt, s.keySaltLength)
	readCipher, err := s.constructor(requestKey)
	if err != nil {
		return err
	}
	reader := shadowaead.NewReader(
		conn,
		readCipher,
		MaxPacketSize,
	)

	err = reader.ReadExternalChunk(requestHeader[s.keySaltLength+aes.BlockSize:])
	if err != nil {
		return err
	}

	headerType, err := rw.ReadByte(reader)
	if err != nil {
		return E.Cause(err, "read header")
	}

	if headerType != HeaderTypeClient {
		return E.Extend(ErrBadHeaderType, "expected ", HeaderTypeClient, ", got ", headerType)
	}

	var epoch uint64
	err = binary.Read(reader, binary.BigEndian, &epoch)
	if err != nil {
		return E.Cause(err, "read timestamp")
	}
	diff := int(math.Abs(float64(s.time().Unix() - int64(epoch))))
	if diff > 30 {
		return E.Extend(ErrBadTimestamp, "received ", epoch, ", diff ", diff, "s")
	}
	var length uint16
	err = binary.Read(reader, binary.BigEndian, &length)
	if err != nil {
		return E.Cause(err, "read length")
	}

	err = reader.ReadWithLength(length)
	if err != nil {
		return err
	}

	destination, err := M.SocksaddrSerializer.ReadAddrPort(reader)
	if err != nil {
		return E.Cause(err, "read destination")
	}

	var paddingLen uint16
	err = binary.Read(reader, binary.BigEndian, &paddingLen)
	if err != nil {
		return E.Cause(err, "read padding length")
	}

	if reader.Cached() < int(paddingLen) {
		return ErrBadPadding
	} else if paddingLen > 0 {
		err = reader.Discard(int(paddingLen))
		if err != nil {
			return E.Cause(err, "discard padding")
		}
	} else if reader.Cached() == 0 {
		return ErrNoPadding
	}

	// The salt is recorded only now that the whole request header has been
	// authenticated, so a forged request cannot burn a salt a real client may
	// still send. Check inserts atomically: of two concurrent requests with the
	// same salt only one gets past this point.
	if !s.replayFilter.Check(requestSalt) {
		return ErrSaltNotUnique
	}
	credential := users.credentials[user]
	if credential.ctx.Err() != nil {
		return os.ErrPermission
	}
	ctx = shadowsocks.ContextWithCredential(ctx, shadowsocks.Credential{Context: credential.ctx, Generation: credential.generation})
	shadowsocks.NotifyAuthenticated(ctx)
	if handshakeSuccess != nil {
		handshakeSuccess()
	}

	protocolConn := &serverConn{
		Service:     s.Service,
		Conn:        conn,
		uPSK:        uPSK,
		headerType:  headerType,
		requestSalt: requestSalt,
	}

	protocolConn.reader = reader
	metadata.Protocol = "shadowsocks"
	metadata.Destination = destination
	ctx = shadowsocks.ContextWithUserEpoch(ctx, users.epoch)
	return s.handler.NewConnection(auth.ContextWithUser(ctx, user), protocolConn, metadata)
}

func (s *MultiService[U]) WriteIsThreadUnsafe() {
}

func (s *MultiService[U]) NewPacket(ctx context.Context, conn N.PacketConn, buffer *buf.Buffer, metadata M.Metadata) error {
	err := s.newPacket(ctx, conn, buffer, metadata)
	if err != nil {
		err = &shadowsocks.ServerPacketError{Source: metadata.Source, Cause: err}
	}
	return err
}

func (s *MultiService[U]) newPacket(ctx context.Context, conn N.PacketConn, buffer *buf.Buffer, metadata M.Metadata) error {
	// Every path owns and releases the input buffer, or transfers it to the queue.
	owned := true
	defer func() {
		if owned {
			buffer.Release()
		}
	}()
	if buffer.Len() < 2*aes.BlockSize+shadowaead.Overhead+11 {
		return ErrPacketTooShort
	}
	packetHeader := buffer.To(aes.BlockSize)
	s.udpBlockCipher.Decrypt(packetHeader, packetHeader)
	var ei [aes.BlockSize]byte
	s.udpBlockCipher.Decrypt(ei[:], buffer.Range(aes.BlockSize, 2*aes.BlockSize))
	xorWords(ei[:], ei[:], packetHeader)
	users := s.loadUsers()
	user, ok := users.uPSKHash[ei]
	if !ok {
		return ErrInvalidRequest
	}
	credential := users.credentials[user]
	if credential.ctx.Err() != nil {
		return os.ErrPermission
	}
	sessionID := binary.BigEndian.Uint64(packetHeader[:8])
	packetID := binary.BigEndian.Uint64(packetHeader[8:])
	key := multiSessionKey[U]{ei, sessionID}
	budgetUser := shadowsocks.PacketBudgetUser(ctx, user)
	// This lock protects the replay check-and-insert and the NAT/session budget.
	// No I/O or token waiting is performed under it.
	s.udpMu.Lock()
	defer s.udpMu.Unlock()
	now := s.time()
	session := s.sessions[key]
	if session != nil && now.Sub(session.lastValid) >= s.retention() {
		if session.nat != nil {
			session.nat.Close()
		}
		delete(s.sessions, key)
		session = nil
	}
	if session != nil && (session.generation != credential.generation || session.user != any(user)) {
		return ErrInvalidRequest
	}
	if session == nil {
		session = &multiSession{protocol: s.newUDPSession(users.uPSK[user]), generation: credential.generation, user: user, budgetUser: budgetUser}
		session.protocol.remoteSessionId = sessionID
		remoteKey := SessionKey(users.uPSK[user], packetHeader[:8], s.keySaltLength)
		var err error
		session.protocol.remoteCipher, err = s.constructor(remoteKey)
		if err != nil {
			return err
		}
	}
	if !session.protocol.window.Check(packetID) {
		return ErrPacketIdNotUnique
	}
	buffer.Advance(2 * aes.BlockSize)
	if _, err := session.protocol.remoteCipher.Open(buffer.Index(0), packetHeader[4:16], buffer.Bytes(), nil); err != nil {
		return E.Cause(err, "decrypt packet")
	}
	buffer.Truncate(buffer.Len() - shadowaead.Overhead)
	headerType, err := buffer.ReadByte()
	if err != nil {
		return err
	}
	if headerType != HeaderTypeClient {
		return ErrBadHeaderType
	}
	var epoch uint64
	if err = binary.Read(buffer, binary.BigEndian, &epoch); err != nil {
		return err
	}
	if math.Abs(float64(now.Unix()-int64(epoch))) > 30 {
		return ErrBadTimestamp
	}
	var padding uint16
	if err = binary.Read(buffer, binary.BigEndian, &padding); err != nil {
		return err
	}
	if int(padding) > buffer.Len() {
		return ErrBadPadding
	}
	buffer.Advance(int(padding))
	destination, err := M.SocksaddrSerializer.ReadAddrPort(buffer)
	if err != nil {
		return err
	}
	if !destination.IsValid() {
		return ErrInvalidRequest
	}
	metadata.Protocol = "shadowsocks"
	metadata.Destination = destination
	ctx = auth.ContextWithUser(ctx, user)
	ctx = shadowsocks.ContextWithUserEpoch(ctx, users.epoch)
	ctx = shadowsocks.ContextWithCredential(ctx, shadowsocks.Credential{Context: credential.ctx, Generation: credential.generation})
	s.sweep(now)
	if s.sessions[key] == nil && !s.canCreate(budgetUser) {
		shadowsocks.NotifyPacketDrop(ctx, user, buffer.Len(), true)
		s.drops.Add(1)
		return nil
	}
	return shadowsocks.AdmitPacket(ctx, user, buffer.Len(), func(allow bool) error {
		if credential.ctx.Err() != nil {
			return os.ErrPermission
		}
		session.protocol.window.Add(packetID)
		session.lastValid = now
		s.sessions[key] = session
		if !allow {
			s.drops.Add(1)
			return nil
		}
		if session.nat == nil || session.nat.isClosed() {
			nat := newBoundedPacketConn(ctx, metadata.Source, s.policy.QueuePackets, s.policy.QueueBytes)
			nat.budget = s.queueBudget
			nat.owner = budgetUser
			session.nat = nat
			writer := &serverPacketWriter{s.Service, conn, nat, session.protocol, users.uCipher[user]}
			nat.writer = writer
			stop := context.AfterFunc(credential.ctx, func() { _ = nat.Close() })
			go func() {
				defer stop()
				defer nat.Close()
				err := s.handler.NewPacketConnection(shadowsocks.ContextWithPacketMetered(nat.ctx), nat, metadata)
				if err != nil {
					s.handler.NewError(ctx, err)
				}
			}()
		}
		session.nat.setPeer(metadata.Source)
		if !session.nat.enqueue(buffer, destination) {
			shadowsocks.NotifyPacketDrop(ctx, user, buffer.Len(), false)
			s.drops.Add(1)
			return nil
		}
		owned = false
		return nil
	})
}

func (s *MultiService[U]) newUDPSession(uPSK []byte) *serverUDPSession {
	session := &serverUDPSession{}
	if s.udpCipher != nil {
		session.rng = Blake3KeyedHash(rand.Reader)
		common.Must(binary.Read(session.rng, binary.BigEndian, &session.sessionId))
	} else {
		common.Must(binary.Read(rand.Reader, binary.BigEndian, &session.sessionId))
	}
	session.packetId--
	sessionId := make([]byte, 8)
	binary.BigEndian.PutUint64(sessionId, session.sessionId)
	key := SessionKey(uPSK, sessionId, s.keySaltLength)
	var err error
	session.cipher, err = s.constructor(key)
	common.Must(err)
	return session
}
