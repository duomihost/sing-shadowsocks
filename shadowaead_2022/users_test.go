package shadowaead_2022

import (
	"context"
	"encoding/binary"
	"net"
	"testing"

	"github.com/sagernet/sing-shadowsocks"
	M "github.com/sagernet/sing/common/metadata"
)

func TestPrepareUsersPublishesOnlyOnCommit(t *testing.T) {
	f := newReplayFixture(t)
	other := testKey(16)

	// A duplicate key is rejected and leaves the published table alone.
	if _, err := f.service.PrepareUsers([]string{"a", "b"}, [][]byte{other, other}, 5); err == nil {
		t.Fatal("duplicate key accepted")
	}
	if _, err := f.service.PrepareUsers([]string{"a", "a"}, [][]byte{other, testKey(16)}, 5); err == nil {
		t.Fatal("duplicate user accepted")
	}
	if err := f.serveTCP(f.tcpRequest()); err != nil {
		t.Fatalf("published user stopped working after a failed preparation: %v", err)
	}

	// A prepared table is not live until it is published.
	prepared, err := f.service.PrepareUsers([]string{"other"}, [][]byte{other}, 7)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.serveTCP(f.tcpRequest()); err != nil {
		t.Fatalf("unpublished table already replaced the live one: %v", err)
	}
	prepared.Publish()
	if err := f.serveTCP(f.tcpRequest()); err == nil {
		t.Fatal("removed user still authenticates after publish")
	}
}

func TestAuthenticatedRequestCarriesUserEpoch(t *testing.T) {
	f := newReplayFixture(t)
	epochs := &epochHandler{countingHandler: newCountingHandler()}
	f.service.handler = epochs
	key := f.client.pskList[len(f.client.pskList)-1]

	prepared, err := f.service.PrepareUsers([]string{"user"}, [][]byte{key}, 42)
	if err != nil {
		t.Fatal(err)
	}
	prepared.Publish()
	if err := f.serveTCP(f.tcpRequest()); err != nil {
		t.Fatal(err)
	}
	if epochs.epoch != 42 || !epochs.labelled {
		t.Fatalf("epoch = %d (labelled %v), want 42", epochs.epoch, epochs.labelled)
	}

	if err := f.service.UpdateUsers([]string{"user"}, [][]byte{key}); err != nil {
		t.Fatal(err)
	}
	if err := f.serveTCP(f.tcpRequest()); err != nil {
		t.Fatal(err)
	}
	if epochs.labelled {
		t.Fatalf("unlabelled table reported epoch %d", epochs.epoch)
	}
}

// Equal client session IDs from different keys must use independent replay
// windows and NAT owners. Reassigning the same credential cannot resurrect
// its old session across a revocation generation.
func TestUDPSessionRejectsPacketsOfAnotherUser(t *testing.T) {
	f := newReplayFixture(t)
	defer f.service.Close()
	firstKey := f.client.pskList[len(f.client.pskList)-1]
	secondKey := testKey(16)
	if err := f.service.UpdateUsers([]string{"user", "other"}, [][]byte{firstKey, secondKey}); err != nil {
		t.Fatal(err)
	}
	secondMethod, err := New(replayTestMethod, [][]byte{f.client.pskList[0], secondKey}, nil)
	if err != nil {
		t.Fatal(err)
	}
	a, b := &captureConn{}, &captureConn{}
	first := f.client.DialPacketConn(a).(*clientPacketConn)
	second := secondMethod.DialPacketConn(b).(*clientPacketConn)
	second.session.sessionId = first.session.sessionId
	sessionID := make([]byte, 8)
	binary.BigEndian.PutUint64(sessionID, second.session.sessionId)
	second.session.cipher, err = second.Method.constructor(SessionKey(secondKey, sessionID, 16))
	if err != nil {
		t.Fatal(err)
	}
	target := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}
	if _, err = first.WriteTo([]byte("one"), target); err != nil {
		t.Fatal(err)
	}
	if _, err = second.WriteTo([]byte("two"), target); err != nil {
		t.Fatal(err)
	}
	if err = f.serveUDP(a.writes[0]); err != nil {
		t.Fatal(err)
	}
	if err = f.serveUDP(b.writes[0]); err != nil {
		t.Fatal(err)
	}
	if len(f.service.sessions) != 2 {
		t.Fatal("different users shared a session")
	}
	if f.handler.waitPackets(2) != 2 {
		t.Fatal("two owners were not delivered independently")
	}
	if err = f.service.UpdateUsers(nil, nil); err != nil {
		t.Fatal(err)
	}
	if err = f.service.UpdateUsers([]string{"user"}, [][]byte{firstKey}); err != nil {
		t.Fatal(err)
	}
	if err = f.serveUDP(a.writes[0]); err == nil {
		t.Fatal("old credential generation resurrected its UDP session")
	}
}

type epochHandler struct {
	*countingHandler
	epoch    uint64
	labelled bool
}

func (h *epochHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	h.epoch, h.labelled = shadowsocks.UserEpochFromContext(ctx)
	return nil
}
