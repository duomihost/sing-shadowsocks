package shadowaead_2022

import (
	"context"
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

func TestUDPSessionRejectsPacketsOfAnotherUser(t *testing.T) {
	f := newReplayFixture(t)
	packets := f.udpPackets(2)
	if err := f.serveUDP(packets[0]); err != nil {
		t.Fatal(err)
	}
	var session *serverUDPSession
	f.service.udpSessions.Range(func(_ uint64, s *serverUDPSession) { session = s })
	session.owner = "someone else"
	if err := f.serveUDP(packets[1]); err == nil {
		t.Fatal("packet of a different user was queued on the session")
	}
	session.owner = "user"
	if err := f.serveUDP(packets[1]); err != nil {
		t.Fatalf("rejected packet consumed its packet ID: %v", err)
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
