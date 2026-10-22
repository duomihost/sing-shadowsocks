package shadowsocks

import "context"

type credentialKey struct{}
type admissionKey struct{}
type meteredKey struct{}

// Credential carries an immutable credential generation's revocation signal.
// It is independent of mutable user positions and stable billing user state.
type Credential struct {
	Context    context.Context
	Generation uint64
}

func ContextWithCredential(ctx context.Context, c Credential) context.Context {
	return context.WithValue(ctx, credentialKey{}, c)
}
func CredentialValid(ctx context.Context) bool {
	if ctx == nil {
		return true
	}
	c, ok := ctx.Value(credentialKey{}).(Credential)
	return !ok || c.Context != nil && c.Context.Err() == nil
}

// PacketAdmission serializes authenticated packet admission with user commit.
// It meters decrypted payload before queue/rate drops and never waits for tokens.
type PacketAdmission interface {
	AdmitPacket(context.Context, any, int, func(bool) error) error
}

func ContextWithAdmission(ctx context.Context, a PacketAdmission) context.Context {
	return context.WithValue(ctx, admissionKey{}, a)
}
func AdmitPacket(ctx context.Context, user any, size int, deliver func(bool) error) error {
	if a, ok := ctx.Value(admissionKey{}).(PacketAdmission); ok {
		return a.AdmitPacket(ctx, user, size, deliver)
	}
	return deliver(true)
}
func ContextWithPacketMetered(ctx context.Context) context.Context {
	if ctx.Value(admissionKey{}) != nil {
		return context.WithValue(ctx, meteredKey{}, true)
	}
	return ctx
}
func PacketMetered(ctx context.Context) bool { v, _ := ctx.Value(meteredKey{}).(bool); return v }

type managedUsersKey struct{}

func ContextWithManagedUsers(ctx context.Context) context.Context {
	return context.WithValue(ctx, managedUsersKey{}, true)
}
func ManagedUsers(ctx context.Context) bool { v, _ := ctx.Value(managedUsersKey{}).(bool); return v }

// Queue and session budget drops are observable without blocking admission.
func NotifyPacketDrop(ctx context.Context, user any, size int, capacity bool) {
	if observer, ok := ctx.Value(admissionKey{}).(interface{ RecordPacketDrop(any, int, bool) }); ok {
		observer.RecordPacketDrop(user, size, capacity)
	}
}

func PacketBudgetUser(ctx context.Context, user any) any {
	if owner, ok := ctx.Value(admissionKey{}).(interface{ PacketBudgetUser(any) any }); ok {
		return owner.PacketBudgetUser(user)
	}
	return user
}
