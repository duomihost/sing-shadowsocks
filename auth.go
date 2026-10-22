package shadowsocks

import "context"

// Servers report two facts about a request through its context, for callers
// that must act exactly when a client has proven it holds a valid credential
// (to lift a handshake deadline or release an unauthenticated slot) or that
// must know which published user table authenticated it.

type authenticatedKey struct{}

// ContextWithAuthenticated returns a context on which a server calls f once a
// request has passed every check the server makes before it accepts it. For
// SIP022 that is the identity header, the AEAD of the fixed and variable
// request header, the header type, the timestamp, the address, the padding
// and, last, the salt replay check. f is never called for a request that fails
// any of them, is called at most once per request, and runs on the request's
// goroutine before the request is handed to the server's handler.
//
// Servers that do not support the signal never call f; callers must still
// release whatever f would have released when the request ends.
func ContextWithAuthenticated(ctx context.Context, f func()) context.Context {
	return context.WithValue(ctx, authenticatedKey{}, f)
}

// NotifyAuthenticated calls the function registered on ctx with
// ContextWithAuthenticated, if any. Servers call it once per request.
func NotifyAuthenticated(ctx context.Context) {
	if f, ok := ctx.Value(authenticatedKey{}).(func()); ok && f != nil {
		f()
	}
}
