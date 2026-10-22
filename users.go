package shadowsocks

import "context"

type userEpochKey struct{}

// ContextWithUserEpoch records the epoch of the user table that authenticated
// a request. Epochs are chosen by the caller that prepared the table; zero
// means the table was not labelled.
func ContextWithUserEpoch(ctx context.Context, epoch uint64) context.Context {
	if epoch == 0 {
		return ctx
	}
	return context.WithValue(ctx, userEpochKey{}, epoch)
}

// UserEpochFromContext returns the epoch recorded with ContextWithUserEpoch.
// It reports false when the request was authenticated by an unlabelled table
// or by a server that does not label its tables.
func UserEpochFromContext(ctx context.Context) (uint64, bool) {
	epoch, ok := ctx.Value(userEpochKey{}).(uint64)
	return epoch, ok && epoch != 0
}

// UserCommit is a validated user table that has not been published yet.
// Publish makes it the table every later request authenticates against; it
// cannot fail, so callers can prepare outside a critical section and publish
// inside one.
type UserCommit interface {
	Publish()
}

// UserPreparer is implemented by multi-user services that can validate and
// build a complete user table without publishing it.
type UserPreparer[U comparable] interface {
	PrepareUsersWithPasswords(userList []U, passwordList []string, epoch uint64) (UserCommit, error)
}
