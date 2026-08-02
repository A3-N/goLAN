package bridge

import "context"

type fastPolicyBackend interface {
	Apply(context.Context, string) error
	Restore(context.Context) error
}

type bridgeIPFilter interface {
	Enable(string) error
}
