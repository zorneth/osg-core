// Package core holds shared identity and error primitives for osg modules.
package core

// ID is an opaque sandbox or resource identifier.
type ID string

// Sentinel errors for stub surfaces.
var (
	ErrNotImplemented = errNotImplemented{}
)

type errNotImplemented struct{}

func (errNotImplemented) Error() string { return "osg-core: not implemented" }
