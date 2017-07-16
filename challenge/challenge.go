// Package challenge defines an interface for a dynamic challenge password cache.
package challenge

// Store is a dynamic challenge password cache.
type Store interface {
	SCEPChallenge() (string, error)
	HasChallenge(pw string) (bool, error)
}
