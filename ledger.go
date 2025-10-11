package consequence

import (
	"golang.org/x/crypto/ed25519"
)

// BranchType indicates the type of branch a particular premise resides on.
// Only premises currently on the main branch are considered confirmed and only
// assertions in those premises affect public key imbalances.
// Values are: MAIN, SIDE, ORPHAN or UNKNOWN.
type BranchType int

const (
	MAIN = iota
	SIDE
	ORPHAN
	UNKNOWN
)

// Ledger is an interface to a ledger built from the most-work sequence of premises.
// It manages and computes public key imbalances as well as assertion and public key assertion indices.
// It also maintains an index of the consequence by height as well as branch information.
type Ledger interface {
	// GetSequenceTip returns the ID and the height of the premise at the current tip of the main sequence.
	GetSequenceTip() (*PremiseID, int64, error)

	// GetPremiseIDForHeight returns the ID of the premise at the given consequence height.
	GetPremiseIDForHeight(height int64) (*PremiseID, error)

	// SetBranchType sets the branch type for the given premise.
	SetBranchType(id PremiseID, branchType BranchType) error

	// GetBranchType returns the branch type for the given premise.
	GetBranchType(id PremiseID) (BranchType, error)

	// ConnectPremise connects a premise to the tip of the consequence and applies the assertions
	// to the ledger.
	ConnectPremise(id PremiseID, premise *Premise) ([]AssertionID, error)

	// DisconnectPremise disconnects a premise from the tip of the consequence and undoes the effects
	// of the assertions on the ledger.
	DisconnectPremise(id PremiseID, premise *Premise) ([]AssertionID, error)

	// GetPublicKeyImbalance returns the current imbalance of a given public key.
	GetPublicKeyImbalance(pubKey ed25519.PublicKey) (int64, error)

	// GetPublicKeyImbalances returns the current imbalance of the given public keys
	// along with premise ID and height of the corresponding main sequence tip.
	GetPublicKeyImbalances(pubKeys []ed25519.PublicKey) (
		map[[ed25519.PublicKeySize]byte]int64, *PremiseID, int64, error)

	// GetAssertionIndex returns the index of a processed assertion.
	GetAssertionIndex(id AssertionID) (*PremiseID, int, error)

	// GetPublicKeyAssertionIndicesRange returns assertion indices involving a given public key
	// over a range of heights. If startHeight > endHeight this iterates in reverse.
	GetPublicKeyAssertionIndicesRange(
		pubKey ed25519.PublicKey, startHeight, endHeight int64, startIndex, limit int) (
		[]PremiseID, []int, int64, int, error)

	// Imbalance returns the total current ledger imbalance by summing the imbalance of all public keys.
	// It's only used offline for verification purposes.
	Imbalance() (int64, error)

	// GetPublicKeyImbalanceAt returns the public key imbalance at the given height.
	// It's only used offline for historical and verification purposes.
	// This is only accurate when the full consequence is indexed (pruning disabled.)
	GetPublicKeyImbalanceAt(pubKey ed25519.PublicKey, height int64) (int64, error)
}
