package consequence

import (
	"golang.org/x/crypto/ed25519"
)

// BranchType indicates the type of branch a particular stage resides on.
// Only stages currently on the main branch are considered confirmed and only
// transitions in those stages affect public key imbalances.
// Values are: MAIN, SIDE, ORPHAN or UNKNOWN.
type BranchType int

const (
	MAIN = iota
	SIDE
	ORPHAN
	UNKNOWN
)

// Ledger is an interface to a ledger built from the most-work sequence of stages.
// It manages and computes public key imbalances as well as transition and public key transition indices.
// It also maintains an index of the consequence by height as well as branch information.
type Ledger interface {
	// GetSequenceTip returns the ID and the height of the stage at the current tip of the main sequence.
	GetSequenceTip() (*StageID, int64, error)

	// GetStageIDForHeight returns the ID of the stage at the given consequence height.
	GetStageIDForHeight(height int64) (*StageID, error)

	// SetBranchType sets the branch type for the given stage.
	SetBranchType(id StageID, branchType BranchType) error

	// GetBranchType returns the branch type for the given stage.
	GetBranchType(id StageID) (BranchType, error)

	// ConnectStage connects a stage to the tip of the consequence and applies the transitions
	// to the ledger.
	ConnectStage(id StageID, stage *Stage) ([]TransitionID, error)

	// DisconnectStage disconnects a stage from the tip of the consequence and undoes the effects
	// of the transitions on the ledger.
	DisconnectStage(id StageID, stage *Stage) ([]TransitionID, error)

	// GetPublicKeyImbalance returns the current imbalance of a given public key.
	GetPublicKeyImbalance(pubKey ed25519.PublicKey) (int64, error)

	// GetPublicKeyImbalances returns the current imbalance of the given public keys
	// along with stage ID and height of the corresponding main sequence tip.
	GetPublicKeyImbalances(pubKeys []ed25519.PublicKey) (
		map[[ed25519.PublicKeySize]byte]int64, *StageID, int64, error)

	// GetTransitionIndex returns the index of a processed transition.
	GetTransitionIndex(id TransitionID) (*StageID, int, error)

	// GetPublicKeyTransitionIndicesRange returns transition indices involving a given public key
	// over a range of heights. If startHeight > endHeight this iterates in reverse.
	GetPublicKeyTransitionIndicesRange(
		pubKey ed25519.PublicKey, startHeight, endHeight int64, startIndex, limit int) (
		[]StageID, []int, int64, int, error)

	// Imbalance returns the total current ledger imbalance by summing the imbalance of all public keys.
	// It's only used offline for verification purposes.
	Imbalance() (int64, error)

	// GetPublicKeyImbalanceAt returns the public key imbalance at the given height.
	// It's only used offline for historical and verification purposes.
	// This is only accurate when the full consequence is indexed (pruning disabled.)
	GetPublicKeyImbalanceAt(pubKey ed25519.PublicKey, height int64) (int64, error)
}
