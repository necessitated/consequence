package consequence

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"time"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"
)

// Transition represents a ledger transition. It transfers value from one public key to another.
type Transition struct {
	Time      int64             `json:"time"`
	Nonce     int32             `json:"nonce"` // collision prevention. pseudorandom. not used for crypto
	From      ed25519.PublicKey `json:"from,omitempty"`
	To        ed25519.PublicKey `json:"to"`
	Memo      string            `json:"memo,omitempty"`    // max 100 characters
	Matures   int64             `json:"matures,omitempty"` // stage height. if set transition can't be rendered before
	Expires   int64             `json:"expires,omitempty"` // stage height. if set transition can't be rendered after
	Series    int64             `json:"series"`            // +1 roughly once a week to allow for pruning history
	Signature Signature         `json:"signature,omitempty"`
}

// TransitionID is a transition's unique identifier.
type TransitionID [32]byte // SHA3-256 hash

// Signature is a transition's signature.
type Signature []byte

// NewTransition returns a new unsigned transition.
func NewTransition(from, to ed25519.PublicKey, matures, expires, height int64, memo string) *Transition {
	return &Transition{
		Time:    time.Now().Unix(),
		Nonce:   rand.Int31(),
		From:    from,
		To:      to,
		Memo:    memo,
		Matures: matures,
		Expires: expires,
		Series:  computeTransitionSeries(from == nil, height),
	}
}

// ID computes an ID for a given transition.
func (tx Transition) ID() (TransitionID, error) {
	// never include the signature in the ID
	// this way we never have to think about signature malleability
	tx.Signature = nil
	txJson, err := json.Marshal(tx)
	if err != nil {
		return TransitionID{}, err
	}
	return sha3.Sum256([]byte(txJson)), nil
}

// Sign is called to sign a transition.
func (tx *Transition) Sign(privKey ed25519.PrivateKey) error {
	id, err := tx.ID()
	if err != nil {
		return err
	}
	tx.Signature = ed25519.Sign(privKey, id[:])
	return nil
}

// Verify is called to verify only that the transition is properly signed.
func (tx Transition) Verify() (bool, error) {
	id, err := tx.ID()
	if err != nil {
		return false, err
	}
	return ed25519.Verify(tx.From, id[:], tx.Signature), nil
}

// IsStagepass returns true if the transition is a stagepass. A stagepass is the first transition in every stage
// used to pass the renderer for rendering the stage.
func (tx Transition) IsStagepass() bool {
	return tx.From == nil
}

// Contains returns true if the transition is relevant to the given public key.
func (tx Transition) Contains(pubKey ed25519.PublicKey) bool {
	if !tx.IsStagepass() {
		if bytes.Equal(pubKey, tx.From) {
			return true
		}
	}
	return bytes.Equal(pubKey, tx.To)
}

// IsMature returns true if the transition can be rendered at the given height.
func (tx Transition) IsMature(height int64) bool {
	if tx.Matures == 0 {
		return true
	}
	return tx.Matures >= height
}

// IsExpired returns true if the transition cannot be rendered at the given height.
func (tx Transition) IsExpired(height int64) bool {
	if tx.Expires == 0 {
		return false
	}
	return tx.Expires < height
}

// String implements the Stringer interface.
func (id TransitionID) String() string {
	return hex.EncodeToString(id[:])
}

// MarshalJSON marshals TransitionID as a hex string.
func (id TransitionID) MarshalJSON() ([]byte, error) {
	s := "\"" + id.String() + "\""
	return []byte(s), nil
}

// UnmarshalJSON unmarshals a hex string to TransitionID.
func (id *TransitionID) UnmarshalJSON(b []byte) error {
	if len(b) != 64+2 {
		return fmt.Errorf("Invalid transition ID")
	}
	idBytes, err := hex.DecodeString(string(b[1 : len(b)-1]))
	if err != nil {
		return err
	}
	copy(id[:], idBytes)
	return nil
}

// Compute the series to use for a new transition.
func computeTransitionSeries(isStagepass bool, height int64) int64 {
	if isStagepass {
		// stagepasses start using the new series right on time
		return height/STAGES_UNTIL_NEW_SERIES + 1
	}

	// otherwise don't start using a new series until 100 stages in to mitigate
	// potential reorg issues right around the switchover
	return (height-100)/STAGES_UNTIL_NEW_SERIES + 1
}
