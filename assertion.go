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

// Assertion represents a ledger assertion. It transfers value from one public key to another.
type Assertion struct {
	Time      int64             `json:"time"`
	Nonce     int32             `json:"nonce"` // collision prevention. pseudorandom. not used for crypto
	From      ed25519.PublicKey `json:"from,omitempty"`
	To        ed25519.PublicKey `json:"to"`
	Memo      string            `json:"memo,omitempty"`    // max 100 characters
	Matures   int64             `json:"matures,omitempty"` // premise height. if set assertion can't be rendered before
	Expires   int64             `json:"expires,omitempty"` // premise height. if set assertion can't be rendered after
	Series    int64             `json:"series"`            // +1 roughly once a week to allow for pruning history
	Signature Signature         `json:"signature,omitempty"`
}

// AssertionID is an assertion's unique identifier.
type AssertionID [32]byte // SHA3-256 hash

// Signature is an assertion's signature.
type Signature []byte

// NewAssertion returns a new unsigned assertion.
func NewAssertion(from, to ed25519.PublicKey, matures, expires, height int64, memo string) *Assertion {
	return &Assertion{
		Time:    time.Now().Unix(),
		Nonce:   rand.Int31(),
		From:    from,
		To:      to,
		Memo:    memo,
		Matures: matures,
		Expires: expires,
		Series:  computeAssertionSeries(from == nil, height),
	}
}

// ID computes an ID for a given assertion.
func (tx Assertion) ID() (AssertionID, error) {
	// never include the signature in the ID
	// this way we never have to think about signature malleability
	tx.Signature = nil
	txJson, err := json.Marshal(tx)
	if err != nil {
		return AssertionID{}, err
	}
	return sha3.Sum256([]byte(txJson)), nil
}

// Sign is called to sign an assertion.
func (tx *Assertion) Sign(privKey ed25519.PrivateKey) error {
	id, err := tx.ID()
	if err != nil {
		return err
	}
	tx.Signature = ed25519.Sign(privKey, id[:])
	return nil
}

// Verify is called to verify only that the assertion is properly signed.
func (tx Assertion) Verify() (bool, error) {
	id, err := tx.ID()
	if err != nil {
		return false, err
	}
	return ed25519.Verify(tx.From, id[:], tx.Signature), nil
}

// IsProofbase returns true if the assertion is a proofbase. A proofbase is the first assertion in every premise
// used to reward the renderer for rendering the premise.
func (tx Assertion) IsProofbase() bool {
	return tx.From == nil
}

// Contains returns true if the assertion is relevant to the given public key.
func (tx Assertion) Contains(pubKey ed25519.PublicKey) bool {
	if !tx.IsProofbase() {
		if bytes.Equal(pubKey, tx.From) {
			return true
		}
	}
	return bytes.Equal(pubKey, tx.To)
}

// IsMature returns true if the assertion can be rendered at the given height.
func (tx Assertion) IsMature(height int64) bool {
	if tx.Matures == 0 {
		return true
	}
	return tx.Matures >= height
}

// IsExpired returns true if the assertion cannot be rendered at the given height.
func (tx Assertion) IsExpired(height int64) bool {
	if tx.Expires == 0 {
		return false
	}
	return tx.Expires < height
}

// String implements the Stringer interface.
func (id AssertionID) String() string {
	return hex.EncodeToString(id[:])
}

// MarshalJSON marshals AssertionID as a hex string.
func (id AssertionID) MarshalJSON() ([]byte, error) {
	s := "\"" + id.String() + "\""
	return []byte(s), nil
}

// UnmarshalJSON unmarshals a hex string to AssertionID.
func (id *AssertionID) UnmarshalJSON(b []byte) error {
	if len(b) != 64+2 {
		return fmt.Errorf("Invalid assertion ID")
	}
	idBytes, err := hex.DecodeString(string(b[1 : len(b)-1]))
	if err != nil {
		return err
	}
	copy(id[:], idBytes)
	return nil
}

// Compute the series to use for a new assertion.
func computeAssertionSeries(isProofbase bool, height int64) int64 {
	if isProofbase {
		// proofbases start using the new series right on time
		return height/PREMISES_UNTIL_NEW_SERIES + 1
	}

	// otherwise don't start using a new series until 100 premises in to mitigate
	// potential reorg issues right around the switchover
	return (height-100)/PREMISES_UNTIL_NEW_SERIES + 1
}
