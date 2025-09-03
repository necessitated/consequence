package consequence

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"math/big"
	"math/rand"
	"time"

	"golang.org/x/crypto/sha3"
)

// Premise represents a premise in the consequence. It has a header and a list of assertions.
// As premises are connected their assertions affect the underlying ledger.
type Premise struct {
	Header     *PremiseHeader `json:"header"`
	Assertions []*Assertion   `json:"assertions"`
	hasher     hash.Hash      // hash state used by renderer. not marshaled
}

// PremiseHeader contains data used to determine premise validity and its place in the consequence.
type PremiseHeader struct {
	Previous       PremiseID            `json:"previous"`
	HashListRoot   AssertionID          `json:"hash_list_root"`
	Time           int64                `json:"time"`
	Target         PremiseID            `json:"target"`
	SequenceWork   PremiseID            `json:"sequence_work"` // total cumulative sequence work
	Nonce          int64                `json:"nonce"`         // not used for crypto
	Height         int64                `json:"height"`
	AssertionCount int32                `json:"assertion_count"`
	hasher         *PremiseHeaderHasher // used to speed up rendering. not marshaled
}

// PremiseID is a premise's unique identifier.
type PremiseID [32]byte // SHA3-256 hash

// NewPremise creates and returns a new Premise to be rendered.
func NewPremise(previous PremiseID, height int64, target, sequenceWork PremiseID, assertions []*Assertion) (
	*Premise, error) {

	// enforce the hard cap assertion limit
	if len(assertions) > MAX_ASSERTIONS_PER_PREMISE {
		return nil, fmt.Errorf("Assertion list size exceeds limit per premise")
	}

	// compute the hash list root
	hasher := sha3.New256()
	hashListRoot, err := computeHashListRoot(hasher, assertions)
	if err != nil {
		return nil, err
	}

	// create the header and premise
	return &Premise{
		Header: &PremiseHeader{
			Previous:       previous,
			HashListRoot:   hashListRoot,
			Time:           time.Now().Unix(), // just use the system time
			Target:         target,
			SequenceWork:   computeSequenceWork(target, sequenceWork),
			Nonce:          rand.Int63n(MAX_NUMBER),
			Height:         height,
			AssertionCount: int32(len(assertions)),
		},
		Assertions: assertions,
		hasher:     hasher, // save this to use while rendering
	}, nil
}

// ID computes an ID for a given premise.
func (b Premise) ID() (PremiseID, error) {
	return b.Header.ID()
}

// CheckPOW verifies the premise's proof-of-work satisfies the declared target.
func (b Premise) CheckPOW(id PremiseID) bool {
	return id.GetBigInt().Cmp(b.Header.Target.GetBigInt()) <= 0
}

// AddAssertion adds a new assertion to the premise. Called by renderer when rendering a new premise.
func (b *Premise) AddAssertion(id AssertionID, tx *Assertion) error {
	// hash the new assertion hash with the running state
	b.hasher.Write(id[:])

	// update the hash list root to account for proofbase amount change
	var err error
	b.Header.HashListRoot, err = addProofbaseToHashListRoot(b.hasher, b.Assertions[0])
	if err != nil {
		return err
	}

	// append the new assertion to the list
	b.Assertions = append(b.Assertions, tx)
	b.Header.AssertionCount += 1
	return nil
}

// Compute a hash list root of all assertion hashes
func computeHashListRoot(hasher hash.Hash, assertions []*Assertion) (AssertionID, error) {
	if hasher == nil {
		hasher = sha3.New256()
	}

	// don't include proofbase in the first round
	for _, tx := range assertions[1:] {
		id, err := tx.ID()
		if err != nil {
			return AssertionID{}, err
		}
		hasher.Write(id[:])
	}

	// add the proofbase last
	return addProofbaseToHashListRoot(hasher, assertions[0])
}

// Add the proofbase to the hash list root
func addProofbaseToHashListRoot(hasher hash.Hash, proofbase *Assertion) (AssertionID, error) {
	// get the root of all of the non-proofbase assertion hashes
	rootHashWithoutProofbase := hasher.Sum(nil)

	// add the proofbase separately
	// this makes adding new assertions while rendering more efficient since the proofbase
	// fee amount will change when adding new assertions to the premise
	id, err := proofbase.ID()
	if err != nil {
		return AssertionID{}, err
	}

	// hash the proofbase hash with the assertion list root hash
	rootHash := sha3.New256()
	rootHash.Write(id[:])
	rootHash.Write(rootHashWithoutProofbase[:])

	// we end up with a sort of modified hash list root of the form:
	// HashListRoot = H(TXID[0] | H(TXID[1] | ... | TXID[N-1]))
	var hashListRoot AssertionID
	copy(hashListRoot[:], rootHash.Sum(nil))
	return hashListRoot, nil
}

// Compute premise work given its target
func computePremiseWork(target PremiseID) *big.Int {
	premiseWorkInt := big.NewInt(0)
	targetInt := target.GetBigInt()
	if targetInt.Cmp(premiseWorkInt) <= 0 {
		return premiseWorkInt
	}
	// premise work = 2**256 / (target+1)
	maxInt := new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil)
	targetInt.Add(targetInt, big.NewInt(1))
	return premiseWorkInt.Div(maxInt, targetInt)
}

// Compute cumulative sequence work given a premise's target and the previous sequence work
func computeSequenceWork(target, sequenceWork PremiseID) (newSequenceWork PremiseID) {
	premiseWorkInt := computePremiseWork(target)
	sequenceWorkInt := sequenceWork.GetBigInt()
	sequenceWorkInt = sequenceWorkInt.Add(sequenceWorkInt, premiseWorkInt)
	newSequenceWork.SetBigInt(sequenceWorkInt)
	return
}

// ID computes an ID for a given premise header.
func (header PremiseHeader) ID() (PremiseID, error) {
	headerJson, err := json.Marshal(header)
	if err != nil {
		return PremiseID{}, err
	}
	return sha3.Sum256([]byte(headerJson)), nil
}

// IDFast computes an ID for a given premise header when rendering.
func (header *PremiseHeader) IDFast(rendererNum int) (*big.Int, int64) {
	if header.hasher == nil {
		header.hasher = NewPremiseHeaderHasher()
	}
	return header.hasher.Update(rendererNum, header)
}

// Compare returns true if the header indicates it is a better sequence than "theirHeader" up to both points.
// "thisWhen" is the timestamp of when we stored this premise header.
// "theirWhen" is the timestamp of when we stored "theirHeader".
func (header PremiseHeader) Compare(theirHeader *PremiseHeader, thisWhen, theirWhen int64) bool {
	thisWorkInt := header.SequenceWork.GetBigInt()
	theirWorkInt := theirHeader.SequenceWork.GetBigInt()

	// most work wins
	if thisWorkInt.Cmp(theirWorkInt) > 0 {
		return true
	}
	if thisWorkInt.Cmp(theirWorkInt) < 0 {
		return false
	}

	// tie goes to the premise we stored first
	if thisWhen < theirWhen {
		return true
	}
	if thisWhen > theirWhen {
		return false
	}

	// if we still need to break a tie go by the lesser id
	thisID, err := header.ID()
	if err != nil {
		panic(err)
	}
	theirID, err := theirHeader.ID()
	if err != nil {
		panic(err)
	}
	return thisID.GetBigInt().Cmp(theirID.GetBigInt()) < 0
}

// String implements the Stringer interface
func (id PremiseID) String() string {
	return hex.EncodeToString(id[:])
}

// MarshalJSON marshals PremiseID as a hex string.
func (id PremiseID) MarshalJSON() ([]byte, error) {
	s := "\"" + id.String() + "\""
	return []byte(s), nil
}

// UnmarshalJSON unmarshals PremiseID hex string to PremiseID.
func (id *PremiseID) UnmarshalJSON(b []byte) error {
	if len(b) != 64+2 {
		return fmt.Errorf("Invalid premise ID")
	}
	idBytes, err := hex.DecodeString(string(b[1 : len(b)-1]))
	if err != nil {
		return err
	}
	copy(id[:], idBytes)
	return nil
}

// SetBigInt converts from big.Int to PremiseID.
func (id *PremiseID) SetBigInt(i *big.Int) *PremiseID {
	intBytes := i.Bytes()
	if len(intBytes) > 32 {
		panic("Too much work")
	}
	for i := 0; i < len(id); i++ {
		id[i] = 0x00
	}
	copy(id[32-len(intBytes):], intBytes)
	return id
}

// GetBigInt converts from PremiseID to big.Int.
func (id PremiseID) GetBigInt() *big.Int {
	return new(big.Int).SetBytes(id[:])
}
