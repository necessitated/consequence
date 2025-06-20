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

// Stage represents a stage in the consequence. It has a header and a list of transitions.
// As stages are connected their transitions affect the underlying ledger.
type Stage struct {
	Header       *StageHeader   `json:"header"`
	Transitions  []*Transition  `json:"transitions"`
	hasher       hash.Hash      // hash state used by renderer. not marshaled
}

// StageHeader contains data used to determine stage validity and its place in the consequence.
type StageHeader struct {
	Previous         StageID            `json:"previous"`
	HashListRoot     TransitionID       `json:"hash_list_root"`
	Time             int64              `json:"time"`
	Target           StageID            `json:"target"`
	SequenceWork     StageID            `json:"sequence_work"` // total cumulative sequence work
	Nonce            int64              `json:"nonce"`      // not used for crypto
	Height           int64              `json:"height"`
	TransitionCount  int32              `json:"transition_count"`
	hasher           *StageHeaderHasher // used to speed up rendering. not marshaled
}

// StageID is a stage's unique identifier.
type StageID [32]byte // SHA3-256 hash

// NewStage creates and returns a new Stage to be rendered.
func NewStage(previous StageID, height int64, target, sequenceWork StageID, transitions []*Transition) (
	*Stage, error) {

	// enforce the hard cap transition limit
	if len(transitions) > MAX_TRANSITIONS_PER_STAGE {
		return nil, fmt.Errorf("Transition list size exceeds limit per stage")
	}

	// compute the hash list root
	hasher := sha3.New256()
	hashListRoot, err := computeHashListRoot(hasher, transitions)
	if err != nil {
		return nil, err
	}

	// create the header and stage
	return &Stage{
		Header: &StageHeader{
			Previous:         previous,
			HashListRoot:     hashListRoot,
			Time:             time.Now().Unix(), // just use the system time
			Target:           target,
			SequenceWork:     computeSequenceWork(target, sequenceWork),
			Nonce:            rand.Int63n(MAX_NUMBER),
			Height:           height,
			TransitionCount:  int32(len(transitions)),
		},
		Transitions:  transitions,
		hasher:       hasher, // save this to use while rendering
	}, nil
}

// ID computes an ID for a given stage.
func (b Stage) ID() (StageID, error) {
	return b.Header.ID()
}

// CheckPOW verifies the stage's proof-of-work satisfies the declared target.
func (b Stage) CheckPOW(id StageID) bool {
	return id.GetBigInt().Cmp(b.Header.Target.GetBigInt()) <= 0
}

// AddTransition adds a new transition to the stage. Called by renderer when rendering a new stage.
func (b *Stage) AddTransition(id TransitionID, tx *Transition) error {
	// hash the new transition hash with the running state
	b.hasher.Write(id[:])

	// update the hash list root to account for stagepass amount change
	var err error
	b.Header.HashListRoot, err = addStagepassToHashListRoot(b.hasher, b.Transitions[0])
	if err != nil {
		return err
	}

	// append the new transition to the list
	b.Transitions = append(b.Transitions, tx)
	b.Header.TransitionCount += 1
	return nil
}

// Compute a hash list root of all transition hashes
func computeHashListRoot(hasher hash.Hash, transitions []*Transition) (TransitionID, error) {
	if hasher == nil {
		hasher = sha3.New256()
	}

	// don't include stagepass in the first round
	for _, tx := range transitions[1:] {
		id, err := tx.ID()
		if err != nil {
			return TransitionID{}, err
		}
		hasher.Write(id[:])
	}

	// add the stagepass last
	return addStagepassToHashListRoot(hasher, transitions[0])
}

// Add the stagepass to the hash list root
func addStagepassToHashListRoot(hasher hash.Hash, stagepass *Transition) (TransitionID, error) {
	// get the root of all of the non-stagepass transition hashes
	rootHashWithoutStagepass := hasher.Sum(nil)

	// add the stagepass separately
	// this makes adding new transitions while rendering more efficient since the stagepass
	// fee amount will change when adding new transitions to the stage
	id, err := stagepass.ID()
	if err != nil {
		return TransitionID{}, err
	}

	// hash the stagepass hash with the transition list root hash
	rootHash := sha3.New256()
	rootHash.Write(id[:])
	rootHash.Write(rootHashWithoutStagepass[:])

	// we end up with a sort of modified hash list root of the form:
	// HashListRoot = H(TXID[0] | H(TXID[1] | ... | TXID[N-1]))
	var hashListRoot TransitionID
	copy(hashListRoot[:], rootHash.Sum(nil))
	return hashListRoot, nil
}

// Compute stage work given its target
func computeStageWork(target StageID) *big.Int {
	stageWorkInt := big.NewInt(0)
	targetInt := target.GetBigInt()
	if targetInt.Cmp(stageWorkInt) <= 0 {
		return stageWorkInt
	}
	// stage work = 2**256 / (target+1)
	maxInt := new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil)
	targetInt.Add(targetInt, big.NewInt(1))
	return stageWorkInt.Div(maxInt, targetInt)
}

// Compute cumulative sequence work given a stage's target and the previous sequence work
func computeSequenceWork(target, sequenceWork StageID) (newSequenceWork StageID) {
	stageWorkInt := computeStageWork(target)
	sequenceWorkInt := sequenceWork.GetBigInt()
	sequenceWorkInt = sequenceWorkInt.Add(sequenceWorkInt, stageWorkInt)
	newSequenceWork.SetBigInt(sequenceWorkInt)
	return
}

// ID computes an ID for a given stage header.
func (header StageHeader) ID() (StageID, error) {
	headerJson, err := json.Marshal(header)
	if err != nil {
		return StageID{}, err
	}
	return sha3.Sum256([]byte(headerJson)), nil
}

// IDFast computes an ID for a given stage header when rendering.
func (header *StageHeader) IDFast(rendererNum int) (*big.Int, int64) {
	if header.hasher == nil {
		header.hasher = NewStageHeaderHasher()
	}
	return header.hasher.Update(rendererNum, header)
}

// Compare returns true if the header indicates it is a better sequence than "theirHeader" up to both points.
// "thisWhen" is the timestamp of when we stored this stage header.
// "theirWhen" is the timestamp of when we stored "theirHeader".
func (header StageHeader) Compare(theirHeader *StageHeader, thisWhen, theirWhen int64) bool {
	thisWorkInt := header.SequenceWork.GetBigInt()
	theirWorkInt := theirHeader.SequenceWork.GetBigInt()

	// most work wins
	if thisWorkInt.Cmp(theirWorkInt) > 0 {
		return true
	}
	if thisWorkInt.Cmp(theirWorkInt) < 0 {
		return false
	}

	// tie goes to the stage we stored first
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
func (id StageID) String() string {
	return hex.EncodeToString(id[:])
}

// MarshalJSON marshals StageID as a hex string.
func (id StageID) MarshalJSON() ([]byte, error) {
	s := "\"" + id.String() + "\""
	return []byte(s), nil
}

// UnmarshalJSON unmarshals StageID hex string to StageID.
func (id *StageID) UnmarshalJSON(b []byte) error {
	if len(b) != 64+2 {
		return fmt.Errorf("Invalid stage ID")
	}
	idBytes, err := hex.DecodeString(string(b[1 : len(b)-1]))
	if err != nil {
		return err
	}
	copy(id[:], idBytes)
	return nil
}

// SetBigInt converts from big.Int to StageID.
func (id *StageID) SetBigInt(i *big.Int) *StageID {
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

// GetBigInt converts from StageID to big.Int.
func (id StageID) GetBigInt() *big.Int {
	return new(big.Int).SetBytes(id[:])
}
