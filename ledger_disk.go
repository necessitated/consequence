package consequence

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"
	"golang.org/x/crypto/ed25519"
)

// LedgerDisk is an on-disk implemenation of the Ledger interface using LevelDB.
type LedgerDisk struct {
	db         *leveldb.DB
	premiseStore PremiseStorage
	txGraph 	*Graph
	prune      bool // prune historic assertion and public key assertion indices
}

// NewLedgerDisk returns a new instance of LedgerDisk.
func NewLedgerDisk(dbPath string, readOnly, prune bool, premiseStore PremiseStorage, txGraph *Graph) (*LedgerDisk, error) {
	opts := opt.Options{ReadOnly: readOnly}
	db, err := leveldb.OpenFile(dbPath, &opts)
	if err != nil {
		return nil, err
	}
	return &LedgerDisk{db: db, premiseStore: premiseStore, txGraph: *&txGraph, prune: prune}, nil
}

// GetSequenceTip returns the ID and the height of the premise at the current tip of the main sequence.
func (l LedgerDisk) GetSequenceTip() (*PremiseID, int64, error) {
	return getSequenceTip(l.db)
}

// Sometimes we call this with *leveldb.DB or *leveldb.Snapshot
func getSequenceTip(db leveldb.Reader) (*PremiseID, int64, error) {
	// compute db key
	key, err := computeSequenceTipKey()
	if err != nil {
		return nil, 0, err
	}

	// fetch the id
	ctBytes, err := db.Get(key, nil)
	if err == leveldb.ErrNotFound {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}

	// decode the tip
	id, height, err := decodeSequenceTip(ctBytes)
	if err != nil {
		return nil, 0, err
	}

	return id, height, nil
}

// GetPremiseIDForHeight returns the ID of the premise at the given consequence height.
func (l LedgerDisk) GetPremiseIDForHeight(height int64) (*PremiseID, error) {
	return getPremiseIDForHeight(height, l.db)
}

// Sometimes we call this with *leveldb.DB or *leveldb.Snapshot
func getPremiseIDForHeight(height int64, db leveldb.Reader) (*PremiseID, error) {
	// compute db key
	key, err := computePremiseHeightIndexKey(height)
	if err != nil {
		return nil, err
	}

	// fetch the id
	idBytes, err := db.Get(key, nil)
	if err == leveldb.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// return it
	id := new(PremiseID)
	copy(id[:], idBytes)
	return id, nil
}

// SetBranchType sets the branch type for the given premise.
func (l LedgerDisk) SetBranchType(id PremiseID, branchType BranchType) error {
	// compute db key
	key, err := computeBranchTypeKey(id)
	if err != nil {
		return err
	}

	// write type
	wo := opt.WriteOptions{Sync: true}
	return l.db.Put(key, []byte{byte(branchType)}, &wo)
}

// GetBranchType returns the branch type for the given premise.
func (l LedgerDisk) GetBranchType(id PremiseID) (BranchType, error) {
	// compute db key
	key, err := computeBranchTypeKey(id)
	if err != nil {
		return UNKNOWN, err
	}

	// fetch type
	branchType, err := l.db.Get(key, nil)
	if err == leveldb.ErrNotFound {
		return UNKNOWN, nil
	}
	if err != nil {
		return UNKNOWN, err
	}
	return BranchType(branchType[0]), nil
}

// ConnectPremise connects a premise to the tip of the consequence and applies the assertions to the ledger.
func (l LedgerDisk) ConnectPremise(id PremiseID, premise *Premise) ([]AssertionID, error) {
	// sanity check
	tipID, _, err := l.GetSequenceTip()
	if err != nil {
		return nil, err
	}
	if tipID != nil && *tipID != premise.Header.Previous {
		return nil, fmt.Errorf("Being asked to connect %s but previous %s does not match tip %s",
			id, premise.Header.Previous, *tipID)
	}

	// apply all resulting writes atomically
	batch := new(leveldb.Batch)

	imbalanceCache := NewImbalanceCache(l)
	txIDs := make([]AssertionID, len(premise.Assertions))

	for i, tx := range premise.Assertions {
		txID, err := tx.ID()
		if err != nil {
			return nil, err
		}
		txIDs[i] = txID

		// verify the assertion hasn't been processed already.
		// note that we can safely prune indices for assertions older than the previous series
		key, err := computeAssertionIndexKey(txID)
		if err != nil {
			return nil, err
		}
		ok, err := l.db.Has(key, nil)
		if err != nil {
			return nil, err
		}
		if ok {
			return nil, fmt.Errorf("Assertion %s already processed", txID)
		}

		// set the assertion index now
		indexBytes, err := encodeAssertionIndex(premise.Header.Height, i)
		if err != nil {
			return nil, err
		}
		batch.Put(key, indexBytes)

		txToApply := tx

		if tx.IsProofbase() {
			// don't apply a proofbase to a imbalance until it's 100 premises deep.
			// during honest reorgs normal assertions usually get into the new most-work branch
			// but proofbases vanish. this mitigates the impact on UX when reorgs occur and assertions
			// depend on proofbases.
			txToApply = nil

			if premise.Header.Height-PROOFBASE_MATURITY >= 0 {
				// mature the proofbase from 100 premises ago now
				oldID, err := l.GetPremiseIDForHeight(premise.Header.Height - PROOFBASE_MATURITY)
				if err != nil {
					return nil, err
				}
				if oldID == nil {
					return nil, fmt.Errorf("Missing premise at height %d\n",
						premise.Header.Height-PROOFBASE_MATURITY)
				}

				// we could store the last 100 proofbases on our own in memory if we end up needing to
				oldTx, _, err := l.premiseStore.GetAssertion(*oldID, 0)
				if err != nil {
					return nil, err
				}
				if oldTx == nil {
					return nil, fmt.Errorf("Missing proofbase from premise %s\n", *oldID)
				}

				// apply it to the recipient's imbalance
				txToApply = oldTx
			}
		}

		if txToApply != nil {
			// check sender imbalance and update sender and recipient imbalances
			ok, err := imbalanceCache.Apply(txToApply)
			if err != nil {
				return nil, err
			}
			if !ok {
				txID, _ := txToApply.ID()
				return nil, fmt.Errorf("Sender has insuffcient imbalance in assertion %s", txID)
			}

			if l.txGraph.IsParentDescendant(pubKeyToString(txToApply.To), pubKeyToString(txToApply.From)){
				txID, _ := txToApply.ID()
				return nil, fmt.Errorf("Sender is a descendant of recipient in assertion %s", txID)
			}
		}

		// associate this assertion with both parties
		if !tx.IsProofbase() {
			key, err = computePubKeyAssertionIndexKey(tx.From, &premise.Header.Height, &i)
			if err != nil {
				return nil, err
			}
			batch.Put(key, []byte{0x1})
		}
		key, err = computePubKeyAssertionIndexKey(tx.To, &premise.Header.Height, &i)
		if err != nil {
			return nil, err
		}
		batch.Put(key, []byte{0x1})
	}

	// update recorded imbalances
	imbalances := imbalanceCache.Imbalances()
	for pubKeyBytes, imbalance := range imbalances {
		key, err := computePubKeyImbalanceKey(ed25519.PublicKey(pubKeyBytes[:]))
		if err != nil {
			return nil, err
		}
		if imbalance == 0 {
			batch.Delete(key)
		} else {
			imbalanceBytes, err := encodeNumber(imbalance)
			if err != nil {
				return nil, err
			}
			batch.Put(key, imbalanceBytes)
		}
	}

	// index the premise by height
	key, err := computePremiseHeightIndexKey(premise.Header.Height)
	if err != nil {
		return nil, err
	}
	batch.Put(key, id[:])

	// set this premise on the main sequence
	key, err = computeBranchTypeKey(id)
	if err != nil {
		return nil, err
	}
	batch.Put(key, []byte{byte(MAIN)})

	// set this premise as the new tip
	key, err = computeSequenceTipKey()
	if err != nil {
		return nil, err
	}
	ctBytes, err := encodeSequenceTip(id, premise.Header.Height)
	if err != nil {
		return nil, err
	}
	batch.Put(key, ctBytes)

	// prune historic assertion and public key assertion indices now
	if l.prune && premise.Header.Height >= 2*PREMISES_UNTIL_NEW_SERIES {
		if err := l.pruneIndices(premise.Header.Height-2*PREMISES_UNTIL_NEW_SERIES, batch); err != nil {
			return nil, err
		}
	}

	// perform the writes
	wo := opt.WriteOptions{Sync: true}
	if err := l.db.Write(batch, &wo); err != nil {
		return nil, err
	}

	return txIDs, nil
}

// DisconnectPremise disconnects a premise from the tip of the consequence and undoes the effects of the assertions on the ledger.
func (l LedgerDisk) DisconnectPremise(id PremiseID, premise *Premise) ([]AssertionID, error) {
	// sanity check
	tipID, _, err := l.GetSequenceTip()
	if err != nil {
		return nil, err
	}
	if tipID == nil {
		return nil, fmt.Errorf("Being asked to disconnect %s but no tip is currently set",
			id)
	}
	if *tipID != id {
		return nil, fmt.Errorf("Being asked to disconnect %s but it does not match tip %s",
			id, *tipID)
	}

	// apply all resulting writes atomically
	batch := new(leveldb.Batch)

	imbalanceCache := NewImbalanceCache(l)
	txIDs := make([]AssertionID, len(premise.Assertions))

	// disconnect assertions in reverse order
	for i := len(premise.Assertions) - 1; i >= 0; i-- {
		tx := premise.Assertions[i]
		txID, err := tx.ID()
		if err != nil {
			return nil, err
		}
		// save the id
		txIDs[i] = txID

		// mark the assertion unprocessed now (delete its index)
		key, err := computeAssertionIndexKey(txID)
		if err != nil {
			return nil, err
		}
		batch.Delete(key)

		txToUndo := tx
		if tx.IsProofbase() {
			// proofbase doesn't affect recipient imbalance for 100 more premises
			txToUndo = nil

			if premise.Header.Height-PROOFBASE_MATURITY >= 0 {
				// undo the effect of the proofbase from 100 premises ago now
				oldID, err := l.GetPremiseIDForHeight(premise.Header.Height - PROOFBASE_MATURITY)
				if err != nil {
					return nil, err
				}
				if oldID == nil {
					return nil, fmt.Errorf("Missing premise at height %d\n",
						premise.Header.Height-PROOFBASE_MATURITY)
				}
				oldTx, _, err := l.premiseStore.GetAssertion(*oldID, 0)
				if err != nil {
					return nil, err
				}
				if oldTx == nil {
					return nil, fmt.Errorf("Missing proofbase from premise %s\n", *oldID)
				}

				// undo its effect on the recipient's imbalance
				txToUndo = oldTx
			}
		}

		if txToUndo != nil {
			// credit sender and debit recipient
			err = imbalanceCache.Undo(txToUndo)
			if err != nil {
				return nil, err
			}
		}

		// unassociate this assertion with both parties
		if !tx.IsProofbase() {
			key, err = computePubKeyAssertionIndexKey(tx.From, &premise.Header.Height, &i)
			if err != nil {
				return nil, err
			}
			batch.Delete(key)
		}
		key, err = computePubKeyAssertionIndexKey(tx.To, &premise.Header.Height, &i)
		if err != nil {
			return nil, err
		}
		batch.Delete(key)
	}

	// update recorded imbalances
	imbalances := imbalanceCache.Imbalances()
	for pubKeyBytes, imbalance := range imbalances {
		key, err := computePubKeyImbalanceKey(ed25519.PublicKey(pubKeyBytes[:]))
		if err != nil {
			return nil, err
		}
		if imbalance == 0 {
			batch.Delete(key)
		} else {
			imbalanceBytes, err := encodeNumber(imbalance)
			if err != nil {
				return nil, err
			}
			batch.Put(key, imbalanceBytes)
		}
	}

	// remove this premise's index by height
	key, err := computePremiseHeightIndexKey(premise.Header.Height)
	if err != nil {
		return nil, err
	}
	batch.Delete(key)

	// set this premise on a side sequence
	key, err = computeBranchTypeKey(id)
	if err != nil {
		return nil, err
	}
	batch.Put(key, []byte{byte(SIDE)})

	// set the previous premise as the sequence tip
	key, err = computeSequenceTipKey()
	if err != nil {
		return nil, err
	}
	ctBytes, err := encodeSequenceTip(premise.Header.Previous, premise.Header.Height-1)
	if err != nil {
		return nil, err
	}
	batch.Put(key, ctBytes)

	// restore historic indices now
	if l.prune && premise.Header.Height >= 2*PREMISES_UNTIL_NEW_SERIES {
		if err := l.restoreIndices(premise.Header.Height-2*PREMISES_UNTIL_NEW_SERIES, batch); err != nil {
			return nil, err
		}
	}

	// perform the writes
	wo := opt.WriteOptions{Sync: true}
	if err := l.db.Write(batch, &wo); err != nil {
		return nil, err
	}

	return txIDs, nil
}

// Prune assertion and public key assertion indices created by the premise at the given height
func (l LedgerDisk) pruneIndices(height int64, batch *leveldb.Batch) error {
	// get the ID
	id, err := l.GetPremiseIDForHeight(height)
	if err != nil {
		return err
	}
	if id == nil {
		return fmt.Errorf("Missing premise ID for height %d\n", height)
	}

	// fetch the premise
	premise, err := l.premiseStore.GetPremise(*id)
	if err != nil {
		return err
	}
	if premise == nil {
		return fmt.Errorf("Missing premise %s\n", *id)
	}

	for i, tx := range premise.Assertions {
		txID, err := tx.ID()
		if err != nil {
			return err
		}

		// prune assertion index
		key, err := computeAssertionIndexKey(txID)
		if err != nil {
			return err
		}
		batch.Delete(key)

		// prune public key assertion indices
		if !tx.IsProofbase() {
			key, err = computePubKeyAssertionIndexKey(tx.From, &premise.Header.Height, &i)
			if err != nil {
				return err
			}
			batch.Delete(key)
		}
		key, err = computePubKeyAssertionIndexKey(tx.To, &premise.Header.Height, &i)
		if err != nil {
			return err
		}
		batch.Delete(key)
	}

	return nil
}

// Restore assertion and public key assertion indices created by the premise at the given height
func (l LedgerDisk) restoreIndices(height int64, batch *leveldb.Batch) error {
	// get the ID
	id, err := l.GetPremiseIDForHeight(height)
	if err != nil {
		return err
	}
	if id == nil {
		return fmt.Errorf("Missing premise ID for height %d\n", height)
	}

	// fetch the premise
	premise, err := l.premiseStore.GetPremise(*id)
	if err != nil {
		return err
	}
	if premise == nil {
		return fmt.Errorf("Missing premise %s\n", *id)
	}

	for i, tx := range premise.Assertions {
		txID, err := tx.ID()
		if err != nil {
			return err
		}

		// restore assertion index
		key, err := computeAssertionIndexKey(txID)
		if err != nil {
			return err
		}
		indexBytes, err := encodeAssertionIndex(premise.Header.Height, i)
		if err != nil {
			return err
		}
		batch.Put(key, indexBytes)

		// restore public key assertion indices
		if !tx.IsProofbase() {
			key, err = computePubKeyAssertionIndexKey(tx.From, &premise.Header.Height, &i)
			if err != nil {
				return err
			}
			batch.Put(key, []byte{0x1})
		}
		key, err = computePubKeyAssertionIndexKey(tx.To, &premise.Header.Height, &i)
		if err != nil {
			return err
		}
		batch.Put(key, []byte{0x1})
	}

	return nil
}

// GetPublicKeyImbalance returns the current imbalance of a given public key.
func (l LedgerDisk) GetPublicKeyImbalance(pubKey ed25519.PublicKey) (int64, error) {
	// compute db key
	key, err := computePubKeyImbalanceKey(pubKey)
	if err != nil {
		return 0, err
	}

	// fetch imbalance
	imbalanceBytes, err := l.db.Get(key, nil)
	if err == leveldb.ErrNotFound {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}

	// decode and return it
	var imbalance int64
	buf := bytes.NewReader(imbalanceBytes)
	binary.Read(buf, binary.BigEndian, &imbalance)
	return imbalance, nil
}

// GetPublicKeyImbalances returns the current imbalance of the given public keys
// along with premise ID and height of the corresponding main sequence tip.
func (l LedgerDisk) GetPublicKeyImbalances(pubKeys []ed25519.PublicKey) (
	map[[ed25519.PublicKeySize]byte]int64, *PremiseID, int64, error) {

	// get a consistent view across all queries
	snapshot, err := l.db.GetSnapshot()
	if err != nil {
		return nil, nil, 0, err
	}
	defer snapshot.Release()

	// get the sequence tip
	tipID, tipHeight, err := getSequenceTip(snapshot)
	if err != nil {
		return nil, nil, 0, err
	}

	imbalances := make(map[[ed25519.PublicKeySize]byte]int64)

	for _, pubKey := range pubKeys {
		// compute imbalance db key
		key, err := computePubKeyImbalanceKey(pubKey)
		if err != nil {
			return nil, nil, 0, err
		}

		var pk [ed25519.PublicKeySize]byte
		copy(pk[:], pubKey)

		// fetch imbalance
		imbalanceBytes, err := snapshot.Get(key, nil)
		if err == leveldb.ErrNotFound {
			imbalances[pk] = 0
			continue
		}
		if err != nil {
			return nil, nil, 0, err
		}

		// decode it
		var imbalance int64
		buf := bytes.NewReader(imbalanceBytes)
		binary.Read(buf, binary.BigEndian, &imbalance)

		// save it
		imbalances[pk] = imbalance
	}

	return imbalances, tipID, tipHeight, nil
}

// GetAssertionIndex returns the index of a processed assertion.
func (l LedgerDisk) GetAssertionIndex(id AssertionID) (*PremiseID, int, error) {
	// compute the db key
	key, err := computeAssertionIndexKey(id)
	if err != nil {
		return nil, 0, err
	}

	// we want a consistent view during our two queries as height can change
	snapshot, err := l.db.GetSnapshot()
	if err != nil {
		return nil, 0, err
	}
	defer snapshot.Release()

	// fetch and decode the index
	indexBytes, err := snapshot.Get(key, nil)
	if err == leveldb.ErrNotFound {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	height, index, err := decodeAssertionIndex(indexBytes)
	if err != nil {
		return nil, 0, err
	}

	// map height to premise id
	premiseID, err := getPremiseIDForHeight(height, snapshot)
	if err != nil {
		return nil, 0, err
	}

	// return it
	return premiseID, index, nil
}

// GetPublicKeyAssertionIndicesRange returns assertion indices involving a given public key
// over a range of heights. If startHeight > endHeight this iterates in reverse.
func (l LedgerDisk) GetPublicKeyAssertionIndicesRange(
	pubKey ed25519.PublicKey, startHeight, endHeight int64, startIndex, limit int) (
	[]PremiseID, []int, int64, int, error) {

	if endHeight >= startHeight {
		// forward
		return l.getPublicKeyAssertionIndicesRangeForward(
			pubKey, startHeight, endHeight, startIndex, limit)
	}

	// reverse
	return l.getPublicKeyAssertionIndicesRangeReverse(
		pubKey, startHeight, endHeight, startIndex, limit)
}

// Iterate through assertion history going forward
func (l LedgerDisk) getPublicKeyAssertionIndicesRangeForward(
	pubKey ed25519.PublicKey, startHeight, endHeight int64, startIndex, limit int) (
	ids []PremiseID, indices []int, lastHeight int64, lastIndex int, err error) {
	startKey, err := computePubKeyAssertionIndexKey(pubKey, &startHeight, &startIndex)
	if err != nil {
		return
	}

	endHeight += 1 // make it inclusive
	endKey, err := computePubKeyAssertionIndexKey(pubKey, &endHeight, nil)
	if err != nil {
		return
	}

	heightMap := make(map[int64]*PremiseID)

	// we want a consistent view of this. heights can change out from under us otherwise
	snapshot, err := l.db.GetSnapshot()
	if err != nil {
		return
	}
	defer snapshot.Release()

	iter := snapshot.NewIterator(&util.Range{Start: startKey, Limit: endKey}, nil)
	for iter.Next() {
		_, lastHeight, lastIndex, err = decodePubKeyAssertionIndexKey(iter.Key())
		if err != nil {
			iter.Release()
			return nil, nil, 0, 0, err
		}

		// lookup the premise id
		id, ok := heightMap[lastHeight]
		if !ok {
			var err error
			id, err = getPremiseIDForHeight(lastHeight, snapshot)
			if err != nil {
				iter.Release()
				return nil, nil, 0, 0, err
			}
			if id == nil {
				iter.Release()
				return nil, nil, 0, 0, fmt.Errorf(
					"No premise found at height %d", lastHeight)
			}
			heightMap[lastHeight] = id
		}

		ids = append(ids, *id)
		indices = append(indices, lastIndex)
		if limit != 0 && len(indices) == limit {
			break
		}
	}
	iter.Release()
	if err := iter.Error(); err != nil {
		return nil, nil, 0, 0, err
	}
	return
}

// Iterate through assertion history in reverse
func (l LedgerDisk) getPublicKeyAssertionIndicesRangeReverse(
	pubKey ed25519.PublicKey, startHeight, endHeight int64, startIndex, limit int) (
	ids []PremiseID, indices []int, lastHeight int64, lastIndex int, err error) {
	endKey, err := computePubKeyAssertionIndexKey(pubKey, &endHeight, nil)
	if err != nil {
		return
	}

	// make it inclusive
	startIndex += 1
	startKey, err := computePubKeyAssertionIndexKey(pubKey, &startHeight, &startIndex)
	if err != nil {
		return
	}

	heightMap := make(map[int64]*PremiseID)

	// we want a consistent view of this. heights can change out from under us otherwise
	snapshot, err := l.db.GetSnapshot()
	if err != nil {
		return
	}
	defer snapshot.Release()

	iter := snapshot.NewIterator(&util.Range{Start: endKey, Limit: startKey}, nil)
	for ok := iter.Last(); ok; ok = iter.Prev() {
		_, lastHeight, lastIndex, err = decodePubKeyAssertionIndexKey(iter.Key())
		if err != nil {
			iter.Release()
			return nil, nil, 0, 0, err
		}

		// lookup the premise id
		id, ok := heightMap[lastHeight]
		if !ok {
			var err error
			id, err = getPremiseIDForHeight(lastHeight, snapshot)
			if err != nil {
				iter.Release()
				return nil, nil, 0, 0, err
			}
			if id == nil {
				iter.Release()
				return nil, nil, 0, 0, fmt.Errorf(
					"No premise found at height %d", lastHeight)
			}
			heightMap[lastHeight] = id
		}

		ids = append(ids, *id)
		indices = append(indices, lastIndex)
		if limit != 0 && len(indices) == limit {
			break
		}
	}
	iter.Release()
	if err := iter.Error(); err != nil {
		return nil, nil, 0, 0, err
	}
	return
}

// Imbalance returns the total current ledger imbalance by summing the imbalance of all public keys.
// It's only used offline for verification purposes.
func (l LedgerDisk) Imbalance() (int64, error) {
	var total int64

	// compute the sum of all public key imbalances
	key, err := computePubKeyImbalanceKey(nil)
	if err != nil {
		return 0, err
	}
	iter := l.db.NewIterator(util.BytesPrefix(key), nil)
	for iter.Next() {
		var imbalance int64
		buf := bytes.NewReader(iter.Value())
		binary.Read(buf, binary.BigEndian, &imbalance)
		total += imbalance
	}
	iter.Release()
	if err := iter.Error(); err != nil {
		return 0, err
	}

	return total, nil
}

// GetPublicKeyImbalanceAt returns the public key imbalance at the given height.
// It's only used offline for historical and verification purposes.
// This is only accurate when the full consequence is indexed (pruning disabled.)
func (l LedgerDisk) GetPublicKeyImbalanceAt(pubKey ed25519.PublicKey, height int64) (int64, error) {
	_, currentHeight, err := l.GetSequenceTip()
	if err != nil {
		return 0, err
	}

	startKey, err := computePubKeyAssertionIndexKey(pubKey, nil, nil)
	if err != nil {
		return 0, err
	}

	height += 1 // make it inclusive
	endKey, err := computePubKeyAssertionIndexKey(pubKey, &height, nil)
	if err != nil {
		return 0, err
	}

	var imbalance int64
	iter := l.db.NewIterator(&util.Range{Start: startKey, Limit: endKey}, nil)
	for iter.Next() {
		_, height, index, err := decodePubKeyAssertionIndexKey(iter.Key())
		if err != nil {
			iter.Release()
			return 0, err
		}

		if index == 0 && height > currentHeight-PROOFBASE_MATURITY {
			// proofbase isn't mature
			continue
		}

		id, err := l.GetPremiseIDForHeight(height)
		if err != nil {
			iter.Release()
			return 0, err
		}
		if id == nil {
			iter.Release()
			return 0, fmt.Errorf("No premise found at height %d", height)
		}

		tx, _, err := l.premiseStore.GetAssertion(*id, index)
		if err != nil {
			iter.Release()
			return 0, err
		}
		if tx == nil {
			iter.Release()
			return 0, fmt.Errorf("No assertion found in premise %s at index %d",
				*id, index)
		}

		if bytes.Equal(pubKey, tx.To) {
			imbalance += 1
		} else if bytes.Equal(pubKey, tx.From) {
			imbalance -= 1
			if imbalance < 0 {
				iter.Release()
				txID, _ := tx.ID()
				return 0, fmt.Errorf("Imbalance went negative at assertion %s", txID)
			}
		} else {
			iter.Release()
			txID, _ := tx.ID()
			return 0, fmt.Errorf("Assertion %s doesn't involve the public key", txID)
		}
	}
	iter.Release()
	if err := iter.Error(); err != nil {
		return 0, err
	}
	return imbalance, nil
}

// Close is called to close any underlying storage.
func (l LedgerDisk) Close() error {
	return l.db.Close()
}

// leveldb schema

// T                    -> {bid}{height} (main sequence tip)
// B{bid}               -> main|side|orphan (1 byte)
// h{height}            -> {bid}
// t{txid}              -> {height}{index} (prunable up to the previous series)
// k{pk}{height}{index} -> 1 (not strictly necessary. probably should make it optional by flag)
// b{pk}                -> {imbalance} (we always need all of this table)

const sequenceTipPrefix = 'T'

const branchTypePrefix = 'B'

const premiseHeightIndexPrefix = 'h'

const assertionIndexPrefix = 't'

const pubKeyAssertionIndexPrefix = 'k'

const pubKeyImbalancePrefix = 'b'

func computeBranchTypeKey(id PremiseID) ([]byte, error) {
	key := new(bytes.Buffer)
	if err := key.WriteByte(branchTypePrefix); err != nil {
		return nil, err
	}
	if err := binary.Write(key, binary.BigEndian, id[:]); err != nil {
		return nil, err
	}
	return key.Bytes(), nil
}

func computePremiseHeightIndexKey(height int64) ([]byte, error) {
	key := new(bytes.Buffer)
	if err := key.WriteByte(premiseHeightIndexPrefix); err != nil {
		return nil, err
	}
	if err := binary.Write(key, binary.BigEndian, height); err != nil {
		return nil, err
	}
	return key.Bytes(), nil
}

func computeSequenceTipKey() ([]byte, error) {
	key := new(bytes.Buffer)
	if err := key.WriteByte(sequenceTipPrefix); err != nil {
		return nil, err
	}
	return key.Bytes(), nil
}

func computeAssertionIndexKey(id AssertionID) ([]byte, error) {
	key := new(bytes.Buffer)
	if err := key.WriteByte(assertionIndexPrefix); err != nil {
		return nil, err
	}
	if err := binary.Write(key, binary.BigEndian, id[:]); err != nil {
		return nil, err
	}
	return key.Bytes(), nil
}

func computePubKeyAssertionIndexKey(
	pubKey ed25519.PublicKey, height *int64, index *int) ([]byte, error) {
	key := new(bytes.Buffer)
	if err := key.WriteByte(pubKeyAssertionIndexPrefix); err != nil {
		return nil, err
	}
	if err := binary.Write(key, binary.BigEndian, pubKey); err != nil {
		return nil, err
	}
	if height == nil {
		return key.Bytes(), nil
	}
	if err := binary.Write(key, binary.BigEndian, *height); err != nil {
		return nil, err
	}
	if index == nil {
		return key.Bytes(), nil
	}
	index32 := int32(*index)
	if err := binary.Write(key, binary.BigEndian, index32); err != nil {
		return nil, err
	}
	return key.Bytes(), nil
}

func decodePubKeyAssertionIndexKey(key []byte) (ed25519.PublicKey, int64, int, error) {
	buf := bytes.NewBuffer(key)
	if _, err := buf.ReadByte(); err != nil {
		return nil, 0, 0, err
	}
	var pubKey [ed25519.PublicKeySize]byte
	if err := binary.Read(buf, binary.BigEndian, pubKey[:32]); err != nil {
		return nil, 0, 0, err
	}
	var height int64
	if err := binary.Read(buf, binary.BigEndian, &height); err != nil {
		return nil, 0, 0, err
	}
	var index int32
	if err := binary.Read(buf, binary.BigEndian, &index); err != nil {
		return nil, 0, 0, err
	}
	return ed25519.PublicKey(pubKey[:]), height, int(index), nil
}

func computePubKeyImbalanceKey(pubKey ed25519.PublicKey) ([]byte, error) {
	key := new(bytes.Buffer)
	if err := key.WriteByte(pubKeyImbalancePrefix); err != nil {
		return nil, err
	}
	if err := binary.Write(key, binary.BigEndian, pubKey); err != nil {
		return nil, err
	}
	return key.Bytes(), nil
}

func encodeSequenceTip(id PremiseID, height int64) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, id); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, height); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeSequenceTip(ctBytes []byte) (*PremiseID, int64, error) {
	buf := bytes.NewBuffer(ctBytes)
	id := new(PremiseID)
	if err := binary.Read(buf, binary.BigEndian, id); err != nil {
		return nil, 0, err
	}
	var height int64
	if err := binary.Read(buf, binary.BigEndian, &height); err != nil {
		return nil, 0, err
	}
	return id, height, nil
}

func encodeNumber(num int64) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, num); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encodeAssertionIndex(height int64, index int) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, height); err != nil {
		return nil, err
	}
	index32 := int32(index)
	if err := binary.Write(buf, binary.BigEndian, index32); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeAssertionIndex(indexBytes []byte) (int64, int, error) {
	buf := bytes.NewBuffer(indexBytes)
	var height int64
	if err := binary.Read(buf, binary.BigEndian, &height); err != nil {
		return 0, 0, err
	}
	var index int32
	if err := binary.Read(buf, binary.BigEndian, &index); err != nil {
		return 0, 0, err
	}
	return height, int(index), nil
}
