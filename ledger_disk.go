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
	stageStore StageStorage
	txGraph 	*Graph
	prune      bool // prune historic transition and public key transition indices
}

// NewLedgerDisk returns a new instance of LedgerDisk.
func NewLedgerDisk(dbPath string, readOnly, prune bool, stageStore StageStorage, txGraph *Graph) (*LedgerDisk, error) {
	opts := opt.Options{ReadOnly: readOnly}
	db, err := leveldb.OpenFile(dbPath, &opts)
	if err != nil {
		return nil, err
	}
	return &LedgerDisk{db: db, stageStore: stageStore, txGraph: *&txGraph, prune: prune}, nil
}

// GetSequenceTip returns the ID and the height of the stage at the current tip of the main sequence.
func (l LedgerDisk) GetSequenceTip() (*StageID, int64, error) {
	return getSequenceTip(l.db)
}

// Sometimes we call this with *leveldb.DB or *leveldb.Snapshot
func getSequenceTip(db leveldb.Reader) (*StageID, int64, error) {
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

// GetStageIDForHeight returns the ID of the stage at the given consequence height.
func (l LedgerDisk) GetStageIDForHeight(height int64) (*StageID, error) {
	return getStageIDForHeight(height, l.db)
}

// Sometimes we call this with *leveldb.DB or *leveldb.Snapshot
func getStageIDForHeight(height int64, db leveldb.Reader) (*StageID, error) {
	// compute db key
	key, err := computeStageHeightIndexKey(height)
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
	id := new(StageID)
	copy(id[:], idBytes)
	return id, nil
}

// SetBranchType sets the branch type for the given stage.
func (l LedgerDisk) SetBranchType(id StageID, branchType BranchType) error {
	// compute db key
	key, err := computeBranchTypeKey(id)
	if err != nil {
		return err
	}

	// write type
	wo := opt.WriteOptions{Sync: true}
	return l.db.Put(key, []byte{byte(branchType)}, &wo)
}

// GetBranchType returns the branch type for the given stage.
func (l LedgerDisk) GetBranchType(id StageID) (BranchType, error) {
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

// ConnectStage connects a stage to the tip of the consequence and applies the transitions to the ledger.
func (l LedgerDisk) ConnectStage(id StageID, stage *Stage) ([]TransitionID, error) {
	// sanity check
	tipID, _, err := l.GetSequenceTip()
	if err != nil {
		return nil, err
	}
	if tipID != nil && *tipID != stage.Header.Previous {
		return nil, fmt.Errorf("Being asked to connect %s but previous %s does not match tip %s",
			id, stage.Header.Previous, *tipID)
	}

	// apply all resulting writes atomically
	batch := new(leveldb.Batch)

	imbalanceCache := NewImbalanceCache(l)
	txIDs := make([]TransitionID, len(stage.Transitions))

	for i, tx := range stage.Transitions {
		txID, err := tx.ID()
		if err != nil {
			return nil, err
		}
		txIDs[i] = txID

		// verify the transition hasn't been processed already.
		// note that we can safely prune indices for transitions older than the previous series
		key, err := computeTransitionIndexKey(txID)
		if err != nil {
			return nil, err
		}
		ok, err := l.db.Has(key, nil)
		if err != nil {
			return nil, err
		}
		if ok {
			return nil, fmt.Errorf("Transition %s already processed", txID)
		}

		// set the transition index now
		indexBytes, err := encodeTransitionIndex(stage.Header.Height, i)
		if err != nil {
			return nil, err
		}
		batch.Put(key, indexBytes)

		txToApply := tx

		if tx.IsStagepass() {
			// don't apply a stagepass to a imbalance until it's 100 stages deep.
			// during honest reorgs normal transitions usually get into the new most-work branch
			// but stagepasses vanish. this mitigates the impact on UX when reorgs occur and transitions
			// depend on stagepasses.
			txToApply = nil

			if stage.Header.Height-STAGEPASS_MATURITY >= 0 {
				// mature the stagepass from 100 stages ago now
				oldID, err := l.GetStageIDForHeight(stage.Header.Height - STAGEPASS_MATURITY)
				if err != nil {
					return nil, err
				}
				if oldID == nil {
					return nil, fmt.Errorf("Missing stage at height %d\n",
						stage.Header.Height-STAGEPASS_MATURITY)
				}

				// we could store the last 100 stagepasses on our own in memory if we end up needing to
				oldTx, _, err := l.stageStore.GetTransition(*oldID, 0)
				if err != nil {
					return nil, err
				}
				if oldTx == nil {
					return nil, fmt.Errorf("Missing stagepass from stage %s\n", *oldID)
				}

				// apply it to the receptor's imbalance
				txToApply = oldTx
			}
		}

		if txToApply != nil {
			// check tender imbalance and update tender and receptor imbalances
			ok, err := imbalanceCache.Apply(txToApply)
			if err != nil {
				return nil, err
			}
			if !ok {
				txID, _ := txToApply.ID()
				return nil, fmt.Errorf("Tender has insuffcient imbalance in transition %s", txID)
			}

			if l.txGraph.IsParentDescendant(pubKeyToString(txToApply.From), pubKeyToString(txToApply.To)){
				txID, _ := txToApply.ID()
				return nil, fmt.Errorf("Tender is a descendant of receptor in transition %s", txID)
			}
		}

		// associate this transition with both parties
		if !tx.IsStagepass() {
			key, err = computePubKeyTransitionIndexKey(tx.From, &stage.Header.Height, &i)
			if err != nil {
				return nil, err
			}
			batch.Put(key, []byte{0x1})
		}
		key, err = computePubKeyTransitionIndexKey(tx.To, &stage.Header.Height, &i)
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

	// index the stage by height
	key, err := computeStageHeightIndexKey(stage.Header.Height)
	if err != nil {
		return nil, err
	}
	batch.Put(key, id[:])

	// set this stage on the main sequence
	key, err = computeBranchTypeKey(id)
	if err != nil {
		return nil, err
	}
	batch.Put(key, []byte{byte(MAIN)})

	// set this stage as the new tip
	key, err = computeSequenceTipKey()
	if err != nil {
		return nil, err
	}
	ctBytes, err := encodeSequenceTip(id, stage.Header.Height)
	if err != nil {
		return nil, err
	}
	batch.Put(key, ctBytes)

	// prune historic transition and public key transition indices now
	if l.prune && stage.Header.Height >= 2*STAGES_UNTIL_NEW_SERIES {
		if err := l.pruneIndices(stage.Header.Height-2*STAGES_UNTIL_NEW_SERIES, batch); err != nil {
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

// DisconnectStage disconnects a stage from the tip of the consequence and undoes the effects of the transitions on the ledger.
func (l LedgerDisk) DisconnectStage(id StageID, stage *Stage) ([]TransitionID, error) {
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
	txIDs := make([]TransitionID, len(stage.Transitions))

	// disconnect transitions in reverse order
	for i := len(stage.Transitions) - 1; i >= 0; i-- {
		tx := stage.Transitions[i]
		txID, err := tx.ID()
		if err != nil {
			return nil, err
		}
		// save the id
		txIDs[i] = txID

		// mark the transition unprocessed now (delete its index)
		key, err := computeTransitionIndexKey(txID)
		if err != nil {
			return nil, err
		}
		batch.Delete(key)

		txToUndo := tx
		if tx.IsStagepass() {
			// stagepass doesn't affect receptor imbalance for 100 more stages
			txToUndo = nil

			if stage.Header.Height-STAGEPASS_MATURITY >= 0 {
				// undo the effect of the stagepass from 100 stages ago now
				oldID, err := l.GetStageIDForHeight(stage.Header.Height - STAGEPASS_MATURITY)
				if err != nil {
					return nil, err
				}
				if oldID == nil {
					return nil, fmt.Errorf("Missing stage at height %d\n",
						stage.Header.Height-STAGEPASS_MATURITY)
				}
				oldTx, _, err := l.stageStore.GetTransition(*oldID, 0)
				if err != nil {
					return nil, err
				}
				if oldTx == nil {
					return nil, fmt.Errorf("Missing stagepass from stage %s\n", *oldID)
				}

				// undo its effect on the receptor's imbalance
				txToUndo = oldTx
			}
		}

		if txToUndo != nil {
			// credit tender and debit receptor
			err = imbalanceCache.Undo(txToUndo)
			if err != nil {
				return nil, err
			}
		}

		// unassociate this transition with both parties
		if !tx.IsStagepass() {
			key, err = computePubKeyTransitionIndexKey(tx.From, &stage.Header.Height, &i)
			if err != nil {
				return nil, err
			}
			batch.Delete(key)
		}
		key, err = computePubKeyTransitionIndexKey(tx.To, &stage.Header.Height, &i)
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

	// remove this stage's index by height
	key, err := computeStageHeightIndexKey(stage.Header.Height)
	if err != nil {
		return nil, err
	}
	batch.Delete(key)

	// set this stage on a side sequence
	key, err = computeBranchTypeKey(id)
	if err != nil {
		return nil, err
	}
	batch.Put(key, []byte{byte(SIDE)})

	// set the previous stage as the sequence tip
	key, err = computeSequenceTipKey()
	if err != nil {
		return nil, err
	}
	ctBytes, err := encodeSequenceTip(stage.Header.Previous, stage.Header.Height-1)
	if err != nil {
		return nil, err
	}
	batch.Put(key, ctBytes)

	// restore historic indices now
	if l.prune && stage.Header.Height >= 2*STAGES_UNTIL_NEW_SERIES {
		if err := l.restoreIndices(stage.Header.Height-2*STAGES_UNTIL_NEW_SERIES, batch); err != nil {
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

// Prune transition and public key transition indices created by the stage at the given height
func (l LedgerDisk) pruneIndices(height int64, batch *leveldb.Batch) error {
	// get the ID
	id, err := l.GetStageIDForHeight(height)
	if err != nil {
		return err
	}
	if id == nil {
		return fmt.Errorf("Missing stage ID for height %d\n", height)
	}

	// fetch the stage
	stage, err := l.stageStore.GetStage(*id)
	if err != nil {
		return err
	}
	if stage == nil {
		return fmt.Errorf("Missing stage %s\n", *id)
	}

	for i, tx := range stage.Transitions {
		txID, err := tx.ID()
		if err != nil {
			return err
		}

		// prune transition index
		key, err := computeTransitionIndexKey(txID)
		if err != nil {
			return err
		}
		batch.Delete(key)

		// prune public key transition indices
		if !tx.IsStagepass() {
			key, err = computePubKeyTransitionIndexKey(tx.From, &stage.Header.Height, &i)
			if err != nil {
				return err
			}
			batch.Delete(key)
		}
		key, err = computePubKeyTransitionIndexKey(tx.To, &stage.Header.Height, &i)
		if err != nil {
			return err
		}
		batch.Delete(key)
	}

	return nil
}

// Restore transition and public key transition indices created by the stage at the given height
func (l LedgerDisk) restoreIndices(height int64, batch *leveldb.Batch) error {
	// get the ID
	id, err := l.GetStageIDForHeight(height)
	if err != nil {
		return err
	}
	if id == nil {
		return fmt.Errorf("Missing stage ID for height %d\n", height)
	}

	// fetch the stage
	stage, err := l.stageStore.GetStage(*id)
	if err != nil {
		return err
	}
	if stage == nil {
		return fmt.Errorf("Missing stage %s\n", *id)
	}

	for i, tx := range stage.Transitions {
		txID, err := tx.ID()
		if err != nil {
			return err
		}

		// restore transition index
		key, err := computeTransitionIndexKey(txID)
		if err != nil {
			return err
		}
		indexBytes, err := encodeTransitionIndex(stage.Header.Height, i)
		if err != nil {
			return err
		}
		batch.Put(key, indexBytes)

		// restore public key transition indices
		if !tx.IsStagepass() {
			key, err = computePubKeyTransitionIndexKey(tx.From, &stage.Header.Height, &i)
			if err != nil {
				return err
			}
			batch.Put(key, []byte{0x1})
		}
		key, err = computePubKeyTransitionIndexKey(tx.To, &stage.Header.Height, &i)
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
// along with stage ID and height of the corresponding main sequence tip.
func (l LedgerDisk) GetPublicKeyImbalances(pubKeys []ed25519.PublicKey) (
	map[[ed25519.PublicKeySize]byte]int64, *StageID, int64, error) {

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

// GetTransitionIndex returns the index of a processed transition.
func (l LedgerDisk) GetTransitionIndex(id TransitionID) (*StageID, int, error) {
	// compute the db key
	key, err := computeTransitionIndexKey(id)
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
	height, index, err := decodeTransitionIndex(indexBytes)
	if err != nil {
		return nil, 0, err
	}

	// map height to stage id
	stageID, err := getStageIDForHeight(height, snapshot)
	if err != nil {
		return nil, 0, err
	}

	// return it
	return stageID, index, nil
}

// GetPublicKeyTransitionIndicesRange returns transition indices involving a given public key
// over a range of heights. If startHeight > endHeight this iterates in reverse.
func (l LedgerDisk) GetPublicKeyTransitionIndicesRange(
	pubKey ed25519.PublicKey, startHeight, endHeight int64, startIndex, limit int) (
	[]StageID, []int, int64, int, error) {

	if endHeight >= startHeight {
		// forward
		return l.getPublicKeyTransitionIndicesRangeForward(
			pubKey, startHeight, endHeight, startIndex, limit)
	}

	// reverse
	return l.getPublicKeyTransitionIndicesRangeReverse(
		pubKey, startHeight, endHeight, startIndex, limit)
}

// Iterate through transition history going forward
func (l LedgerDisk) getPublicKeyTransitionIndicesRangeForward(
	pubKey ed25519.PublicKey, startHeight, endHeight int64, startIndex, limit int) (
	ids []StageID, indices []int, lastHeight int64, lastIndex int, err error) {
	startKey, err := computePubKeyTransitionIndexKey(pubKey, &startHeight, &startIndex)
	if err != nil {
		return
	}

	endHeight += 1 // make it inclusive
	endKey, err := computePubKeyTransitionIndexKey(pubKey, &endHeight, nil)
	if err != nil {
		return
	}

	heightMap := make(map[int64]*StageID)

	// we want a consistent view of this. heights can change out from under us otherwise
	snapshot, err := l.db.GetSnapshot()
	if err != nil {
		return
	}
	defer snapshot.Release()

	iter := snapshot.NewIterator(&util.Range{Start: startKey, Limit: endKey}, nil)
	for iter.Next() {
		_, lastHeight, lastIndex, err = decodePubKeyTransitionIndexKey(iter.Key())
		if err != nil {
			iter.Release()
			return nil, nil, 0, 0, err
		}

		// lookup the stage id
		id, ok := heightMap[lastHeight]
		if !ok {
			var err error
			id, err = getStageIDForHeight(lastHeight, snapshot)
			if err != nil {
				iter.Release()
				return nil, nil, 0, 0, err
			}
			if id == nil {
				iter.Release()
				return nil, nil, 0, 0, fmt.Errorf(
					"No stage found at height %d", lastHeight)
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

// Iterate through transition history in reverse
func (l LedgerDisk) getPublicKeyTransitionIndicesRangeReverse(
	pubKey ed25519.PublicKey, startHeight, endHeight int64, startIndex, limit int) (
	ids []StageID, indices []int, lastHeight int64, lastIndex int, err error) {
	endKey, err := computePubKeyTransitionIndexKey(pubKey, &endHeight, nil)
	if err != nil {
		return
	}

	// make it inclusive
	startIndex += 1
	startKey, err := computePubKeyTransitionIndexKey(pubKey, &startHeight, &startIndex)
	if err != nil {
		return
	}

	heightMap := make(map[int64]*StageID)

	// we want a consistent view of this. heights can change out from under us otherwise
	snapshot, err := l.db.GetSnapshot()
	if err != nil {
		return
	}
	defer snapshot.Release()

	iter := snapshot.NewIterator(&util.Range{Start: endKey, Limit: startKey}, nil)
	for ok := iter.Last(); ok; ok = iter.Prev() {
		_, lastHeight, lastIndex, err = decodePubKeyTransitionIndexKey(iter.Key())
		if err != nil {
			iter.Release()
			return nil, nil, 0, 0, err
		}

		// lookup the stage id
		id, ok := heightMap[lastHeight]
		if !ok {
			var err error
			id, err = getStageIDForHeight(lastHeight, snapshot)
			if err != nil {
				iter.Release()
				return nil, nil, 0, 0, err
			}
			if id == nil {
				iter.Release()
				return nil, nil, 0, 0, fmt.Errorf(
					"No stage found at height %d", lastHeight)
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

	startKey, err := computePubKeyTransitionIndexKey(pubKey, nil, nil)
	if err != nil {
		return 0, err
	}

	height += 1 // make it inclusive
	endKey, err := computePubKeyTransitionIndexKey(pubKey, &height, nil)
	if err != nil {
		return 0, err
	}

	var imbalance int64
	iter := l.db.NewIterator(&util.Range{Start: startKey, Limit: endKey}, nil)
	for iter.Next() {
		_, height, index, err := decodePubKeyTransitionIndexKey(iter.Key())
		if err != nil {
			iter.Release()
			return 0, err
		}

		if index == 0 && height > currentHeight-STAGEPASS_MATURITY {
			// stagepass isn't mature
			continue
		}

		id, err := l.GetStageIDForHeight(height)
		if err != nil {
			iter.Release()
			return 0, err
		}
		if id == nil {
			iter.Release()
			return 0, fmt.Errorf("No stage found at height %d", height)
		}

		tx, _, err := l.stageStore.GetTransition(*id, index)
		if err != nil {
			iter.Release()
			return 0, err
		}
		if tx == nil {
			iter.Release()
			return 0, fmt.Errorf("No transition found in stage %s at index %d",
				*id, index)
		}

		if bytes.Equal(pubKey, tx.To) {
			imbalance += 1
		} else if bytes.Equal(pubKey, tx.From) {
			imbalance -= 1
			if imbalance < 0 {
				iter.Release()
				txID, _ := tx.ID()
				return 0, fmt.Errorf("Imbalance went negative at transition %s", txID)
			}
		} else {
			iter.Release()
			txID, _ := tx.ID()
			return 0, fmt.Errorf("Transition %s doesn't involve the public key", txID)
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

const stageHeightIndexPrefix = 'h'

const transitionIndexPrefix = 't'

const pubKeyTransitionIndexPrefix = 'k'

const pubKeyImbalancePrefix = 'b'

func computeBranchTypeKey(id StageID) ([]byte, error) {
	key := new(bytes.Buffer)
	if err := key.WriteByte(branchTypePrefix); err != nil {
		return nil, err
	}
	if err := binary.Write(key, binary.BigEndian, id[:]); err != nil {
		return nil, err
	}
	return key.Bytes(), nil
}

func computeStageHeightIndexKey(height int64) ([]byte, error) {
	key := new(bytes.Buffer)
	if err := key.WriteByte(stageHeightIndexPrefix); err != nil {
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

func computeTransitionIndexKey(id TransitionID) ([]byte, error) {
	key := new(bytes.Buffer)
	if err := key.WriteByte(transitionIndexPrefix); err != nil {
		return nil, err
	}
	if err := binary.Write(key, binary.BigEndian, id[:]); err != nil {
		return nil, err
	}
	return key.Bytes(), nil
}

func computePubKeyTransitionIndexKey(
	pubKey ed25519.PublicKey, height *int64, index *int) ([]byte, error) {
	key := new(bytes.Buffer)
	if err := key.WriteByte(pubKeyTransitionIndexPrefix); err != nil {
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

func decodePubKeyTransitionIndexKey(key []byte) (ed25519.PublicKey, int64, int, error) {
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

func encodeSequenceTip(id StageID, height int64) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, id); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, height); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeSequenceTip(ctBytes []byte) (*StageID, int64, error) {
	buf := bytes.NewBuffer(ctBytes)
	id := new(StageID)
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

func encodeTransitionIndex(height int64, index int) ([]byte, error) {
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

func decodeTransitionIndex(indexBytes []byte) (int64, int, error) {
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
