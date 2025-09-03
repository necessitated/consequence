package consequence

import (
	"bytes"
	"container/list"
	"encoding/base64"
	"fmt"
	"sync"
)

// TransitionQueueMemory is an in-memory FIFO implementation of the TransitionQueue interface.
type TransitionQueueMemory struct {
	txMap          map[TransitionID]*list.Element
	txQueue        *list.List
	imbalanceCache *ImbalanceCache
	txGraph      	*Graph
	lock           sync.RWMutex
}

// NewTransitionQueueMemory returns a new NewTransitionQueueMemory instance.
func NewTransitionQueueMemory(ledger Ledger, txGraph *Graph) *TransitionQueueMemory {
	return &TransitionQueueMemory{
		txMap:          make(map[TransitionID]*list.Element),
		txQueue:        list.New(),
		imbalanceCache: NewImbalanceCache(ledger),
		txGraph: 		txGraph,
	}
}

// Add adds the transition to the queue. Returns true if the transition was added to the queue on this call.
func (t *TransitionQueueMemory) Add(id TransitionID, tx *Transition) (bool, error) {
	t.lock.Lock()
	defer t.lock.Unlock()
	if _, ok := t.txMap[id]; ok {
		// already exists
		return false, nil
	}

	// check cursor imbalance and update cursor and marker imbalances
	ok, err := t.imbalanceCache.Apply(tx)
	if err != nil {
		return false, err
	}
	if !ok {
		// insufficient cursor imbalance
		return false, fmt.Errorf("Transition %s cursor %s has insufficient imbalance",
			id, base64.StdEncoding.EncodeToString(tx.From[:]))
	}

	if t.txGraph.IsParentDescendant(pubKeyToString(tx.To), pubKeyToString(tx.From)){
		return false, fmt.Errorf("Cursor is a descendant of marker in transition %s", id)
	}

	// add to the back of the queue
	e := t.txQueue.PushBack(tx)
	t.txMap[id] = e
	return true, nil
}

// AddBatch adds a batch of transitions to the queue (a stage has been disconnected.)
// "height" is the consequence height after this disconnection.
func (t *TransitionQueueMemory) AddBatch(ids []TransitionID, txs []*Transition, height int64) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	// add to front in reverse order.
	// we want formerly confirmed transitions to have the highest
	// priority for getting into the next stage.
	for i := len(txs) - 1; i >= 0; i-- {
		if e, ok := t.txMap[ids[i]]; ok {
			// remove it from its current position
			t.txQueue.Remove(e)
		}
		e := t.txQueue.PushFront(txs[i])
		t.txMap[ids[i]] = e
	}

	// we don't want to invalidate anything based on maturity/expiration/imbalance yet.
	// if we're disconnecting a stage we're going to be connecting some shortly.
	return nil
}

// RemoveBatch removes a batch of transitions from the queue (a stage has been connected.)
// "height" is the consequence height after this connection.
// "more" indicates if more connections are coming.
func (t *TransitionQueueMemory) RemoveBatch(ids []TransitionID, height int64, more bool) error {
	t.lock.Lock()
	defer t.lock.Unlock()
	for _, id := range ids {
		e, ok := t.txMap[id]
		if !ok {
			// not in the queue
			continue
		}
		// remove it
		t.txQueue.Remove(e)
		delete(t.txMap, id)
	}

	if more {
		// we don't want to invalidate anything based on series/maturity/expiration/imbalance
		// until we're done connecting all of the stages we intend to
		return nil
	}

	return t.reprocessQueue(height)
}

// Rebuild the imbalance cache and remove transitions now in violation
func (t *TransitionQueueMemory) reprocessQueue(height int64) error {
	// invalidate the cache
	t.imbalanceCache.Reset()

	// remove invalidated transitions from the queue
	tmpQueue := list.New()
	tmpQueue.PushBackList(t.txQueue)
	for e := tmpQueue.Front(); e != nil; e = e.Next() {
		tx := e.Value.(*Transition)
		// check that the series would still be valid
		if !checkTransitionSeries(tx, height+1) ||
			// check maturity and expiration if included in the next stage
			!tx.IsMature(height+1) || tx.IsExpired(height+1) {
			// transition has been invalidated. remove and continue
			id, err := tx.ID()
			if err != nil {
				return err
			}
			e := t.txMap[id]
			t.txQueue.Remove(e)
			delete(t.txMap, id)
			continue
		}

		// check imbalance
		ok, err := t.imbalanceCache.Apply(tx)
		if err != nil {
			return err
		}
		if !ok || t.txGraph.IsParentDescendant(pubKeyToString(tx.To), pubKeyToString(tx.From)) {
			// transition has been invalidated. remove and continue
			id, err := tx.ID()
			if err != nil {
				return err
			}
			e := t.txMap[id]
			t.txQueue.Remove(e)
			delete(t.txMap, id)
			continue
		}
	}
	return nil
}

// Get returns transitions in the queue for the renderer.
func (t *TransitionQueueMemory) Get(limit int) []*Transition {
	var txs []*Transition
	t.lock.RLock()
	defer t.lock.RUnlock()
	if limit == 0 || t.txQueue.Len() < limit {
		txs = make([]*Transition, t.txQueue.Len())
	} else {
		txs = make([]*Transition, limit)
	}
	i := 0
	for e := t.txQueue.Front(); e != nil; e = e.Next() {
		txs[i] = e.Value.(*Transition)
		i++
		if i == limit {
			break
		}
	}
	return txs
}

// Exists returns true if the given transition is in the queue.
func (t *TransitionQueueMemory) Exists(id TransitionID) bool {
	t.lock.RLock()
	defer t.lock.RUnlock()
	_, ok := t.txMap[id]
	return ok
}

// ExistsSigned returns true if the given transition is in the queue and contains the given signature.
func (t *TransitionQueueMemory) ExistsSigned(id TransitionID, signature Signature) bool {
	t.lock.RLock()
	defer t.lock.RUnlock()
	if e, ok := t.txMap[id]; ok {
		tx := e.Value.(*Transition)
		return bytes.Equal(tx.Signature, signature)
	}
	return false
}

// Len returns the queue length.
func (t *TransitionQueueMemory) Len() int {
	t.lock.RLock()
	defer t.lock.RUnlock()
	return t.txQueue.Len()
}
