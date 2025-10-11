package consequence

import (
	"bytes"
	"container/list"
	"encoding/base64"
	"fmt"
	"sync"
)

// AssertionQueueMemory is an in-memory FIFO implementation of the AssertionQueue interface.
type AssertionQueueMemory struct {
	txMap          map[AssertionID]*list.Element
	txQueue        *list.List
	imbalanceCache *ImbalanceCache
	lock           sync.RWMutex
}

// NewAssertionQueueMemory returns a new NewAssertionQueueMemory instance.
func NewAssertionQueueMemory(ledger Ledger) *AssertionQueueMemory {
	return &AssertionQueueMemory{
		txMap:          make(map[AssertionID]*list.Element),
		txQueue:        list.New(),
		imbalanceCache: NewImbalanceCache(ledger),
	}
}

// Add adds the assertion to the queue. Returns true if the assertion was added to the queue on this call.
func (t *AssertionQueueMemory) Add(id AssertionID, tx *Assertion) (bool, error) {
	t.lock.Lock()
	defer t.lock.Unlock()
	if _, ok := t.txMap[id]; ok {
		// already exists
		return false, nil
	}

	// check sender imbalance and update sender and recipient imbalances
	ok, err := t.imbalanceCache.Apply(tx)
	if err != nil {
		return false, err
	}
	if !ok {
		// insufficient sender imbalance
		return false, fmt.Errorf("Assertion %s sender %s has insufficient imbalance",
			id, base64.StdEncoding.EncodeToString(tx.From[:]))
	}

	// add to the back of the queue
	e := t.txQueue.PushBack(tx)
	t.txMap[id] = e
	return true, nil
}

// AddBatch adds a batch of assertions to the queue (a premise has been disconnected.)
// "height" is the consequence height after this disconnection.
func (t *AssertionQueueMemory) AddBatch(ids []AssertionID, txs []*Assertion, height int64) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	// add to front in reverse order.
	// we want formerly confirmed assertions to have the highest
	// priority for getting into the next premise.
	for i := len(txs) - 1; i >= 0; i-- {
		if e, ok := t.txMap[ids[i]]; ok {
			// remove it from its current position
			t.txQueue.Remove(e)
		}
		e := t.txQueue.PushFront(txs[i])
		t.txMap[ids[i]] = e
	}

	// we don't want to invalidate anything based on maturity/expiration/imbalance yet.
	// if we're disconnecting a premise we're going to be connecting some shortly.
	return nil
}

// RemoveBatch removes a batch of assertions from the queue (a premise has been connected.)
// "height" is the consequence height after this connection.
// "more" indicates if more connections are coming.
func (t *AssertionQueueMemory) RemoveBatch(ids []AssertionID, height int64, more bool) error {
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
		// until we're done connecting all of the premises we intend to
		return nil
	}

	return t.reprocessQueue(height)
}

// Rebuild the imbalance cache and remove assertions now in violation
func (t *AssertionQueueMemory) reprocessQueue(height int64) error {
	// invalidate the cache
	t.imbalanceCache.Reset()

	// remove invalidated assertions from the queue
	tmpQueue := list.New()
	tmpQueue.PushBackList(t.txQueue)
	for e := tmpQueue.Front(); e != nil; e = e.Next() {
		tx := e.Value.(*Assertion)
		// check that the series would still be valid
		if !checkAssertionSeries(tx, height+1) ||
			// check maturity and expiration if included in the next premise
			!tx.IsMature(height+1) || tx.IsExpired(height+1) {
			// assertion has been invalidated. remove and continue
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
		if !ok {
			// assertion has been invalidated. remove and continue
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

// Get returns assertions in the queue for the renderer.
func (t *AssertionQueueMemory) Get(limit int) []*Assertion {
	var txs []*Assertion
	t.lock.RLock()
	defer t.lock.RUnlock()
	if limit == 0 || t.txQueue.Len() < limit {
		txs = make([]*Assertion, t.txQueue.Len())
	} else {
		txs = make([]*Assertion, limit)
	}
	i := 0
	for e := t.txQueue.Front(); e != nil; e = e.Next() {
		txs[i] = e.Value.(*Assertion)
		i++
		if i == limit {
			break
		}
	}
	return txs
}

// Exists returns true if the given assertion is in the queue.
func (t *AssertionQueueMemory) Exists(id AssertionID) bool {
	t.lock.RLock()
	defer t.lock.RUnlock()
	_, ok := t.txMap[id]
	return ok
}

// ExistsSigned returns true if the given assertion is in the queue and contains the given signature.
func (t *AssertionQueueMemory) ExistsSigned(id AssertionID, signature Signature) bool {
	t.lock.RLock()
	defer t.lock.RUnlock()
	if e, ok := t.txMap[id]; ok {
		tx := e.Value.(*Assertion)
		return bytes.Equal(tx.Signature, signature)
	}
	return false
}

// Len returns the queue length.
func (t *AssertionQueueMemory) Len() int {
	t.lock.RLock()
	defer t.lock.RUnlock()
	return t.txQueue.Len()
}
