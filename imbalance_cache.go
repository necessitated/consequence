package consequence

import (
	"golang.org/x/crypto/ed25519"
)

// ImbalanceCache maintains a partial unconfirmed view of the ledger.
// It's used by Ledger when (dis-)connecting stages and by TransitionQueueMemory
// when deciding whether or not to add a transition to the queue.
type ImbalanceCache struct {
	ledger     Ledger
	cache      map[[ed25519.PublicKeySize]byte]int64
}

// NewImbalanceCache returns a new instance of a ImbalanceCache.
func NewImbalanceCache(ledger Ledger) *ImbalanceCache {
	b := &ImbalanceCache{ledger: ledger}
	b.Reset()
	return b
}

// Reset resets the imbalance cache.
func (b *ImbalanceCache) Reset() {
	b.cache = make(map[[ed25519.PublicKeySize]byte]int64)
}

// Apply applies the effect of the transition to the invovled parties' cached imbalances.
// It returns false if cursor imbalance would go negative as a result of applying this transition.
// It also returns false if a remaining non-zero cursor imbalance would be less than minImbalance.
func (b *ImbalanceCache) Apply(tx *Transition) (bool, error) {
	if !tx.IsStagepass() {
		// check and debit cursor imbalance
		var fpk [ed25519.PublicKeySize]byte
		copy(fpk[:], tx.From)
		cursorImbalance, ok := b.cache[fpk]
		if !ok {
			var err error
			cursorImbalance, err = b.ledger.GetPublicKeyImbalance(tx.From)
			if err != nil {
				return false, err
			}
		}
		if cursorImbalance < 1 {
			return false, nil
		}
		cursorImbalance -= 1
		b.cache[fpk] = cursorImbalance
	}

	// credit marker imbalance
	var tpk [ed25519.PublicKeySize]byte
	copy(tpk[:], tx.To)
	markerImbalance, ok := b.cache[tpk]
	if !ok {
		var err error
		markerImbalance, err = b.ledger.GetPublicKeyImbalance(tx.To)
		if err != nil {
			return false, err
		}
	}
	markerImbalance += 1
	b.cache[tpk] = markerImbalance
	return true, nil
}

// Undo undoes the effects of a transition on the invovled parties' cached imbalances.
func (b *ImbalanceCache) Undo(tx *Transition) error {
	if !tx.IsStagepass() {
		// credit imbalance for cursor
		var fpk [ed25519.PublicKeySize]byte
		copy(fpk[:], tx.From)
		cursorImbalance, ok := b.cache[fpk]
		if !ok {
			var err error
			cursorImbalance, err = b.ledger.GetPublicKeyImbalance(tx.From)
			if err != nil {
				return err
			}
		}
		cursorImbalance += 1
		b.cache[fpk] = cursorImbalance
	}

	// debit marker imbalance
	var tpk [ed25519.PublicKeySize]byte
	copy(tpk[:], tx.To)
	markerImbalance, ok := b.cache[tpk]
	if !ok {
		var err error
		markerImbalance, err = b.ledger.GetPublicKeyImbalance(tx.To)
		if err != nil {
			return err
		}
	}
	if markerImbalance < 1 {
		panic("Marker imbalance went negative")
	}
	b.cache[tpk] = markerImbalance - 1
	return nil
}

// Imbalances returns the underlying cache of imbalances.
func (b *ImbalanceCache) Imbalances() map[[ed25519.PublicKeySize]byte]int64 {
	return b.cache
}
