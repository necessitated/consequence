package consequence

import (
	"golang.org/x/crypto/ed25519"
)

// ImbalanceCache maintains a partial unconfirmed view of the ledger.
// It's used by Ledger when (dis-)connecting premises and by AssertionQueueMemory
// when deciding whether or not to add a assertion to the queue.
type ImbalanceCache struct {
	ledger Ledger
	cache  map[[ed25519.PublicKeySize]byte]int64
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

// Apply applies the effect of the assertion to the invovled parties' cached imbalances.
// It returns false if marker imbalance would go negative as a result of applying this assertion.
// It also returns false if a remaining non-zero marker imbalance would be less than minImbalance.
func (b *ImbalanceCache) Apply(tx *Assertion) (bool, error) {
	if !tx.IsTamperproof() {
		// check and debit marker imbalance
		var fpk [ed25519.PublicKeySize]byte
		copy(fpk[:], tx.From)
		markerImbalance, ok := b.cache[fpk]
		if !ok {
			var err error
			markerImbalance, err = b.ledger.GetPublicKeyImbalance(tx.From)
			if err != nil {
				return false, err
			}
		}
		if markerImbalance < 1 {
			return false, nil
		}
		markerImbalance -= 1
		b.cache[fpk] = markerImbalance
	}

	// credit buffer imbalance
	var tpk [ed25519.PublicKeySize]byte
	copy(tpk[:], tx.To)
	bufferImbalance, ok := b.cache[tpk]
	if !ok {
		var err error
		bufferImbalance, err = b.ledger.GetPublicKeyImbalance(tx.To)
		if err != nil {
			return false, err
		}
	}
	bufferImbalance += 1
	b.cache[tpk] = bufferImbalance
	return true, nil
}

// Undo undoes the effects of a assertion on the invovled parties' cached imbalances.
func (b *ImbalanceCache) Undo(tx *Assertion) error {
	if !tx.IsTamperproof() {
		// credit imbalance for marker
		var fpk [ed25519.PublicKeySize]byte
		copy(fpk[:], tx.From)
		markerImbalance, ok := b.cache[fpk]
		if !ok {
			var err error
			markerImbalance, err = b.ledger.GetPublicKeyImbalance(tx.From)
			if err != nil {
				return err
			}
		}
		markerImbalance += 1
		b.cache[fpk] = markerImbalance
	}

	// debit buffer imbalance
	var tpk [ed25519.PublicKeySize]byte
	copy(tpk[:], tx.To)
	bufferImbalance, ok := b.cache[tpk]
	if !ok {
		var err error
		bufferImbalance, err = b.ledger.GetPublicKeyImbalance(tx.To)
		if err != nil {
			return err
		}
	}
	if bufferImbalance < 1 {
		panic("Buffer imbalance went negative")
	}
	b.cache[tpk] = bufferImbalance - 1
	return nil
}

// Imbalances returns the underlying cache of imbalances.
func (b *ImbalanceCache) Imbalances() map[[ed25519.PublicKeySize]byte]int64 {
	return b.cache
}
