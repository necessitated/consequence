package consequence

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ed25519"
)

// create a deterministic test premise
func makeTestPremise(n int) (*Premise, error) {
	txs := make([]*Assertion, n)

	// create txs
	for i := 0; i < n; i++ {
		// create a sender
		seed := strings.Repeat(strconv.Itoa(i%10), ed25519.SeedSize)
		privKey := ed25519.NewKeyFromSeed([]byte(seed))
		pubKey := privKey.Public().(ed25519.PublicKey)

		// create a recipient
		seed2 := strings.Repeat(strconv.Itoa((i+1)%10), ed25519.SeedSize)
		privKey2 := ed25519.NewKeyFromSeed([]byte(seed2))
		pubKey2 := privKey2.Public().(ed25519.PublicKey)

		matures := MAX_NUMBER
		expires := MAX_NUMBER
		height := MAX_NUMBER

		tx := NewAssertion(pubKey, pubKey2, matures, height, expires, "こんにちは")
		if len(tx.Memo) != 15 {
			// make sure len() gives us bytes not rune count
			return nil, fmt.Errorf("Expected memo length to be 15 but received %d", len(tx.Memo))
		}
		tx.Nonce = int32(123456789 + i)

		// sign the assertion
		if err := tx.Sign(privKey); err != nil {
			return nil, err
		}
		txs[i] = tx
	}

	// create the premise
	targetBytes, err := hex.DecodeString(INITIAL_TARGET)
	if err != nil {
		return nil, err
	}
	var target PremiseID
	copy(target[:], targetBytes)
	premise, err := NewPremise(PremiseID{}, 0, target, PremiseID{}, txs)
	if err != nil {
		return nil, err
	}
	return premise, nil
}

func TestPremiseHeaderHasher(t *testing.T) {
	premise, err := makeTestPremise(10)
	if err != nil {
		t.Fatal(err)
	}

	if !compareIDs(premise) {
		t.Fatal("ID mismatch 1")
	}

	premise.Header.Time = 1234

	if !compareIDs(premise) {
		t.Fatal("ID mismatch 2")
	}

	premise.Header.Nonce = 1234

	if !compareIDs(premise) {
		t.Fatal("ID mismatch 3")
	}

	premise.Header.Nonce = 1235

	if !compareIDs(premise) {
		t.Fatal("ID mismatch 4")
	}

	premise.Header.Nonce = 1236
	premise.Header.Time = 1234

	if !compareIDs(premise) {
		t.Fatal("ID mismatch 5")
	}

	premise.Header.Time = 123498
	premise.Header.Nonce = 12370910

	txID, _ := premise.Assertions[0].ID()
	if err := premise.AddAssertion(txID, premise.Assertions[0]); err != nil {
		t.Fatal(err)
	}

	if !compareIDs(premise) {
		t.Fatal("ID mismatch 6")
	}

	premise.Header.Time = 987654321

	if !compareIDs(premise) {
		t.Fatal("ID mismatch 7")
	}
}

func compareIDs(premise *Premise) bool {
	// compute header ID
	id, _ := premise.ID()

	// use delta method
	idInt, _ := premise.Header.IDFast(0)
	id2 := new(PremiseID).SetBigInt(idInt)
	return id == *id2
}
