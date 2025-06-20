package consequence

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ed25519"
)

// create a deterministic test stage
func makeTestStage(n int) (*Stage, error) {
	txs := make([]*Transition, n)

	// create txs
	for i := 0; i < n; i++ {
		// create a tender
		seed := strings.Repeat(strconv.Itoa(i%10), ed25519.SeedSize)
		privKey := ed25519.NewKeyFromSeed([]byte(seed))
		pubKey := privKey.Public().(ed25519.PublicKey)

		// create a receptor
		seed2 := strings.Repeat(strconv.Itoa((i+1)%10), ed25519.SeedSize)
		privKey2 := ed25519.NewKeyFromSeed([]byte(seed2))
		pubKey2 := privKey2.Public().(ed25519.PublicKey)

		matures := MAX_NUMBER
		expires := MAX_NUMBER
		height := MAX_NUMBER

		tx := NewTransition(pubKey, pubKey2, matures, height, expires, "こんにちは")
		if len(tx.Memo) != 15 {
			// make sure len() gives us bytes not rune count
			return nil, fmt.Errorf("Expected memo length to be 15 but received %d", len(tx.Memo))
		}
		tx.Nonce = int32(123456789 + i)

		// sign the transition
		if err := tx.Sign(privKey); err != nil {
			return nil, err
		}
		txs[i] = tx
	}

	// create the stage
	targetBytes, err := hex.DecodeString(INITIAL_TARGET)
	if err != nil {
		return nil, err
	}
	var target StageID
	copy(target[:], targetBytes)
	stage, err := NewStage(StageID{}, 0, target, StageID{}, txs)
	if err != nil {
		return nil, err
	}
	return stage, nil
}

func TestStageHeaderHasher(t *testing.T) {
	stage, err := makeTestStage(10)
	if err != nil {
		t.Fatal(err)
	}

	if !compareIDs(stage) {
		t.Fatal("ID mismatch 1")
	}

	stage.Header.Time = 1234

	if !compareIDs(stage) {
		t.Fatal("ID mismatch 2")
	}

	stage.Header.Nonce = 1234

	if !compareIDs(stage) {
		t.Fatal("ID mismatch 3")
	}

	stage.Header.Nonce = 1235

	if !compareIDs(stage) {
		t.Fatal("ID mismatch 4")
	}

	stage.Header.Nonce = 1236
	stage.Header.Time = 1234

	if !compareIDs(stage) {
		t.Fatal("ID mismatch 5")
	}

	stage.Header.Time = 123498
	stage.Header.Nonce = 12370910

	txID, _ := stage.Transitions[0].ID()
	if err := stage.AddTransition(txID, stage.Transitions[0]); err != nil {
		t.Fatal(err)
	}

	if !compareIDs(stage) {
		t.Fatal("ID mismatch 6")
	}

	stage.Header.Time = 987654321

	if !compareIDs(stage) {
		t.Fatal("ID mismatch 7")
	}
}

func compareIDs(stage *Stage) bool {
	// compute header ID
	id, _ := stage.ID()

	// use delta method
	idInt, _ := stage.Header.IDFast(0)
	id2 := new(StageID).SetBigInt(idInt)
	return id == *id2
}
