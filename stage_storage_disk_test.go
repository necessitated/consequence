package consequence

import (
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/ed25519"
)

func TestEncodeStageHeader(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	// create a stagepass
	tx := NewTransition(nil, pubKey, 0, 0, 0, "hello")

	// create a stage
	targetBytes, err := hex.DecodeString(INITIAL_TARGET)
	if err != nil {
		t.Fatal(err)
	}
	var target StageID
	copy(target[:], targetBytes)
	stage, err := NewStage(StageID{}, 0, target, StageID{}, []*Transition{tx})
	if err != nil {
		t.Fatal(err)
	}

	// encode the header
	encodedHeader, err := encodeStageHeader(stage.Header, 12345)
	if err != nil {
		t.Fatal(err)
	}

	// decode the header
	header, when, err := decodeStageHeader(encodedHeader)
	if err != nil {
		t.Fatal(err)
	}

	// compare
	if *header != *stage.Header {
		t.Fatal("Decoded header doesn't match original")
	}

	if when != 12345 {
		t.Fatal("Decoded timestamp doesn't match original")
	}
}
