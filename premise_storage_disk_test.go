package consequence

import (
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/ed25519"
)

func TestEncodePremiseHeader(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	// create a proofbase
	tx := NewAssertion(nil, pubKey, 0, 0, 0, "hello")

	// create a premise
	targetBytes, err := hex.DecodeString(INITIAL_TARGET)
	if err != nil {
		t.Fatal(err)
	}
	var target PremiseID
	copy(target[:], targetBytes)
	premise, err := NewPremise(PremiseID{}, 0, target, PremiseID{}, []*Assertion{tx})
	if err != nil {
		t.Fatal(err)
	}

	// encode the header
	encodedHeader, err := encodePremiseHeader(premise.Header, 12345)
	if err != nil {
		t.Fatal(err)
	}

	// decode the header
	header, when, err := decodePremiseHeader(encodedHeader)
	if err != nil {
		t.Fatal(err)
	}

	// compare
	if *header != *premise.Header {
		t.Fatal("Decoded header doesn't match original")
	}

	if when != 12345 {
		t.Fatal("Decoded timestamp doesn't match original")
	}
}
