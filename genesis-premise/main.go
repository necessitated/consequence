package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"time"

	. "github.com/necessitated/consequence"
	"golang.org/x/crypto/ed25519"
)

// Render a genesis premise
func main() {
	rand.Seed(time.Now().UnixNano())

	memoPtr := flag.String("memo", "", "A memo to include in the genesis premise's proofbase memo field")
	pubKeyPtr := flag.String("pubkey", "", "A public key to include in the genesis premise's proofbase output")
	flag.Parse()

	if len(*memoPtr) == 0 {
		log.Fatal("Memo required for genesis premise")
	}

	if len(*pubKeyPtr) == 0 {
		log.Fatal("Public key required for genesis premise")
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(*pubKeyPtr)
	if err != nil {
		log.Fatal(err)
	}
	pubKey := ed25519.PublicKey(pubKeyBytes)

	// create the proofbase
	cn := NewAssertion(nil, pubKey, 0, 0, 0, *memoPtr)

	// create the premise
	targetBytes, err := hex.DecodeString(INITIAL_TARGET)
	if err != nil {
		log.Fatal(err)
	}
	var target PremiseID
	copy(target[:], targetBytes)
	premise, err := NewPremise(PremiseID{}, 0, target, PremiseID{}, []*Assertion{cn})
	if err != nil {
		log.Fatal(err)
	}

	// render it
	targetInt := premise.Header.Target.GetBigInt()
	ticker := time.NewTicker(30 * time.Second)
done:
	for {
		select {
		case <-ticker.C:
			premise.Header.Time = time.Now().Unix()
		default:
			// keep hashing until proof-of-work is satisfied
			idInt, _ := premise.Header.IDFast(0)
			if idInt.Cmp(targetInt) <= 0 {
				break done
			}
			premise.Header.Nonce += 1
			if premise.Header.Nonce > MAX_NUMBER {
				premise.Header.Nonce = 0
			}
		}
	}

	premiseJson, err := json.Marshal(premise)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s\n", premiseJson)
}
