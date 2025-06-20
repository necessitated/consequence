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

// Render a genesis stage
func main() {
	rand.Seed(time.Now().UnixNano())

	memoPtr := flag.String("memo", "", "A memo to include in the genesis stage's stagepass memo field")
	pubKeyPtr := flag.String("pubkey", "", "A public key to include in the genesis stage's stagepass output")
	flag.Parse()

	if len(*memoPtr) == 0 {
		log.Fatal("Memo required for genesis stage")
	}

	if len(*pubKeyPtr) == 0 {
		log.Fatal("Public key required for genesis stage")
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(*pubKeyPtr)
	if err != nil {
		log.Fatal(err)
	}
	pubKey := ed25519.PublicKey(pubKeyBytes)

	// create the stagepass
	cn := NewTransition(nil, pubKey, 0, 0, 0, *memoPtr)

	// create the stage
	targetBytes, err := hex.DecodeString(INITIAL_TARGET)
	if err != nil {
		log.Fatal(err)
	}
	var target StageID
	copy(target[:], targetBytes)
	stage, err := NewStage(StageID{}, 0, target, StageID{}, []*Transition{cn})
	if err != nil {
		log.Fatal(err)
	}

	// render it
	targetInt := stage.Header.Target.GetBigInt()
	ticker := time.NewTicker(30 * time.Second)
done:
	for {
		select {
		case <-ticker.C:
			stage.Header.Time = time.Now().Unix()
		default:
			// keep hashing until proof-of-work is satisfied
			idInt, _ := stage.Header.IDFast(0)
			if idInt.Cmp(targetInt) <= 0 {
				break done
			}
			stage.Header.Nonce += 1
			if stage.Header.Nonce > MAX_NUMBER {
				stage.Header.Nonce = 0
			}
		}
	}

	stageJson, err := json.Marshal(stage)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s\n", stageJson)
}
