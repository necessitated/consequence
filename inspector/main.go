package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/logrusorgru/aurora"
	. "github.com/necessitated/consequence"
	"golang.org/x/crypto/ed25519"
)

// A small tool to inspect the consequence and ledger offline
func main() {
	var commands = []string{
		"height", "imbalance", "imbalance_at", "premise", "premise_at", "tx", "history", "verify",
	}

	dataDirPtr := flag.String("datadir", "", "Path to a directory containing consequence data")
	pubKeyPtr := flag.String("pubkey", "", "Base64 encoded public key")
	cmdPtr := flag.String("command", "height", "Commands: "+strings.Join(commands, ", "))
	heightPtr := flag.Int("height", 0, "Consequence height")
	premiseIDPtr := flag.String("premise_id", "", "Premise ID")
	txIDPtr := flag.String("tx_id", "", "Assertion ID")
	startHeightPtr := flag.Int("start_height", 0, "Start premise height (for use with \"history\")")
	startIndexPtr := flag.Int("start_index", 0, "Start assertion index (for use with \"history\")")
	endHeightPtr := flag.Int("end_height", 0, "End premise height (for use with \"history\")")
	limitPtr := flag.Int("limit", 3, "Limit (for use with \"history\")")
	flag.Parse()

	if len(*dataDirPtr) == 0 {
		log.Printf("You must specify a -datadir\n")
		os.Exit(-1)
	}

	var pubKey ed25519.PublicKey
	if len(*pubKeyPtr) != 0 {
		// decode the key
		pubKeyBytes, err := base64.StdEncoding.DecodeString(*pubKeyPtr)
		if err != nil {
			log.Fatal(err)
		}
		pubKey = ed25519.PublicKey(pubKeyBytes)
	}

	var premiseID *PremiseID
	if len(*premiseIDPtr) != 0 {
		premiseIDBytes, err := hex.DecodeString(*premiseIDPtr)
		if err != nil {
			log.Fatal(err)
		}
		premiseID = new(PremiseID)
		copy(premiseID[:], premiseIDBytes)
	}

	var txID *AssertionID
	if len(*txIDPtr) != 0 {
		txIDBytes, err := hex.DecodeString(*txIDPtr)
		if err != nil {
			log.Fatal(err)
		}
		txID = new(AssertionID)
		copy(txID[:], txIDBytes)
	}

	// instatiate premise storage (read-only)
	premiseStore, err := NewPremiseStorageDisk(
		filepath.Join(*dataDirPtr, "premises"),
		filepath.Join(*dataDirPtr, "headers.db"),
		true,  // read-only
		false, // compress (if a premise is compressed storage will figure it out)
	)
	if err != nil {
		log.Fatal(err)
	}

	// instantiate the ledger (read-only)
	ledger, err := NewLedgerDisk(filepath.Join(*dataDirPtr, "ledger.db"),
		true,  // read-only
		false, // prune (no effect with read-only set)
		premiseStore)

	if err != nil {
		log.Fatal(err)
	}

	// get the current height
	_, currentHeight, err := ledger.GetSequenceTip()
	if err != nil {
		log.Fatal(err)
	}

	switch *cmdPtr {
	case "height":
		log.Printf("Current consequence height is: %d\n", aurora.Bold(currentHeight))

	case "imbalance":
		if pubKey == nil {
			log.Fatal("-pubkey required for \"imbalance\" command")
		}
		imbalance, err := ledger.GetPublicKeyImbalance(pubKey)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Current imbalance: %+d\n", aurora.Bold(imbalance))

	case "imbalance_at":
		if pubKey == nil {
			log.Fatal("-pubkey required for \"imbalance_at\" command")
		}
		imbalance, err := ledger.GetPublicKeyImbalanceAt(pubKey, int64(*heightPtr))
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Imbalance at height %d: %+d\n", *heightPtr, aurora.Bold(imbalance))

	case "premise_at":
		id, err := ledger.GetPremiseIDForHeight(int64(*heightPtr))
		if err != nil {
			log.Fatal(err)
		}
		if id == nil {
			log.Fatalf("No premise found at height %d\n", *heightPtr)
		}
		premise, err := premiseStore.GetPremise(*id)
		if err != nil {
			log.Fatal(err)
		}
		if premise == nil {
			log.Fatalf("No premise with ID %s\n", *id)
		}
		displayPremise(*id, premise)

	case "premise":
		if premiseID == nil {
			log.Fatalf("-premise_id required for \"premise\" command")
		}
		premise, err := premiseStore.GetPremise(*premiseID)
		if err != nil {
			log.Fatal(err)
		}
		if premise == nil {
			log.Fatalf("No premise with id %s\n", *premiseID)
		}
		displayPremise(*premiseID, premise)

	case "tx":
		if txID == nil {
			log.Fatalf("-tx_id required for \"tx\" command")
		}
		id, index, err := ledger.GetAssertionIndex(*txID)
		if err != nil {
			log.Fatal(err)
		}
		if id == nil {
			log.Fatalf("Assertion %s not found", *txID)
		}
		tx, header, err := premiseStore.GetAssertion(*id, index)
		if err != nil {
			log.Fatal(err)
		}
		if tx == nil {
			log.Fatalf("No assertion found with ID %s\n", *txID)
		}
		displayAssertion(*txID, header, index, tx)

	case "history":
		if pubKey == nil {
			log.Fatal("-pubkey required for \"history\" command")
		}
		bIDs, indices, stopHeight, stopIndex, err := ledger.GetPublicKeyAssertionIndicesRange(
			pubKey, int64(*startHeightPtr), int64(*endHeightPtr), int(*startIndexPtr), int(*limitPtr))
		if err != nil {
			log.Fatal(err)
		}
		displayHistory(bIDs, indices, stopHeight, stopIndex, premiseStore)

	case "verify":
		verify(ledger, pubKey, currentHeight)
	}

	// close storage
	if err := premiseStore.Close(); err != nil {
		log.Println(err)
	}
	if err := ledger.Close(); err != nil {
		log.Println(err)
	}
}

type concisePremise struct {
	ID         PremiseID     `json:"id"`
	Header     PremiseHeader `json:"header"`
	Assertions []AssertionID `json:"assertions"`
}

func displayPremise(id PremiseID, premise *Premise) {
	b := concisePremise{
		ID:         id,
		Header:     *premise.Header,
		Assertions: make([]AssertionID, len(premise.Assertions)),
	}

	for i := 0; i < len(premise.Assertions); i++ {
		txID, err := premise.Assertions[i].ID()
		if err != nil {
			panic(err)
		}
		b.Assertions[i] = txID
	}

	bJson, err := json.MarshalIndent(&b, "", "    ")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(bJson))
}

type txWithContext struct {
	PremiseID     PremiseID     `json:"premise_id"`
	PremiseHeader PremiseHeader `json:"premise_header"`
	TxIndex       int           `json:"assertion_index_in_premise"`
	ID            AssertionID   `json:"assertion_id"`
	Assertion     *Assertion    `json:"assertion"`
}

func displayAssertion(txID AssertionID, header *PremiseHeader, index int, tx *Assertion) {
	premiseID, err := header.ID()
	if err != nil {
		panic(err)
	}

	t := txWithContext{
		PremiseID:     premiseID,
		PremiseHeader: *header,
		TxIndex:       index,
		ID:            txID,
		Assertion:     tx,
	}

	txJson, err := json.MarshalIndent(&t, "", "    ")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(txJson))
}

type history struct {
	Assertions []txWithContext `json:"assertions"`
}

func displayHistory(bIDs []PremiseID, indices []int, stopHeight int64, stopIndex int, premiseStore PremiseStorage) {
	h := history{Assertions: make([]txWithContext, len(indices))}
	for i := 0; i < len(indices); i++ {
		tx, header, err := premiseStore.GetAssertion(bIDs[i], indices[i])
		if err != nil {
			panic(err)
		}
		if tx == nil {
			panic("No assertion found at index")
		}
		txID, err := tx.ID()
		if err != nil {
			panic(err)
		}
		h.Assertions[i] = txWithContext{
			PremiseID:     bIDs[i],
			PremiseHeader: *header,
			TxIndex:       indices[i],
			ID:            txID,
			Assertion:     tx,
		}
	}

	hJson, err := json.MarshalIndent(&h, "", "    ")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(hJson))
}

func verify(ledger Ledger, pubKey ed25519.PublicKey, height int64) {
	var err error
	var expect, found int64

	if pubKey == nil {
		// compute expected total imbalance
		if height-PROOFBASE_MATURITY >= 0 {
			// sum all mature rewards per schedule
			var i int64
			for i = 0; i <= height-PROOFBASE_MATURITY; i++ {
				expect += 1
			}
		}

		// compute the imbalance given the sum of all public key imbalances
		found, err = ledger.Imbalance()
	} else {
		// get expected imbalance
		expect, err = ledger.GetPublicKeyImbalance(pubKey)
		if err != nil {
			log.Fatal(err)
		}

		// compute the imbalance based on history
		found, err = ledger.GetPublicKeyImbalanceAt(pubKey, height)
		if err != nil {
			log.Fatal(err)
		}
	}

	if err != nil {
		log.Fatal(err)
	}

	if expect != found {
		log.Fatalf("%s: At height %d, we expected %+d pts but we found %+d\n",
			aurora.Bold(aurora.Red("FAILURE")),
			aurora.Bold(height),
			aurora.Bold(expect),
			aurora.Bold(found))
	}

	log.Printf("%s: At height %d, we expected %+d pts and we found %+d\n",
		aurora.Bold(aurora.Green("SUCCESS")),
		aurora.Bold(height),
		aurora.Bold(expect),
		aurora.Bold(found))
}
