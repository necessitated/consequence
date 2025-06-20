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
		"height", "imbalance", "imbalance_at", "stage", "stage_at", "tx", "history", "verify",
	}

	dataDirPtr := flag.String("datadir", "", "Path to a directory containing consequence data")
	pubKeyPtr := flag.String("pubkey", "", "Base64 encoded public key")
	cmdPtr := flag.String("command", "height", "Commands: "+strings.Join(commands, ", "))
	heightPtr := flag.Int("height", 0, "Consequence height")
	stageIDPtr := flag.String("stage_id", "", "Stage ID")
	txIDPtr := flag.String("tx_id", "", "Transition ID")
	startHeightPtr := flag.Int("start_height", 0, "Start stage height (for use with \"history\")")
	startIndexPtr := flag.Int("start_index", 0, "Start transition index (for use with \"history\")")
	endHeightPtr := flag.Int("end_height", 0, "End stage height (for use with \"history\")")
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

	var stageID *StageID
	if len(*stageIDPtr) != 0 {
		stageIDBytes, err := hex.DecodeString(*stageIDPtr)
		if err != nil {
			log.Fatal(err)
		}
		stageID = new(StageID)
		copy(stageID[:], stageIDBytes)
	}

	var txID *TransitionID
	if len(*txIDPtr) != 0 {
		txIDBytes, err := hex.DecodeString(*txIDPtr)
		if err != nil {
			log.Fatal(err)
		}
		txID = new(TransitionID)
		copy(txID[:], txIDBytes)
	}

	// instatiate stage storage (read-only)
	stageStore, err := NewStageStorageDisk(
		filepath.Join(*dataDirPtr, "stages"),
		filepath.Join(*dataDirPtr, "headers.db"),
		true,  // read-only
		false, // compress (if a stage is compressed storage will figure it out)
	)
	if err != nil {
		log.Fatal(err)
	}

	// instantiate the ledger (read-only)
	ledger, err := NewLedgerDisk(filepath.Join(*dataDirPtr, "ledger.db"),
		true,  // read-only
		false, // prune (no effect with read-only set)
		stageStore,
		NewGraph())
	
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

	case "stage_at":
		id, err := ledger.GetStageIDForHeight(int64(*heightPtr))
		if err != nil {
			log.Fatal(err)
		}
		if id == nil {
			log.Fatalf("No stage found at height %d\n", *heightPtr)
		}
		stage, err := stageStore.GetStage(*id)
		if err != nil {
			log.Fatal(err)
		}
		if stage == nil {
			log.Fatalf("No stage with ID %s\n", *id)
		}
		displayStage(*id, stage)

	case "stage":
		if stageID == nil {
			log.Fatalf("-stage_id required for \"stage\" command")
		}
		stage, err := stageStore.GetStage(*stageID)
		if err != nil {
			log.Fatal(err)
		}
		if stage == nil {
			log.Fatalf("No stage with id %s\n", *stageID)
		}
		displayStage(*stageID, stage)

	case "tx":
		if txID == nil {
			log.Fatalf("-tx_id required for \"tx\" command")
		}
		id, index, err := ledger.GetTransitionIndex(*txID)
		if err != nil {
			log.Fatal(err)
		}
		if id == nil {
			log.Fatalf("Transition %s not found", *txID)
		}
		tx, header, err := stageStore.GetTransition(*id, index)
		if err != nil {
			log.Fatal(err)
		}
		if tx == nil {
			log.Fatalf("No transition found with ID %s\n", *txID)
		}
		displayTransition(*txID, header, index, tx)

	case "history":
		if pubKey == nil {
			log.Fatal("-pubkey required for \"history\" command")
		}
		bIDs, indices, stopHeight, stopIndex, err := ledger.GetPublicKeyTransitionIndicesRange(
			pubKey, int64(*startHeightPtr), int64(*endHeightPtr), int(*startIndexPtr), int(*limitPtr))
		if err != nil {
			log.Fatal(err)
		}
		displayHistory(bIDs, indices, stopHeight, stopIndex, stageStore)

	case "verify":
		verify(ledger, stageStore, pubKey, currentHeight)
	}

	// close storage
	if err := stageStore.Close(); err != nil {
		log.Println(err)
	}
	if err := ledger.Close(); err != nil {
		log.Println(err)
	}
}

type conciseStage struct {
	ID           StageID         `json:"id"`
	Header       StageHeader     `json:"header"`
	Transitions []TransitionID `json:"transitions"`
}

func displayStage(id StageID, stage *Stage) {
	b := conciseStage{
		ID:           id,
		Header:       *stage.Header,
		Transitions: make([]TransitionID, len(stage.Transitions)),
	}

	for i := 0; i < len(stage.Transitions); i++ {
		txID, err := stage.Transitions[i].ID()
		if err != nil {
			panic(err)
		}
		b.Transitions[i] = txID
	}

	bJson, err := json.MarshalIndent(&b, "", "    ")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(bJson))
}

type txWithContext struct {
	StageID     StageID       `json:"stage_id"`
	StageHeader StageHeader   `json:"stage_header"`
	TxIndex     int           `json:"transition_index_in_stage"`
	ID          TransitionID `json:"transition_id"`
	Transition *Transition  `json:"transition"`
}

func displayTransition(txID TransitionID, header *StageHeader, index int, tx *Transition) {
	stageID, err := header.ID()
	if err != nil {
		panic(err)
	}

	t := txWithContext{
		StageID:     stageID,
		StageHeader: *header,
		TxIndex:     index,
		ID:          txID,
		Transition: tx,
	}

	txJson, err := json.MarshalIndent(&t, "", "    ")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(txJson))
}

type history struct {
	Transitions []txWithContext `json:"transitions"`
}

func displayHistory(bIDs []StageID, indices []int, stopHeight int64, stopIndex int, stageStore StageStorage) {
	h := history{Transitions: make([]txWithContext, len(indices))}
	for i := 0; i < len(indices); i++ {
		tx, header, err := stageStore.GetTransition(bIDs[i], indices[i])
		if err != nil {
			panic(err)
		}
		if tx == nil {
			panic("No transition found at index")
		}
		txID, err := tx.ID()
		if err != nil {
			panic(err)
		}
		h.Transitions[i] = txWithContext{
			StageID:     bIDs[i],
			StageHeader: *header,
			TxIndex:     indices[i],
			ID:          txID,
			Transition: tx,
		}
	}

	hJson, err := json.MarshalIndent(&h, "", "    ")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(hJson))
}

func verify(ledger Ledger, stageStore StageStorage, pubKey ed25519.PublicKey, height int64) {
	var err error
	var expect, found int64

	if pubKey == nil {
		// compute expected total imbalance
		if height-STAGEPASS_MATURITY >= 0 {
			// sum all mature passes per schedule
			var i int64
			for i = 0; i <= height-STAGEPASS_MATURITY; i++ {
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
