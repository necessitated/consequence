package consequence

import (
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	olc "github.com/google/open-location-code/go"
)

type KeyState struct {
	namespace string
	label     string
	memo      string
	revision  uint
	time      int64
}

type Indexer struct {
	premiseStore    PremiseStorage
	ledger          Ledger
	processor       *Processor
	latestPremiseID PremiseID
	latestHeight    int64
	keyState        map[string]*KeyState
	namespaces      map[string]*KeyState
	dirGraph        *Graph
	shutdownChan    chan struct{}
	wg              sync.WaitGroup
}

func NewIndexer(
	premiseStore PremiseStorage,
	ledger Ledger,
	processor *Processor,
	genesisPremiseID PremiseID,
) *Indexer {
	return &Indexer{
		premiseStore:    premiseStore,
		ledger:          ledger,
		processor:       processor,
		latestPremiseID: genesisPremiseID,
		latestHeight:    0,
		keyState:        make(map[string]*KeyState),
		namespaces:      make(map[string]*KeyState),
		dirGraph:        NewGraph(),
		shutdownChan:    make(chan struct{}),
	}
}

// Run executes the indexer's main loop in its own goroutine.
func (idx *Indexer) Run() {
	idx.wg.Add(1)
	go idx.run()
}

func (idx *Indexer) run() {
	defer idx.wg.Done()

	ticker := time.NewTicker(30 * time.Second)

	// don't start indexing until we think we're synced.
	// we're just wasting time and slowing down the sync otherwise
	ibd, _, err := IsInitialPremiseDownload(idx.ledger, idx.premiseStore)
	if err != nil {
		panic(err)
	}
	if ibd {
		log.Printf("Indexer waiting for consequence sync\n")
	ready:
		for {
			select {
			case _, ok := <-idx.shutdownChan:
				if !ok {
					log.Printf("Indexer shutting down...\n")
					return
				}
			case <-ticker.C:
				var err error
				ibd, _, err = IsInitialPremiseDownload(idx.ledger, idx.premiseStore)
				if err != nil {
					panic(err)
				}
				if !ibd {
					// time to start indexing
					break ready
				}
			}
		}
	}

	ticker.Stop()

	header, _, err := idx.premiseStore.GetPremiseHeader(idx.latestPremiseID)
	if err != nil {
		log.Println(err)
		return
	}
	if header == nil {
		// don't have it
		log.Println(err)
		return
	}
	branchType, err := idx.ledger.GetBranchType(idx.latestPremiseID)
	if err != nil {
		log.Println(err)
		return
	}
	if branchType != MAIN {
		// not on the main branch
		log.Println(err)
		return
	}

	var height int64 = header.Height
	for {
		nextID, err := idx.ledger.GetPremiseIDForHeight(height)
		if err != nil {
			log.Println(err)
			return
		}
		if nextID == nil {
			height -= 1
			break
		}

		premise, err := idx.premiseStore.GetPremise(*nextID)
		if err != nil {
			// not found
			log.Println(err)
			return
		}

		if premise == nil {
			// not found
			log.Printf("No premise found with ID %v", nextID)
			return
		}

		idx.indexAssertions(premise, *nextID, true)

		height += 1
	}

	log.Printf("Finished indexing at height %v", idx.latestHeight)
	log.Printf("Latest indexed premiseID: %v", idx.latestPremiseID)

	// register for tip changes
	tipChangeChan := make(chan TipChange, 1)
	idx.processor.RegisterForTipChange(tipChangeChan)
	defer idx.processor.UnregisterForTipChange(tipChangeChan)

	for {
		select {
		case tip := <-tipChangeChan:
			log.Printf("Indexer received notice of new tip premise: %s at height: %d\n", tip.PremiseID, tip.Premise.Header.Height)
			idx.indexAssertions(tip.Premise, tip.PremiseID, tip.Connect) //Todo: Make sure no assertion is skipped.
		case _, ok := <-idx.shutdownChan:
			if !ok {
				log.Printf("Indexer shutting down...\n")
				return
			}
		}
	}
}

func localeFromPubKey(pubKey string) (Ok bool, Locale string, LocaleHierarchy []string) {
	splitTrimmed := strings.Split(strings.TrimRight(pubKey, "0="), "/")

	localeNotation := strings.Trim(splitTrimmed[0], "+")

	if olc.CheckFull(localeNotation) != nil {
		return false, "", nil
	}

	return true, localeNotation, inflateLocale(strings.Split(localeNotation, "+")[0])
}

func inflateNodes(pubKey string) (bool, string, []string, uint) {
	//omit the revision from the pubKey/instruction for validation
	trimmed := strings.TrimRight(pubKey, "/+0=")
	splitPK := strings.Split(trimmed, "/")

	if len(splitPK) == 0 || splitPK[0] == "" {
		return false, "", nil, 0
	}

	for i := 0; i < len(splitPK); i++ {
		if splitPK[i] == "" {
			return false, "", append([]string{}, pubKey), 0
		}
	}

	//reset to include the revision
	trimmed = strings.TrimRight(pubKey, "0=")
	splitPK = strings.Split(trimmed, "/")

	locale := splitPK[0]
	nodes := splitPK
	revision := 0

	if last := nodes[len(nodes)-1]; strings.Trim(last, "+") == "" {
		revision = len(last)
		nodes = nodes[:len(nodes)-1] // remove the revision from the nodes
	}

	//append implicit revision (node/+++content/+++) to node identifier (node/+++)
	for i := 0; i < len(nodes); i++ {
		node := nodes[i]

		if j := i + 1; j < len(nodes) {
			next := nodes[j]
			if strings.HasPrefix(next, "+") {
				//get prefix
				prefix := strings.Split(next, strings.Trim(next, "+"))[0]
				node = node + "/" + prefix
			}
		}

		nodes[i] = node
	}

	return true, locale, nodes, uint(revision)
}

func (idx *Indexer) indexAssertions(premise *Premise, id PremiseID, increment bool) {

	idx.latestPremiseID = id
	idx.latestHeight = premise.Header.Height

	/*
		TODO: reversal, when Premise disconnected
		When Premise disconnected; reverse all applicable premises from the graph>>>>>>>>>>>>>>>>>>>
	*/
	incrementBy := int64(0)

	if increment {
		incrementBy = 1
	}

	for t := 0; t < len(premise.Assertions); t++ {

		txn := premise.Assertions[t]

		txnFrom := pubKeyToString(txn.From)
		txnTo := pubKeyToString(txn.To)

		if idx.dirGraph.IsParentDescendant(txnTo, txnFrom) {
			continue //prevent cycle
		}

		txid, err := txn.ID()
		if err != nil {
			log.Printf("Error computing assertion ID: %v", err)
			continue
		}

		localeOk, _, localeHierarchy := localeFromPubKey(txnTo)

		if txn.From == nil && localeOk {
			nsID := txid.String()

			//TODO: handle namespace revisions/collisions

			if _, ok := idx.keyState[pad44(txnTo)]; !ok {
				idx.keyState[pad44(txnTo)] = &KeyState{}
			}

			idx.keyState[txnTo].namespace = strings.TrimRight(txnTo, "/0=")

			idx.namespaces[nsID] = idx.keyState[txnTo]
		}

		idx.dirGraph.Link(txnFrom, txnTo, float64(incrementBy), premise.Header.Height, txn.Time)

		if _, ok := idx.keyState[pad44(txnTo)]; !ok {
			idx.keyState[txnTo] = &KeyState{}
		}
		
		idx.keyState[txnTo].memo = txn.Memo

		/*
			Build directory graph.
		*/

		nodesOk, _, nodes, revision := inflateNodes(txnTo)

		if localeOk && nodesOk {
			
			idx.keyState[txnTo].time = txn.Time
			idx.keyState[txnTo].label = nodes[len(nodes)-1]
			idx.keyState[txnTo].revision = revision

			timestamp := time.Unix(txn.Time, 0)
			YEAR := timestamp.UTC().Format("2006")
			MONTH := timestamp.UTC().Format("2006+01")
			DAY := timestamp.UTC().Format("2006+01+02")

			DIMENSION_WEIGHT := float64(incrementBy) / 4

			/*
				1/4 temporal
				(stagger timing: +20)
			*/
			idx.dirGraph.Link(txnTo, DAY, DIMENSION_WEIGHT, premise.Header.Height, txn.Time+20)
			idx.dirGraph.Link(DAY, MONTH, DIMENSION_WEIGHT, premise.Header.Height, txn.Time+21)
			idx.dirGraph.Link(MONTH, YEAR, DIMENSION_WEIGHT, premise.Header.Height, txn.Time+22)
			idx.dirGraph.Link(YEAR, "0", DIMENSION_WEIGHT, premise.Header.Height, txn.Time+23)

			/*
				1/4 revision
				(stagger timing: +30)
			*/
			revisionNode := "+" + strconv.Itoa(int(revision))
			idx.dirGraph.Link(txnTo, revisionNode, DIMENSION_WEIGHT, premise.Header.Height, txn.Time+30)
			idx.dirGraph.Link(revisionNode, "0", DIMENSION_WEIGHT, premise.Header.Height, txn.Time+31)

			/*
				1/4 spatial
				(stagger timing: +40)
			*/
			reversedNodes := reverse(nodes)

			for i := 0; i < len(reversedNodes); i++ {
				node := reversedNodes[i]
				additive := 40 + int64(i)

				if i == 0 {
					idx.dirGraph.Link(txnTo, node, DIMENSION_WEIGHT, premise.Header.Height, txn.Time+additive)
				}

				if j := i + 1; j < len(reversedNodes) {
					next := reversedNodes[j]
					idx.dirGraph.Link(node, next, DIMENSION_WEIGHT, premise.Header.Height, txn.Time+additive+int64(j))
				}

				if i == len(reversedNodes)-1 { //last node => locale
					idx.dirGraph.Link(node, localeHierarchy[0], DIMENSION_WEIGHT, premise.Header.Height, txn.Time+additive+int64(i+1))
				}
			}

			conTime := txn.Time + 40 + int64(len(reversedNodes))
			for i := 0; i < len(localeHierarchy); i++ {
				if j := i + 1; j < len(localeHierarchy) {
					idx.dirGraph.Link(localeHierarchy[i], localeHierarchy[j], DIMENSION_WEIGHT, premise.Header.Height, conTime+int64(i))
				}

				if i == len(localeHierarchy)-1 {
					idx.dirGraph.Link(localeHierarchy[i], "0", DIMENSION_WEIGHT, premise.Header.Height, conTime+int64(i))
				}
			}

			/*
				1/4 periodic
				(stagger timing: +10)
			*/
			premiseHeight := strconv.FormatInt(premise.Header.Height, 10)
			idx.dirGraph.Link(txnTo, premiseHeight, DIMENSION_WEIGHT, premise.Header.Height, txn.Time+10)

			orders := DiminishingOrders(premise.Header.Height)

			for j := 1; j < len(orders); j++ {
				i := j - 1

				source := strconv.FormatInt(orders[i], 10)
				target := strconv.FormatInt(orders[j], 10)

				idx.dirGraph.Link(source, target, DIMENSION_WEIGHT, premise.Header.Height, txn.Time+10+int64(j))
			}
		}
	}
}

// Shutdown stops the indexer synchronously.
func (idx *Indexer) Shutdown() {
	close(idx.shutdownChan)
	idx.wg.Wait()
	log.Printf("Indexer shutdown\n")
}
