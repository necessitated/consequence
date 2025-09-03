package consequence

import (
	"log"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	olc "github.com/google/open-location-code/go"
)

type KeyState struct {
	pseudonym  string
	bio 	   string
	rating     uint
	time       int64
}

type Indexer struct {
	stageStore    StageStorage
	ledger       Ledger
	processor    *Processor
	latestStageID StageID
	latestHeight int64
	cnGraph      *Graph
	memory   	 map[string]*KeyState
	shutdownChan chan struct{}
	wg           sync.WaitGroup
}

func NewIndexer(
	conGraph *Graph,
	stageStore StageStorage,
	ledger Ledger,
	processor *Processor,
	genesisStageID StageID,
) *Indexer {
	return &Indexer{
		cnGraph:      conGraph,
		stageStore:    stageStore,
		ledger:       ledger,
		processor:    processor,
		latestStageID: genesisStageID,
		latestHeight: 0,
		memory:       make(map[string]*KeyState),
		shutdownChan: make(chan struct{}),
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
	ibd, _, err := IsInitialStageDownload(idx.ledger, idx.stageStore)
	if err != nil {
		panic(err)
	}
	if ibd {
		log.Printf("Indexer waiting for focalpoint sync\n")
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
				ibd, _, err = IsInitialStageDownload(idx.ledger, idx.stageStore)
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

	header, _, err := idx.stageStore.GetStageHeader(idx.latestStageID)
	if err != nil {
		log.Println(err)
		return
	}
	if header == nil {
		// don't have it
		log.Println(err)
		return
	}
	branchType, err := idx.ledger.GetBranchType(idx.latestStageID)
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
		nextID, err := idx.ledger.GetStageIDForHeight(height)
		if err != nil {
			log.Println(err)
			return
		}
		if nextID == nil {
			height -= 1
			break
		}

		stage, err := idx.stageStore.GetStage(*nextID)
		if err != nil {
			// not found
			log.Println(err)
			return
		}

		if stage == nil {
			// not found
			log.Printf("No stage found with ID %v", nextID)
			return
		}

		idx.indexTransitions(stage, *nextID, true)

		height += 1
	}

	log.Printf("Finished indexing at height %v", idx.latestHeight)
	log.Printf("Latest indexed stageID: %v", idx.latestStageID)

	idx.rankGraph()

	// register for tip changes
	tipChangeChan := make(chan TipChange, 1)
	idx.processor.RegisterForTipChange(tipChangeChan)
	defer idx.processor.UnregisterForTipChange(tipChangeChan)

	for {
		select {
		case tip := <-tipChangeChan:
			log.Printf("Indexer received notice of new tip stage: %s at height: %d\n", tip.StageID, tip.Stage.Header.Height)
			idx.indexTransitions(tip.Stage, tip.StageID, tip.Connect) //Todo: Make sure no consideration is skipped.
			if !tip.More {
				idx.rankGraph()
			}
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
	//omit the rating from the pubKey/instruction for validation
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

	//reset to include the rating
	trimmed = strings.TrimRight(pubKey, "0=")
	splitPK = strings.Split(trimmed, "/")

	locale := splitPK[0]
	nodes := splitPK
	rating := 0

	if last := nodes[len(nodes)-1]; strings.Trim(last, "+") == "" {
		rating = len(last)
		nodes = nodes[:len(nodes)-1]// remove the rating from the nodes
	}

	//append implicit rating (node/+++content/+++) to node identifier (node/+++)
	for i := 0; i < len(nodes); i++ {
		node := nodes[i]

		if j := i + 1; j < len(nodes) {
			next := nodes[j]
			if strings.HasPrefix(next, "+"){
				//get prefix
				prefix := strings.Split(next, strings.Trim(next, "+"))[0]
				node = node + "/" + prefix
			}
		}

		nodes[i] = node
	}

	return true, locale, nodes, uint(rating)
}

func (idx *Indexer) indexTransitions(stage *Stage, id StageID, increment bool) {
	idx.latestStageID = id
	idx.latestHeight = stage.Header.Height
	incrementBy := 0.00
	decrementBy := 0.00

	if increment {
		incrementBy = 1
		decrementBy = -1
	} else {
		//Stage disconnected: Reverse all applicable considerations from the graph
		incrementBy = -1
		decrementBy = 1
	}

	for t := 0; t < len(stage.Transitions); t++ {
		txn := stage.Transitions[t]

		txnFrom := pubKeyToString(txn.From)
		txnTo := pubKeyToString(txn.To)

		idx.cnGraph.SetImbalance(txnFrom, int64(decrementBy))
		idx.cnGraph.SetImbalance(txnTo, int64(incrementBy))

		nodesOk, _, nodes, rating := inflateNodes(txnTo)

		/*
			Capture pseudonym for Cursor:
			"CursorKey" -> "//Pseudonymous//0000000000000000000000000000="
		*/
		if !nodesOk && strings.HasPrefix(txnTo, "//") {
			re := regexp.MustCompile(`//([^/]+)//`)
			trimmed := strings.TrimRight(txnTo, "0=")
			matches := re.FindStringSubmatch(trimmed)
			if len(matches) > 1 {				
				if _, ok := idx.memory[txnFrom]; !ok {
					idx.memory[txnFrom] = &KeyState{}
				}
				idx.memory[txnFrom].pseudonym = strings.ReplaceAll(strings.Trim(trimmed, "/"), "+", " ")
				memo := strings.TrimSpace(txn.Memo)
				if len(memo) > 100 {
					memo = memo[:100]
				}
				idx.memory[txnFrom].bio = memo
				//Don't register system considerations. 
				// TODO: Or perhaps we can register them with a system category? 
				continue 
			}
		}

		/*
			Build graph.
		*/
		idx.cnGraph.Link(txnFrom, txnTo, incrementBy, stage.Header.Height, txn.Time)//0->1 
		idx.cnGraph.SetGroup(txnTo, 0)//TODO: Categorise nodes by groups for refined visualization.------------------------------>

		if ok, _, localeHierarchy := localeFromPubKey(txnTo); ok && nodesOk {

			if _, ok := idx.memory[pad44(txnTo)]; !ok {
				idx.memory[pad44(txnTo)] = &KeyState{}
			}

			idx.memory[pad44(txnTo)].time = txn.Time
			idx.memory[pad44(txnTo)].rating = rating
			idx.memory[pad44(txnTo)].pseudonym = nodes[len(nodes)-1]
			

			timestamp := time.Unix(txn.Time, 0)
			YEAR := timestamp.UTC().Format("2006")
			MONTH := timestamp.UTC().Format("2006+01")
			DAY := timestamp.UTC().Format("2006+01+02")

			DIMENSION_WEIGHT := incrementBy / 4

			/* Temporal 1/4 perspective-----------// Time + 20 */
			idx.cnGraph.Link(txnTo, DAY, DIMENSION_WEIGHT, stage.Header.Height, txn.Time + 20)
			idx.cnGraph.Link(DAY, MONTH, DIMENSION_WEIGHT, stage.Header.Height, txn.Time + 21)
			idx.cnGraph.Link(MONTH, YEAR, DIMENSION_WEIGHT, stage.Header.Height, txn.Time + 22)
			idx.cnGraph.Link(YEAR, "0", DIMENSION_WEIGHT, stage.Header.Height, txn.Time + 23)

			/* rating  1/4 perspective ------------// Time + 30 */		
			ratingNode := "+"+strconv.Itoa(int(rating))	
			idx.cnGraph.Link(txnTo, ratingNode, DIMENSION_WEIGHT, stage.Header.Height, txn.Time + 30)
			idx.cnGraph.Link(ratingNode, "0", DIMENSION_WEIGHT, stage.Header.Height, txn.Time + 31)

			
			/* Spatial  1/4 perspective ------------// Time + 40 */			
			reversedNodes := reverse(nodes)		
			
			nodeWeight := DIMENSION_WEIGHT / float64(len(reversedNodes))

			for i := 0; i < len(reversedNodes); i++ {
				node := reversedNodes[i]
				additive := 40 + int64(i)
				idx.cnGraph.Link(txnTo, node, nodeWeight, stage.Header.Height, txn.Time + additive)

				if j := i + 1; j < len(reversedNodes) {
					next := reversedNodes[j]

					idx.cnGraph.Link(node, next, (nodeWeight * float64(j)), stage.Header.Height, txn.Time + additive + int64(j))// => accumulated
				}

				if i == len(reversedNodes)-1 { //last node => locale
					idx.cnGraph.Link(node, localeHierarchy[0], DIMENSION_WEIGHT, stage.Header.Height, txn.Time + additive + int64(i+1))// => total spatial accumulation
				}
			}

			conTime := txn.Time + 40 + int64(len(reversedNodes))
			for i := 0; i < len(localeHierarchy); i++ {
				if j := i + 1; j < len(localeHierarchy) {
					idx.cnGraph.Link(localeHierarchy[i], localeHierarchy[j], DIMENSION_WEIGHT, stage.Header.Height, conTime + int64(i))// => accumulated
				}

				if i == len(localeHierarchy)-1 {
					idx.cnGraph.Link(localeHierarchy[i], "0", DIMENSION_WEIGHT, stage.Header.Height, conTime + int64(i))
				}
			}

			/* 
				1/4 metric/perspective------------// Time + 10//
				Height: Age = Stage = Clock = Iteration = Duration = Direction = Revolution
			 */
			stageHeight := strconv.FormatInt(stage.Header.Height, 10)
			idx.cnGraph.Link(txnTo, stageHeight, DIMENSION_WEIGHT, stage.Header.Height, txn.Time + 10)

			orders := DiminishingOrders(stage.Header.Height)

			for j := 1; j < len(orders); j++ {
				i := j - 1

				source := strconv.FormatInt(orders[i], 10)
				target := strconv.FormatInt(orders[j], 10)

				idx.cnGraph.Link(source, target, DIMENSION_WEIGHT, stage.Header.Height, txn.Time + 10 + int64(j))
			}
		}
	}
}

func (idx *Indexer) rankGraph() {
	log.Printf("Indexer ranking at height: %d\n", idx.latestHeight)
	idx.cnGraph.Rank(1.0, 1e-6)
	log.Printf("Ranking finished")
}

// Shutdown stops the indexer synchronously.
func (idx *Indexer) Shutdown() {
	close(idx.shutdownChan)
	idx.wg.Wait()
	log.Printf("Indexer shutdown\n")
}
