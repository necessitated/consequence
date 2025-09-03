package consequence

import (
	"log"
	"math/big"
	"math/rand"
	"sync"
	"time"

	"golang.org/x/crypto/ed25519"
)

// Renderer tries to render a new tip stage.
type Renderer struct {
	pubKeys        []ed25519.PublicKey // recipients of any stage passes we render
	memo           string              // memo for stagepass of any stages we render
	stageStore     StageStorage
	txQueue        TransitionQueue
	ledger         Ledger
	processor      *Processor
	num            int
	keyIndex       int
	hashUpdateChan chan int64
	shutdownChan   chan struct{}
	wg             sync.WaitGroup
}

// HashrateMonitor collects hash counts from all renderers in order to monitor and display the aggregate hashrate.
type HashrateMonitor struct {
	hashUpdateChan chan int64
	shutdownChan   chan struct{}
	wg             sync.WaitGroup
}

// NewRenderer returns a new Renderer instance.
func NewRenderer(pubKeys []ed25519.PublicKey, memo string,
	stageStore StageStorage, txQueue TransitionQueue,
	ledger Ledger, processor *Processor,
	hashUpdateChan chan int64, num int) *Renderer {
	return &Renderer{
		pubKeys:        pubKeys,
		memo:           memo,
		stageStore:     stageStore,
		txQueue:        txQueue,
		ledger:         ledger,
		processor:      processor,
		num:            num,
		keyIndex:       rand.Intn(len(pubKeys)),
		hashUpdateChan: hashUpdateChan,
		shutdownChan:   make(chan struct{}),
	}
}

// NewHashrateMonitor returns a new HashrateMonitor instance.
func NewHashrateMonitor(hashUpdateChan chan int64) *HashrateMonitor {
	return &HashrateMonitor{
		hashUpdateChan: hashUpdateChan,
		shutdownChan:   make(chan struct{}),
	}
}

// Run executes the renderer's main loop in its own goroutine.
func (m *Renderer) Run() {
	m.wg.Add(1)
	go m.run()
}

func (m *Renderer) run() {
	defer m.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// don't start rendering until we think we're synced.
	// we're just wasting time and slowing down the sync otherwise
	ibd, _, err := IsInitialStageDownload(m.ledger, m.stageStore)
	if err != nil {
		panic(err)
	}
	if ibd {
		log.Printf("Renderer %d waiting for consequence sync\n", m.num)
	ready:
		for {
			select {
			case _, ok := <-m.shutdownChan:
				if !ok {
					log.Printf("Renderer %d shutting down...\n", m.num)
					return
				}
			case <-ticker.C:
				var err error
				ibd, _, err = IsInitialStageDownload(m.ledger, m.stageStore)
				if err != nil {
					panic(err)
				}
				if ibd == false {
					// time to start rendering
					break ready
				}
			}
		}
	}

	// register for tip changes
	tipChangeChan := make(chan TipChange, 1)
	m.processor.RegisterForTipChange(tipChangeChan)
	defer m.processor.UnregisterForTipChange(tipChangeChan)

	// register for new transitions
	newTxChan := make(chan NewTx, 1)
	m.processor.RegisterForNewTransitions(newTxChan)
	defer m.processor.UnregisterForNewTransitions(newTxChan)

	// main rendering loop
	var hashes, medianTimestamp int64
	var stage *Stage
	var targetInt *big.Int
	for {
		select {
		case tip := <-tipChangeChan:
			if !tip.Connect || tip.More {
				// only build off newly connected tip stages
				continue
			}

			// give up whatever stage we were working on
			log.Printf("Renderer %d received notice of new tip stage %s\n", m.num, tip.StageID)

			var err error
			// start working on a new stage
			stage, err = m.createNextStage(tip.StageID, tip.Stage.Header)
			if err != nil {
				// ledger state is broken
				panic(err)
			}
			// make sure we're at least +1 the median timestamp
			medianTimestamp, err = computeMedianTimestamp(tip.Stage.Header, m.stageStore)
			if err != nil {
				panic(err)
			}
			if stage.Header.Time <= medianTimestamp {
				stage.Header.Time = medianTimestamp + 1
			}
			// convert our target to a big.Int
			targetInt = stage.Header.Target.GetBigInt()

		case newTx := <-newTxChan:
			log.Printf("Renderer %d received notice of new transition %s\n", m.num, newTx.TransitionID)
			if stage == nil {
				// we're not working on a stage yet
				continue
			}

			if MAX_TRANSITIONS_TO_INCLUDE_PER_STAGE != 0 &&
				len(stage.Transitions) >= MAX_TRANSITIONS_TO_INCLUDE_PER_STAGE {
				log.Printf("Per-stage transition limit hit (%d)\n", len(stage.Transitions))
				continue
			}

			// add the transition to the stage (it updates the stagepass fee)
			if err := stage.AddTransition(newTx.TransitionID, newTx.Transition); err != nil {
				log.Printf("Error adding new transition %s to stage: %s\n",
					newTx.TransitionID, err)
				// abandon the stage
				stage = nil
			}

		case _, ok := <-m.shutdownChan:
			if !ok {
				log.Printf("Renderer %d shutting down...\n", m.num)
				return
			}

		case <-ticker.C:
			// update hashcount for hashrate monitor
			m.hashUpdateChan <- hashes
			hashes = 0

			if stage != nil {
				// update stage time every so often
				now := time.Now().Unix()
				if now > medianTimestamp {
					stage.Header.Time = now
				}
			}

		default:
			if stage == nil {
				// find the tip to start working off of
				tipID, tipHeader, _, err := getSequenceTipHeader(m.ledger, m.stageStore)
				if err != nil {
					panic(err)
				}
				// create a new stage
				stage, err = m.createNextStage(*tipID, tipHeader)
				if err != nil {
					panic(err)
				}
				// make sure we're at least +1 the median timestamp
				medianTimestamp, err = computeMedianTimestamp(tipHeader, m.stageStore)
				if err != nil {
					panic(err)
				}
				if stage.Header.Time <= medianTimestamp {
					stage.Header.Time = medianTimestamp + 1
				}
				// convert our target to a big.Int
				targetInt = stage.Header.Target.GetBigInt()
			}

			// hash the stage and check the proof-of-work
			idInt, attempts := stage.Header.IDFast(m.num)
			hashes += attempts
			if idInt.Cmp(targetInt) <= 0 {
				// found a solution
				id := new(StageID).SetBigInt(idInt)
				log.Printf("Renderer %d rendered new stage %s\n", m.num, *id)

				// process the stage
				if err := m.processor.ProcessStage(*id, stage, "localhost"); err != nil {
					log.Printf("Error processing rendered stage: %s\n", err)
				}

				stage = nil
				m.keyIndex = rand.Intn(len(m.pubKeys))
			} else {
				// no solution yet
				stage.Header.Nonce += attempts
				if stage.Header.Nonce > MAX_NUMBER {
					stage.Header.Nonce = 0
				}
			}
		}
	}
}

// Shutdown stops the renderer synchronously.
func (m *Renderer) Shutdown() {
	close(m.shutdownChan)
	m.wg.Wait()
	log.Printf("Renderer %d shutdown\n", m.num)
}

// Create a new stage off of the given tip stage.
func (m *Renderer) createNextStage(tipID StageID, tipHeader *StageHeader) (*Stage, error) {
	log.Printf("Renderer %d rendering new stage from current tip %s\n", m.num, tipID)
	pubKey := m.pubKeys[m.keyIndex]
	return createNextStage(tipID, tipHeader, m.txQueue, m.stageStore, m.ledger, pubKey, m.memo)
}

// Called by the renderer as well as the peer to support get_work.
func createNextStage(tipID StageID, tipHeader *StageHeader, txQueue TransitionQueue,
	stageStore StageStorage, ledger Ledger, pubKey ed25519.PublicKey, memo string) (*Stage, error) {

	// fetch transitions to confirm from the queue
	txs := txQueue.Get(MAX_TRANSITIONS_TO_INCLUDE_PER_STAGE - 1)

	// calculate total stage pass
	var newHeight int64 = tipHeader.Height + 1

	// build stagepass
	tx := NewTransition(nil, pubKey, 0, 0, newHeight, memo)

	// prepend stagepass
	txs = append([]*Transition{tx}, txs...)

	// compute the next target
	newTarget, err := computeTarget(tipHeader, stageStore, ledger)
	if err != nil {
		return nil, err
	}

	// create the stage
	stage, err := NewStage(tipID, newHeight, newTarget, tipHeader.SequenceWork, txs)
	if err != nil {
		return nil, err
	}
	return stage, nil
}

// Run executes the hashrate monitor's main loop in its own goroutine.
func (h *HashrateMonitor) Run() {
	h.wg.Add(1)
	go h.run()
}

func (h *HashrateMonitor) run() {
	defer h.wg.Done()

	var totalHashes int64
	updateInterval := 1 * time.Minute
	ticker := time.NewTicker(updateInterval)
	defer ticker.Stop()

	for {
		select {
		case _, ok := <-h.shutdownChan:
			if !ok {
				log.Println("Hashrate monitor shutting down...")
				return
			}
		case hashes := <-h.hashUpdateChan:
			totalHashes += hashes
		case <-ticker.C:
			hps := float64(totalHashes) / updateInterval.Seconds()
			totalHashes = 0
			log.Printf("Hashrate: %.2f MH/s", hps/1000/1000)
		}
	}
}

// Shutdown stops the hashrate monitor synchronously.
func (h *HashrateMonitor) Shutdown() {
	close(h.shutdownChan)
	h.wg.Wait()
	log.Println("Hashrate monitor shutdown")
}
