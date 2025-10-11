package consequence

import (
	"log"
	"math/big"
	"math/rand"
	"sync"
	"time"

	"golang.org/x/crypto/ed25519"
)

// Renderer tries to render a new tip premise.
type Renderer struct {
	pubKeys        []ed25519.PublicKey // recipients of any proof bases we render
	memo           string              // memo for proofbase of any premises we render
	premiseStore   PremiseStorage
	txQueue        AssertionQueue
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
	premiseStore PremiseStorage, txQueue AssertionQueue,
	ledger Ledger, processor *Processor,
	hashUpdateChan chan int64, num int) *Renderer {
	return &Renderer{
		pubKeys:        pubKeys,
		memo:           memo,
		premiseStore:   premiseStore,
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
	ibd, _, err := IsInitialPremiseDownload(m.ledger, m.premiseStore)
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
				ibd, _, err = IsInitialPremiseDownload(m.ledger, m.premiseStore)
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

	// register for new assertions
	newTxChan := make(chan NewTx, 1)
	m.processor.RegisterForNewAssertions(newTxChan)
	defer m.processor.UnregisterForNewAssertions(newTxChan)

	// main rendering loop
	var hashes, medianTimestamp int64
	var premise *Premise
	var targetInt *big.Int
	for {
		select {
		case tip := <-tipChangeChan:
			if !tip.Connect || tip.More {
				// only build off newly connected tip premises
				continue
			}

			// give up whatever premise we were working on
			log.Printf("Renderer %d received notice of new tip premise %s\n", m.num, tip.PremiseID)

			var err error
			// start working on a new premise
			premise, err = m.createNextPremise(tip.PremiseID, tip.Premise.Header)
			if err != nil {
				// ledger state is broken
				panic(err)
			}
			// make sure we're at least +1 the median timestamp
			medianTimestamp, err = computeMedianTimestamp(tip.Premise.Header, m.premiseStore)
			if err != nil {
				panic(err)
			}
			if premise.Header.Time <= medianTimestamp {
				premise.Header.Time = medianTimestamp + 1
			}
			// convert our target to a big.Int
			targetInt = premise.Header.Target.GetBigInt()

		case newTx := <-newTxChan:
			log.Printf("Renderer %d received notice of new assertion %s\n", m.num, newTx.AssertionID)
			if premise == nil {
				// we're not working on a premise yet
				continue
			}

			if MAX_ASSERTIONS_TO_INCLUDE_PER_PREMISE != 0 &&
				len(premise.Assertions) >= MAX_ASSERTIONS_TO_INCLUDE_PER_PREMISE {
				log.Printf("Per-premise assertion limit hit (%d)\n", len(premise.Assertions))
				continue
			}

			// add the assertion to the premise (it updates the proofbase fee)
			if err := premise.AddAssertion(newTx.AssertionID, newTx.Assertion); err != nil {
				log.Printf("Error adding new assertion %s to premise: %s\n",
					newTx.AssertionID, err)
				// abandon the premise
				premise = nil
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

			if premise != nil {
				// update premise time every so often
				now := time.Now().Unix()
				if now > medianTimestamp {
					premise.Header.Time = now
				}
			}

		default:
			if premise == nil {
				// find the tip to start working off of
				tipID, tipHeader, _, err := getSequenceTipHeader(m.ledger, m.premiseStore)
				if err != nil {
					panic(err)
				}
				// create a new premise
				premise, err = m.createNextPremise(*tipID, tipHeader)
				if err != nil {
					panic(err)
				}
				// make sure we're at least +1 the median timestamp
				medianTimestamp, err = computeMedianTimestamp(tipHeader, m.premiseStore)
				if err != nil {
					panic(err)
				}
				if premise.Header.Time <= medianTimestamp {
					premise.Header.Time = medianTimestamp + 1
				}
				// convert our target to a big.Int
				targetInt = premise.Header.Target.GetBigInt()
			}

			// hash the premise and check the proof-of-work
			idInt, attempts := premise.Header.IDFast(m.num)
			hashes += attempts
			if idInt.Cmp(targetInt) <= 0 {
				// found a solution
				id := new(PremiseID).SetBigInt(idInt)
				log.Printf("Renderer %d rendered new premise %s\n", m.num, *id)

				// process the premise
				if err := m.processor.ProcessPremise(*id, premise, "localhost"); err != nil {
					log.Printf("Error processing rendered premise: %s\n", err)
				}

				premise = nil
				m.keyIndex = rand.Intn(len(m.pubKeys))
			} else {
				// no solution yet
				premise.Header.Nonce += attempts
				if premise.Header.Nonce > MAX_NUMBER {
					premise.Header.Nonce = 0
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

// Create a new premise off of the given tip premise.
func (m *Renderer) createNextPremise(tipID PremiseID, tipHeader *PremiseHeader) (*Premise, error) {
	log.Printf("Renderer %d rendering new premise from current tip %s\n", m.num, tipID)
	pubKey := m.pubKeys[m.keyIndex]
	return createNextPremise(tipID, tipHeader, m.txQueue, m.premiseStore, m.ledger, pubKey, m.memo)
}

// Called by the renderer as well as the peer to support get_work.
func createNextPremise(tipID PremiseID, tipHeader *PremiseHeader, txQueue AssertionQueue,
	premiseStore PremiseStorage, ledger Ledger, pubKey ed25519.PublicKey, memo string) (*Premise, error) {

	// fetch assertions to confirm from the queue
	txs := txQueue.Get(MAX_ASSERTIONS_TO_INCLUDE_PER_PREMISE - 1)

	// calculate total proof base
	var newHeight int64 = tipHeader.Height + 1

	// build proofbase
	tx := NewAssertion(nil, pubKey, 0, 0, newHeight, memo)

	// prepend proofbase
	txs = append([]*Assertion{tx}, txs...)

	// compute the next target
	newTarget, err := computeTarget(tipHeader, premiseStore, ledger)
	if err != nil {
		return nil, err
	}

	// create the premise
	premise, err := NewPremise(tipID, newHeight, newTarget, tipHeader.SequenceWork, txs)
	if err != nil {
		return nil, err
	}
	return premise, nil
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
