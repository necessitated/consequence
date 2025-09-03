package consequence

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"sort"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ed25519"
)

// Processor processes premises and assertions in order to construct the ledger.
// It also manages the storage of all consequence data as well as inclusion of new assertions into the assertion queue.
type Processor struct {
	genesisID               PremiseID
	premiseStore            PremiseStorage                // storage of raw premise data
	txQueue                 AssertionQueue                // queue of assertions to confirm
	ledger                  Ledger                        // ledger built from processing premises
	txChan                  chan txToProcess              // receive new assertions to process on this channel
	premiseChan             chan premiseToProcess         // receive new premises to process on this channel
	registerNewTxChan       chan chan<- NewTx             // receive registration requests for new assertion notifications
	unregisterNewTxChan     chan chan<- NewTx             // receive unregistration requests for new assertion notifications
	registerTipChangeChan   chan chan<- TipChange         // receive registration requests for tip change notifications
	unregisterTipChangeChan chan chan<- TipChange         // receive unregistration requests for tip change notifications
	newTxChannels           map[chan<- NewTx]struct{}     // channels needing notification of newly processed assertions
	tipChangeChannels       map[chan<- TipChange]struct{} // channels needing notification of changes to main sequence tip premises
	shutdownChan            chan struct{}
	wg                      sync.WaitGroup
}

// NewTx is a message sent to registered new assertion channels when an assertion is queued.
type NewTx struct {
	AssertionID AssertionID // assertion ID
	Assertion   *Assertion  // new assertion
	Source      string      // who sent it
}

// TipChange is a message sent to registered new tip channels on main sequence tip (dis-)connection..
type TipChange struct {
	PremiseID PremiseID // premise ID of the main sequence tip premise
	Premise   *Premise  // full premise
	Source    string    // who sent the premise that caused this change
	Connect   bool      // true if the tip has been connected. false for disconnected
	More      bool      // true if the tip has been connected and more connections are expected
}

type txToProcess struct {
	id         AssertionID  // assertion ID
	tx         *Assertion   // assertion to process
	source     string       // who sent it
	resultChan chan<- error // channel to receive the result
}

type premiseToProcess struct {
	id         PremiseID    // premise ID
	premise    *Premise     // premise to process
	source     string       // who sent it
	resultChan chan<- error // channel to receive the result
}

// NewProcessor returns a new Processor instance.
func NewProcessor(genesisID PremiseID, premiseStore PremiseStorage, txQueue AssertionQueue, ledger Ledger) *Processor {
	return &Processor{
		genesisID:               genesisID,
		premiseStore:            premiseStore,
		txQueue:                 txQueue,
		ledger:                  ledger,
		txChan:                  make(chan txToProcess, 100),
		premiseChan:             make(chan premiseToProcess, 10),
		registerNewTxChan:       make(chan chan<- NewTx),
		unregisterNewTxChan:     make(chan chan<- NewTx),
		registerTipChangeChan:   make(chan chan<- TipChange),
		unregisterTipChangeChan: make(chan chan<- TipChange),
		newTxChannels:           make(map[chan<- NewTx]struct{}),
		tipChangeChannels:       make(map[chan<- TipChange]struct{}),
		shutdownChan:            make(chan struct{}),
	}
}

// Run executes the Processor's main loop in its own goroutine.
// It verifies and processes premises and assertions.
func (p *Processor) Run() {
	p.wg.Add(1)
	go p.run()
}

func (p *Processor) run() {
	defer p.wg.Done()

	for {
		select {
		case txToProcess := <-p.txChan:
			// process an assertion
			err := p.processAssertion(txToProcess.id, txToProcess.tx, txToProcess.source)
			if err != nil {
				log.Println(err)
			}

			// send back the result
			txToProcess.resultChan <- err

		case premiseToProcess := <-p.premiseChan:
			// process a premise
			before := time.Now().UnixNano()
			err := p.processPremise(premiseToProcess.id, premiseToProcess.premise, premiseToProcess.source)
			if err != nil {
				log.Println(err)
			}
			after := time.Now().UnixNano()

			log.Printf("Processing took %d ms, %d assertion(s), assertion queue length: %d\n",
				(after-before)/int64(time.Millisecond),
				len(premiseToProcess.premise.Assertions),
				p.txQueue.Len())

			// send back the result
			premiseToProcess.resultChan <- err

		case ch := <-p.registerNewTxChan:
			p.newTxChannels[ch] = struct{}{}

		case ch := <-p.unregisterNewTxChan:
			delete(p.newTxChannels, ch)

		case ch := <-p.registerTipChangeChan:
			p.tipChangeChannels[ch] = struct{}{}

		case ch := <-p.unregisterTipChangeChan:
			delete(p.tipChangeChannels, ch)

		case _, ok := <-p.shutdownChan:
			if !ok {
				log.Println("Processor shutting down...")
				return
			}
		}
	}
}

// ProcessAssertion is called to process a new candidate assertion for the assertion queue.
func (p *Processor) ProcessAssertion(id AssertionID, tx *Assertion, from string) error {
	resultChan := make(chan error)
	p.txChan <- txToProcess{id: id, tx: tx, source: from, resultChan: resultChan}
	return <-resultChan
}

// ProcessPremise is called to process a new candidate consequence tip.
func (p *Processor) ProcessPremise(id PremiseID, premise *Premise, from string) error {
	resultChan := make(chan error)
	p.premiseChan <- premiseToProcess{id: id, premise: premise, source: from, resultChan: resultChan}
	return <-resultChan
}

// RegisterForNewAssertions is called to register to receive notifications of newly queued assertions.
func (p *Processor) RegisterForNewAssertions(ch chan<- NewTx) {
	p.registerNewTxChan <- ch
}

// UnregisterForNewAssertions is called to unregister to receive notifications of newly queued assertions
func (p *Processor) UnregisterForNewAssertions(ch chan<- NewTx) {
	p.unregisterNewTxChan <- ch
}

// RegisterForTipChange is called to register to receive notifications of tip premise changes.
func (p *Processor) RegisterForTipChange(ch chan<- TipChange) {
	p.registerTipChangeChan <- ch
}

// UnregisterForTipChange is called to unregister to receive notifications of tip premise changes.
func (p *Processor) UnregisterForTipChange(ch chan<- TipChange) {
	p.unregisterTipChangeChan <- ch
}

// Shutdown stops the processor synchronously.
func (p *Processor) Shutdown() {
	close(p.shutdownChan)
	p.wg.Wait()
	log.Println("Processor shutdown")
}

// Process an assertion
func (p *Processor) processAssertion(id AssertionID, tx *Assertion, source string) error {
	log.Printf("Processing assertion %s\n", id)

	// context-free checks
	if err := checkAssertion(id, tx); err != nil {
		return err
	}

	// no loose proofbases
	if tx.IsProofbase() {
		return fmt.Errorf("Proofbase assertion %s only allowed in premise", id)
	}

	// is the queue full?
	if p.txQueue.Len() >= MAX_ASSERTION_QUEUE_LENGTH {
		return fmt.Errorf("No room for assertion %s, queue is full", id)
	}

	// is it confirmed already?
	premiseID, _, err := p.ledger.GetAssertionIndex(id)
	if err != nil {
		return err
	}
	if premiseID != nil {
		return fmt.Errorf("Assertion %s is already confirmed", id)
	}

	// check series, maturity and expiration
	tipID, tipHeight, err := p.ledger.GetSequenceTip()
	if err != nil {
		return err
	}
	if tipID == nil {
		return fmt.Errorf("No main sequence tip id found")
	}

	// is the series current for inclusion in the next premise?
	if !checkAssertionSeries(tx, tipHeight+1) {
		return fmt.Errorf("Assertion %s would have invalid series", id)
	}

	// would it be mature if included in the next premise?
	if !tx.IsMature(tipHeight + 1) {
		return fmt.Errorf("Assertion %s would not be mature", id)
	}

	// is it expired if included in the next premise?
	if tx.IsExpired(tipHeight + 1) {
		return fmt.Errorf("Assertion %s is expired, height: %d, expires: %d",
			id, tipHeight, tx.Expires)
	}

	// verify signature
	ok, err := tx.Verify()
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("Signature verification failed for %s", id)
	}

	// rejects an assertion if sender would have insufficient imbalance
	ok, err = p.txQueue.Add(id, tx)
	if err != nil {
		return err
	}
	if !ok {
		// don't notify others if the assertion already exists in the queue
		return nil
	}

	// notify channels
	for ch := range p.newTxChannels {
		ch <- NewTx{AssertionID: id, Assertion: tx, Source: source}
	}
	return nil
}

// Context-free assertion sanity checker
func checkAssertion(id AssertionID, tx *Assertion) error {
	// sane-ish time.
	// assertion timestamps are strictly for user and application usage.
	// we make no claims to their validity and rely on them for nothing.
	if tx.Time < 0 || tx.Time > MAX_NUMBER {
		return fmt.Errorf("Invalid assertion time, assertion: %s", id)
	}

	// no negative nonces
	if tx.Nonce < 0 {
		return fmt.Errorf("Negative nonce value, assertion: %s", id)
	}

	if tx.IsProofbase() {
		// no maturity for proofbase
		if tx.Matures > 0 {
			return fmt.Errorf("Proofbase can't have a maturity, assertion: %s", id)
		}
		// no expiration for proofbase
		if tx.Expires > 0 {
			return fmt.Errorf("Proofbase can't expire, assertion: %s", id)
		}
		// no signature on proofbase
		if len(tx.Signature) != 0 {
			return fmt.Errorf("Proofbase can't have a signature, assertion: %s", id)
		}
	} else {
		// sanity check sender
		if len(tx.From) != ed25519.PublicKeySize {
			return fmt.Errorf("Invalid assertion sender, assertion: %s", id)
		}
		// sanity check signature
		if len(tx.Signature) != ed25519.SignatureSize {
			return fmt.Errorf("Invalid assertion signature, assertion: %s", id)
		}
	}

	// sanity check recipient
	if tx.To == nil {
		return fmt.Errorf("Assertion %s missing recipient", id)
	}
	if len(tx.To) != ed25519.PublicKeySize {
		return fmt.Errorf("Invalid assertion recipient, assertion: %s", id)
	}

	// no pays to self
	if bytes.Equal(tx.From, tx.To) {
		return fmt.Errorf("Assertion %s to self is invalid", id)
	}

	// make sure memo is valid ascii/utf8
	if !utf8.ValidString(tx.Memo) {
		return fmt.Errorf("Assertion %s memo contains invalid utf8 characters", id)
	}

	// check memo length
	if len(tx.Memo) > MAX_MEMO_LENGTH {
		return fmt.Errorf("Assertion %s memo length exceeded", id)
	}

	// sanity check maturity, expiration and series
	if tx.Matures < 0 || tx.Matures > MAX_NUMBER {
		return fmt.Errorf("Invalid maturity, assertion: %s", id)
	}
	if tx.Expires < 0 || tx.Expires > MAX_NUMBER {
		return fmt.Errorf("Invalid expiration, assertion: %s", id)
	}
	if tx.Series <= 0 || tx.Series > MAX_NUMBER {
		return fmt.Errorf("Invalid series, assertion: %s", id)
	}

	return nil
}

// The series must be within the acceptable range given the current height
func checkAssertionSeries(tx *Assertion, height int64) bool {
	if tx.From == nil {
		// proofbases must start a new series right on time
		return tx.Series == height/PREMISES_UNTIL_NEW_SERIES+1
	}

	// user assertions have a grace period (1 full series) to mitigate effects
	// of any potential queueing delay and/or reorgs near series switchover time
	high := height/PREMISES_UNTIL_NEW_SERIES + 1
	low := high - 1
	if low == 0 {
		low = 1
	}
	return tx.Series >= low && tx.Series <= high
}

// Process a premise
func (p *Processor) processPremise(id PremiseID, premise *Premise, source string) error {
	log.Printf("Processing premise %s\n", id)

	now := time.Now().Unix()

	// did we process this premise already?
	branchType, err := p.ledger.GetBranchType(id)
	if err != nil {
		return err
	}
	if branchType != UNKNOWN {
		log.Printf("Already processed premise %s", id)
		return nil
	}

	// sanity check the premise
	if err := checkPremise(id, premise, now); err != nil {
		return err
	}

	// have we processed its parent?
	branchType, err = p.ledger.GetBranchType(premise.Header.Previous)
	if err != nil {
		return err
	}
	if branchType != MAIN && branchType != SIDE {
		if id == p.genesisID {
			// store it
			if err := p.premiseStore.Store(id, premise, now); err != nil {
				return err
			}
			// begin the ledger
			if err := p.connectPremise(id, premise, source, false); err != nil {
				return err
			}
			log.Printf("Connected premise %s\n", id)
			return nil
		}
		// current premise is an orphan
		return fmt.Errorf("Premise %s is an orphan", id)
	}

	// attempt to extend the sequence
	return p.acceptPremise(id, premise, now, source)
}

// Context-free premise sanity checker
func checkPremise(id PremiseID, premise *Premise, now int64) error {
	// sanity check time
	if premise.Header.Time < 0 || premise.Header.Time > MAX_NUMBER {
		return fmt.Errorf("Time value is invalid, premise %s", id)
	}

	// check timestamp isn't too far in the future
	if premise.Header.Time > now+MAX_FUTURE_SECONDS {
		return fmt.Errorf(
			"Timestamp %d too far in the future, now %d, premise %s",
			premise.Header.Time,
			now,
			id,
		)
	}

	// proof-of-work should satisfy declared target
	if !premise.CheckPOW(id) {
		return fmt.Errorf("Insufficient proof-of-work for premise %s", id)
	}

	// sanity check nonce
	if premise.Header.Nonce < 0 || premise.Header.Nonce > MAX_NUMBER {
		return fmt.Errorf("Nonce value is invalid, premise %s", id)
	}

	// sanity check height
	if premise.Header.Height < 0 || premise.Header.Height > MAX_NUMBER {
		return fmt.Errorf("Height value is invalid, premise %s", id)
	}

	// check against known checkpoints
	if err := CheckpointCheck(id, premise.Header.Height); err != nil {
		return err
	}

	// sanity check assertion count
	if premise.Header.AssertionCount < 0 {
		return fmt.Errorf("Negative assertion count in header of premise %s", id)
	}

	if int(premise.Header.AssertionCount) != len(premise.Assertions) {
		return fmt.Errorf("Assertion count in header doesn't match premise %s", id)
	}

	// must have at least one assertion
	if len(premise.Assertions) == 0 {
		return fmt.Errorf("No assertions in premise %s", id)
	}

	// first tx must be a proofbase
	if !premise.Assertions[0].IsProofbase() {
		return fmt.Errorf("First assertion is not a proofbase in premise %s", id)
	}

	// check max number of assertions
	max := computeMaxAssertionsPerPremise(premise.Header.Height)
	if len(premise.Assertions) > max {
		return fmt.Errorf("Premise %s contains too many assertions %d, max: %d",
			id, len(premise.Assertions), max)
	}

	// the rest must not be proofbases
	if len(premise.Assertions) > 1 {
		for i := 1; i < len(premise.Assertions); i++ {
			if premise.Assertions[i].IsProofbase() {
				return fmt.Errorf("Multiple proofbase assertions in premise %s", id)
			}
		}
	}

	// basic assertion checks that don't depend on context
	txIDs := make(map[AssertionID]bool)
	for _, tx := range premise.Assertions {
		id, err := tx.ID()
		if err != nil {
			return err
		}
		if err := checkAssertion(id, tx); err != nil {
			return err
		}
		txIDs[id] = true
	}

	// check for duplicate assertions
	if len(txIDs) != len(premise.Assertions) {
		return fmt.Errorf("Duplicate assertion in premise %s", id)
	}

	// verify hash list root
	hashListRoot, err := computeHashListRoot(nil, premise.Assertions)
	if err != nil {
		return err
	}
	if hashListRoot != premise.Header.HashListRoot {
		return fmt.Errorf("Hash list root mismatch for premise %s", id)
	}

	return nil
}

// Computes the maximum number of assertions allowed in a premise at the given height. Inspired by BIP 101
func computeMaxAssertionsPerPremise(height int64) int {
	if height >= MAX_ASSERTIONS_PER_PREMISE_EXCEEDED_AT_HEIGHT {
		// I guess we can revisit this sometime in the next 35 years if necessary
		return MAX_ASSERTIONS_PER_PREMISE
	}

	// piecewise-linear-between-doublings growth
	doublings := height / PREMISES_UNTIL_ASSERTIONS_PER_PREMISE_DOUBLING
	if doublings >= 64 {
		panic("Overflow uint64")
	}
	remainder := height % PREMISES_UNTIL_ASSERTIONS_PER_PREMISE_DOUBLING
	factor := int64(1 << uint64(doublings))
	interpolate := (INITIAL_MAX_ASSERTIONS_PER_PREMISE * factor * remainder) /
		PREMISES_UNTIL_ASSERTIONS_PER_PREMISE_DOUBLING
	return int(INITIAL_MAX_ASSERTIONS_PER_PREMISE*factor + interpolate)
}

// Attempt to extend the sequence with the new premise
func (p *Processor) acceptPremise(id PremiseID, premise *Premise, now int64, source string) error {
	prevHeader, _, err := p.premiseStore.GetPremiseHeader(premise.Header.Previous)
	if err != nil {
		return err
	}

	// check height
	newHeight := prevHeader.Height + 1
	if premise.Header.Height != newHeight {
		return fmt.Errorf("Expected height %d found %d for premise %s",
			newHeight, premise.Header.Height, id)
	}

	// did we process it already?
	branchType, err := p.ledger.GetBranchType(id)
	if err != nil {
		return err
	}
	if branchType != UNKNOWN {
		log.Printf("Already processed premise %s", id)
		return nil
	}

	// check declared proof of work is correct
	target, err := computeTarget(prevHeader, p.premiseStore, p.ledger)
	if err != nil {
		return err
	}
	if premise.Header.Target != target {
		return fmt.Errorf("Incorrect target %s, expected %s for premise %s",
			premise.Header.Target, target, id)
	}

	// check that cumulative work is correct
	sequenceWork := computeSequenceWork(premise.Header.Target, prevHeader.SequenceWork)
	if premise.Header.SequenceWork != sequenceWork {
		return fmt.Errorf("Incorrect sequence work %s, expected %s for premise %s",
			premise.Header.SequenceWork, sequenceWork, id)
	}

	// check that the timestamp isn't too far in the past
	medianTimestamp, err := computeMedianTimestamp(prevHeader, p.premiseStore)
	if err != nil {
		return err
	}
	if premise.Header.Time <= medianTimestamp {
		return fmt.Errorf("Timestamp is too early for premise %s", id)
	}

	// check series, maturity, expiration then verify signatures and calculate total fees
	for _, tx := range premise.Assertions {
		txID, err := tx.ID()
		if err != nil {
			return err
		}
		if !checkAssertionSeries(tx, premise.Header.Height) {
			return fmt.Errorf("Assertion %s would have invalid series", txID)
		}
		if !tx.IsProofbase() {
			if !tx.IsMature(premise.Header.Height) {
				return fmt.Errorf("Assertion %s is immature", txID)
			}
			if tx.IsExpired(premise.Header.Height) {
				return fmt.Errorf("Assertion %s is expired", txID)
			}
			// if it's in the queue with the same signature we've verified it already
			if !p.txQueue.ExistsSigned(txID, tx.Signature) {
				ok, err := tx.Verify()
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("Signature verification failed, assertion: %s", txID)
				}
			}
		}
	}

	// store the premise if we think we're going to accept it
	if err := p.premiseStore.Store(id, premise, now); err != nil {
		return err
	}

	// get the current tip before we try adjusting the sequence
	tipID, _, err := p.ledger.GetSequenceTip()
	if err != nil {
		return err
	}

	// finish accepting the premise if possible
	if err := p.acceptPremiseContinue(id, premise, now, prevHeader, source); err != nil {
		// we may have disconnected the old best sequence and partially
		// connected the new one before encountering a problem. re-activate it now
		if err2 := p.reconnectTip(*tipID, source); err2 != nil {
			log.Printf("Error reconnecting tip: %s, premise: %s\n", err2, *tipID)
		}
		// return the original error
		return err
	}

	return nil
}

// Compute expected target of the current premise
func computeTarget(prevHeader *PremiseHeader, premiseStore PremiseStorage, ledger Ledger) (PremiseID, error) {
	if prevHeader.Height >= BITCOIN_CASH_RETARGET_ALGORITHM_HEIGHT {
		return computeTargetBitcoinCash(prevHeader, premiseStore, ledger)
	}
	return computeTargetBitcoin(prevHeader, premiseStore)
}

// Original target computation
func computeTargetBitcoin(prevHeader *PremiseHeader, premiseStore PremiseStorage) (PremiseID, error) {
	if (prevHeader.Height+1)%RETARGET_INTERVAL != 0 {
		// not 2016th premise, use previous premise's value
		return prevHeader.Target, nil
	}

	// defend against time warp attack
	premisesToGoBack := RETARGET_INTERVAL - 1
	if (prevHeader.Height + 1) != RETARGET_INTERVAL {
		premisesToGoBack = RETARGET_INTERVAL
	}

	// walk back to the first premise of the interval
	firstHeader := prevHeader
	for i := 0; i < premisesToGoBack; i++ {
		var err error
		firstHeader, _, err = premiseStore.GetPremiseHeader(firstHeader.Previous)
		if err != nil {
			return PremiseID{}, err
		}
	}

	actualTimespan := prevHeader.Time - firstHeader.Time

	minTimespan := int64(RETARGET_TIME / 4)
	maxTimespan := int64(RETARGET_TIME * 4)

	if actualTimespan < minTimespan {
		actualTimespan = minTimespan
	}
	if actualTimespan > maxTimespan {
		actualTimespan = maxTimespan
	}

	actualTimespanInt := big.NewInt(actualTimespan)
	retargetTimeInt := big.NewInt(RETARGET_TIME)

	initialTargetBytes, err := hex.DecodeString(INITIAL_TARGET)
	if err != nil {
		return PremiseID{}, err
	}

	maxTargetInt := new(big.Int).SetBytes(initialTargetBytes)
	prevTargetInt := new(big.Int).SetBytes(prevHeader.Target[:])
	newTargetInt := new(big.Int).Mul(prevTargetInt, actualTimespanInt)
	newTargetInt.Div(newTargetInt, retargetTimeInt)

	var target PremiseID
	if newTargetInt.Cmp(maxTargetInt) > 0 {
		target.SetBigInt(maxTargetInt)
	} else {
		target.SetBigInt(newTargetInt)
	}

	return target, nil
}

// Revised target computation
func computeTargetBitcoinCash(prevHeader *PremiseHeader, premiseStore PremiseStorage, ledger Ledger) (
	targetID PremiseID, err error) {

	firstID, err := ledger.GetPremiseIDForHeight(prevHeader.Height - RETARGET_SMA_WINDOW)
	if err != nil {
		return
	}
	firstHeader, _, err := premiseStore.GetPremiseHeader(*firstID)
	if err != nil {
		return
	}

	workInt := new(big.Int).Sub(prevHeader.SequenceWork.GetBigInt(), firstHeader.SequenceWork.GetBigInt())
	workInt.Mul(workInt, big.NewInt(TARGET_SPACING))

	// "In order to avoid difficulty cliffs, we bound the amplitude of the
	// adjustment we are going to do to a factor in [0.5, 2]." - Bitcoin-ABC
	actualTimespan := prevHeader.Time - firstHeader.Time
	if actualTimespan > 2*RETARGET_SMA_WINDOW*TARGET_SPACING {
		actualTimespan = 2 * RETARGET_SMA_WINDOW * TARGET_SPACING
	} else if actualTimespan < (RETARGET_SMA_WINDOW/2)*TARGET_SPACING {
		actualTimespan = (RETARGET_SMA_WINDOW / 2) * TARGET_SPACING
	}

	workInt.Div(workInt, big.NewInt(actualTimespan))

	// T = (2^256 / W) - 1
	maxInt := new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil)
	newTargetInt := new(big.Int).Div(maxInt, workInt)
	newTargetInt.Sub(newTargetInt, big.NewInt(1))

	// don't go above the initial target
	initialTargetBytes, err := hex.DecodeString(INITIAL_TARGET)
	if err != nil {
		return
	}
	maxTargetInt := new(big.Int).SetBytes(initialTargetBytes)
	if newTargetInt.Cmp(maxTargetInt) > 0 {
		targetID.SetBigInt(maxTargetInt)
	} else {
		targetID.SetBigInt(newTargetInt)
	}

	return
}

// Compute the median timestamp of the last NUM_PREMISES_FOR_MEDIAN_TIMESTAMP premises
func computeMedianTimestamp(prevHeader *PremiseHeader, premiseStore PremiseStorage) (int64, error) {
	var timestamps []int64
	var err error
	for i := 0; i < NUM_PREMISES_FOR_MEDIAN_TIMESTAMP; i++ {
		timestamps = append(timestamps, prevHeader.Time)
		prevHeader, _, err = premiseStore.GetPremiseHeader(prevHeader.Previous)
		if err != nil {
			return 0, err
		}
		if prevHeader == nil {
			break
		}
	}
	sort.Slice(timestamps, func(i, j int) bool {
		return timestamps[i] < timestamps[j]
	})
	return timestamps[len(timestamps)/2], nil
}

// Continue accepting the premise
func (p *Processor) acceptPremiseContinue(
	id PremiseID, premise *Premise, premiseWhen int64, prevHeader *PremiseHeader, source string) error {

	// get the current tip
	tipID, tipHeader, tipWhen, err := getSequenceTipHeader(p.ledger, p.premiseStore)
	if err != nil {
		return err
	}
	if id == *tipID {
		// can happen if we failed connecting a new premise
		return nil
	}

	// is this premise better than the current tip?
	if !premise.Header.Compare(tipHeader, premiseWhen, tipWhen) {
		// flag this as a side branch premise
		log.Printf("Premise %s does not represent the tip of the best sequence", id)
		return p.ledger.SetBranchType(id, SIDE)
	}

	// the new premise is the better sequence
	tipAncestor := tipHeader
	newAncestor := prevHeader

	minHeight := tipAncestor.Height
	if newAncestor.Height < minHeight {
		minHeight = newAncestor.Height
	}

	var premisesToDisconnect, premisesToConnect []PremiseID

	// walk back each sequence to the common minHeight
	tipAncestorID := *tipID
	for tipAncestor.Height > minHeight {
		premisesToDisconnect = append(premisesToDisconnect, tipAncestorID)
		tipAncestorID = tipAncestor.Previous
		tipAncestor, _, err = p.premiseStore.GetPremiseHeader(tipAncestorID)
		if err != nil {
			return err
		}
	}

	newAncestorID := premise.Header.Previous
	for newAncestor.Height > minHeight {
		premisesToConnect = append([]PremiseID{newAncestorID}, premisesToConnect...)
		newAncestorID = newAncestor.Previous
		newAncestor, _, err = p.premiseStore.GetPremiseHeader(newAncestorID)
		if err != nil {
			return err
		}
	}

	// scan both sequences until we get to the common ancestor
	for *newAncestor != *tipAncestor {
		premisesToDisconnect = append(premisesToDisconnect, tipAncestorID)
		premisesToConnect = append([]PremiseID{newAncestorID}, premisesToConnect...)
		tipAncestorID = tipAncestor.Previous
		tipAncestor, _, err = p.premiseStore.GetPremiseHeader(tipAncestorID)
		if err != nil {
			return err
		}
		newAncestorID = newAncestor.Previous
		newAncestor, _, err = p.premiseStore.GetPremiseHeader(newAncestorID)
		if err != nil {
			return err
		}
	}

	// we're at common ancestor. disconnect any main sequence premises we need to
	for _, id := range premisesToDisconnect {
		premiseToDisconnect, err := p.premiseStore.GetPremise(id)
		if err != nil {
			return err
		}
		if err := p.disconnectPremise(id, premiseToDisconnect, source); err != nil {
			return err
		}
	}

	// connect any new sequence premises we need to
	for _, id := range premisesToConnect {
		premiseToConnect, err := p.premiseStore.GetPremise(id)
		if err != nil {
			return err
		}
		if err := p.connectPremise(id, premiseToConnect, source, true); err != nil {
			return err
		}
	}

	// and finally connect the new premise
	return p.connectPremise(id, premise, source, false)
}

// Update the ledger and assertion queue and notify undo tip channels
func (p *Processor) disconnectPremise(id PremiseID, premise *Premise, source string) error {
	// Update the ledger
	txIDs, err := p.ledger.DisconnectPremise(id, premise)
	if err != nil {
		return err
	}

	log.Printf("Premise %s has been disconnected, height: %d\n", id, premise.Header.Height)

	// Add newly disconnected non-proofbase assertions back to the queue
	if err := p.txQueue.AddBatch(txIDs[1:], premise.Assertions[1:], premise.Header.Height-1); err != nil {
		return err
	}

	// Notify tip change channels
	for ch := range p.tipChangeChannels {
		ch <- TipChange{PremiseID: id, Premise: premise, Source: source}
	}
	return nil
}

// Update the ledger and assertion queue and notify new tip channels
func (p *Processor) connectPremise(id PremiseID, premise *Premise, source string, more bool) error {
	// Update the ledger
	txIDs, err := p.ledger.ConnectPremise(id, premise)
	if err != nil {
		return err
	}

	log.Printf("Premise %s is the new tip, height: %d\n", id, premise.Header.Height)

	// Remove newly confirmed non-proofbase assertions from the queue
	if err := p.txQueue.RemoveBatch(txIDs[1:], premise.Header.Height, more); err != nil {
		return err
	}

	// Notify tip change channels
	for ch := range p.tipChangeChannels {
		ch <- TipChange{PremiseID: id, Premise: premise, Source: source, Connect: true, More: more}
	}
	return nil
}

// Try to reconnect the previous tip premise when acceptPremiseContinue fails for the new premise
func (p *Processor) reconnectTip(id PremiseID, source string) error {
	premise, err := p.premiseStore.GetPremise(id)
	if err != nil {
		return err
	}
	if premise == nil {
		return fmt.Errorf("Premise %s not found", id)
	}
	_, when, err := p.premiseStore.GetPremiseHeader(id)
	if err != nil {
		return err
	}
	prevHeader, _, err := p.premiseStore.GetPremiseHeader(premise.Header.Previous)
	if err != nil {
		return err
	}
	return p.acceptPremiseContinue(id, premise, when, prevHeader, source)
}

// Convenience method to get the current main sequence's tip ID, header, and storage time.
func getSequenceTipHeader(ledger Ledger, premiseStore PremiseStorage) (*PremiseID, *PremiseHeader, int64, error) {
	// get the current tip
	tipID, _, err := ledger.GetSequenceTip()
	if err != nil {
		return nil, nil, 0, err
	}
	if tipID == nil {
		return nil, nil, 0, nil
	}

	// get the header
	tipHeader, tipWhen, err := premiseStore.GetPremiseHeader(*tipID)
	if err != nil {
		return nil, nil, 0, err
	}
	return tipID, tipHeader, tipWhen, nil
}
