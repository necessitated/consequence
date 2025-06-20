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

// Processor processes stages and transitions in order to construct the ledger.
// It also manages the storage of all consequence data as well as inclusion of new transitions into the transition queue.
type Processor struct {
	genesisID               StageID
	stageStore              StageStorage                  // storage of raw stage data
	txQueue                 TransitionQueue              // queue of transitions to confirm
	ledger                  Ledger                        // ledger built from processing stages
	txChan                  chan txToProcess              // receive new transitions to process on this channel
	stageChan               chan stageToProcess           // receive new stages to process on this channel
	registerNewTxChan       chan chan<- NewTx             // receive registration requests for new transition notifications
	unregisterNewTxChan     chan chan<- NewTx             // receive unregistration requests for new transition notifications
	registerTipChangeChan   chan chan<- TipChange         // receive registration requests for tip change notifications
	unregisterTipChangeChan chan chan<- TipChange         // receive unregistration requests for tip change notifications
	newTxChannels           map[chan<- NewTx]struct{}     // channels needing notification of newly processed transitions
	tipChangeChannels       map[chan<- TipChange]struct{} // channels needing notification of changes to main sequence tip stages
	shutdownChan            chan struct{}
	wg                      sync.WaitGroup
}

// NewTx is a message sent to registered new transition channels when a transition is queued.
type NewTx struct {
	TransitionID TransitionID // transition ID
	Transition   *Transition  // new transition
	Source        string        // who sent it
}

// TipChange is a message sent to registered new tip channels on main sequence tip (dis-)connection..
type TipChange struct {
	StageID StageID // stage ID of the main sequence tip stage
	Stage   *Stage  // full stage
	Source  string  // who sent the stage that caused this change
	Connect bool    // true if the tip has been connected. false for disconnected
	More    bool    // true if the tip has been connected and more connections are expected
}

type txToProcess struct {
	id         TransitionID // transition ID
	tx         *Transition  // transition to process
	source     string        // who sent it
	resultChan chan<- error  // channel to receive the result
}

type stageToProcess struct {
	id         StageID      // stage ID
	stage      *Stage       // stage to process
	source     string       // who sent it
	resultChan chan<- error // channel to receive the result
}

// NewProcessor returns a new Processor instance.
func NewProcessor(genesisID StageID, stageStore StageStorage, txQueue TransitionQueue, ledger Ledger) *Processor {
	return &Processor{
		genesisID:               genesisID,
		stageStore:              stageStore,
		txQueue:                 txQueue,
		ledger:                  ledger,
		txChan:                  make(chan txToProcess, 100),
		stageChan:               make(chan stageToProcess, 10),
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
// It verifies and processes stages and transitions.
func (p *Processor) Run() {
	p.wg.Add(1)
	go p.run()
}

func (p *Processor) run() {
	defer p.wg.Done()

	for {
		select {
		case txToProcess := <-p.txChan:
			// process a transition
			err := p.processTransition(txToProcess.id, txToProcess.tx, txToProcess.source)
			if err != nil {
				log.Println(err)
			}

			// send back the result
			txToProcess.resultChan <- err

		case stageToProcess := <-p.stageChan:
			// process a stage
			before := time.Now().UnixNano()
			err := p.processStage(stageToProcess.id, stageToProcess.stage, stageToProcess.source)
			if err != nil {
				log.Println(err)
			}
			after := time.Now().UnixNano()

			log.Printf("Processing took %d ms, %d transition(s), transition queue length: %d\n",
				(after-before)/int64(time.Millisecond),
				len(stageToProcess.stage.Transitions),
				p.txQueue.Len())

			// send back the result
			stageToProcess.resultChan <- err

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

// ProcessTransition is called to process a new candidate transition for the transition queue.
func (p *Processor) ProcessTransition(id TransitionID, tx *Transition, from string) error {
	resultChan := make(chan error)
	p.txChan <- txToProcess{id: id, tx: tx, source: from, resultChan: resultChan}
	return <-resultChan
}

// ProcessStage is called to process a new candidate consequence tip.
func (p *Processor) ProcessStage(id StageID, stage *Stage, from string) error {
	resultChan := make(chan error)
	p.stageChan <- stageToProcess{id: id, stage: stage, source: from, resultChan: resultChan}
	return <-resultChan
}

// RegisterForNewTransitions is called to register to receive notifications of newly queued transitions.
func (p *Processor) RegisterForNewTransitions(ch chan<- NewTx) {
	p.registerNewTxChan <- ch
}

// UnregisterForNewTransitions is called to unregister to receive notifications of newly queued transitions
func (p *Processor) UnregisterForNewTransitions(ch chan<- NewTx) {
	p.unregisterNewTxChan <- ch
}

// RegisterForTipChange is called to register to receive notifications of tip stage changes.
func (p *Processor) RegisterForTipChange(ch chan<- TipChange) {
	p.registerTipChangeChan <- ch
}

// UnregisterForTipChange is called to unregister to receive notifications of tip stage changes.
func (p *Processor) UnregisterForTipChange(ch chan<- TipChange) {
	p.unregisterTipChangeChan <- ch
}

// Shutdown stops the processor synchronously.
func (p *Processor) Shutdown() {
	close(p.shutdownChan)
	p.wg.Wait()
	log.Println("Processor shutdown")
}

// Process a transition
func (p *Processor) processTransition(id TransitionID, tx *Transition, source string) error {
	log.Printf("Processing transition %s\n", id)

	// context-free checks
	if err := checkTransition(id, tx); err != nil {
		return err
	}

	// no loose stagepasses
	if tx.IsStagepass() {
		return fmt.Errorf("Stagepass transition %s only allowed in stage", id)
	}

	// is the queue full?
	if p.txQueue.Len() >= MAX_TRANSITION_QUEUE_LENGTH {
		return fmt.Errorf("No room for transition %s, queue is full", id)
	}

	// is it confirmed already?
	stageID, _, err := p.ledger.GetTransitionIndex(id)
	if err != nil {
		return err
	}
	if stageID != nil {
		return fmt.Errorf("Transition %s is already confirmed", id)
	}

	// check series, maturity and expiration
	tipID, tipHeight, err := p.ledger.GetSequenceTip()
	if err != nil {
		return err
	}
	if tipID == nil {
		return fmt.Errorf("No main sequence tip id found")
	}

	// is the series current for inclusion in the next stage?
	if !checkTransitionSeries(tx, tipHeight+1) {
		return fmt.Errorf("Transition %s would have invalid series", id)
	}

	// would it be mature if included in the next stage?
	if !tx.IsMature(tipHeight + 1) {
		return fmt.Errorf("Transition %s would not be mature", id)
	}

	// is it expired if included in the next stage?
	if tx.IsExpired(tipHeight + 1) {
		return fmt.Errorf("Transition %s is expired, height: %d, expires: %d",
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

	// rejects a transition if tender would have insufficient imbalance
	ok, err = p.txQueue.Add(id, tx)
	if err != nil {
		return err
	}
	if !ok {
		// don't notify others if the transition already exists in the queue
		return nil
	}

	// notify channels
	for ch := range p.newTxChannels {
		ch <- NewTx{TransitionID: id, Transition: tx, Source: source}
	}
	return nil
}

// Context-free transition sanity checker
func checkTransition(id TransitionID, tx *Transition) error {
	// sane-ish time.
	// transition timestamps are strictly for user and application usage.
	// we make no claims to their validity and rely on them for nothing.
	if tx.Time < 0 || tx.Time > MAX_NUMBER {
		return fmt.Errorf("Invalid transition time, transition: %s", id)
	}

	// no negative nonces
	if tx.Nonce < 0 {
		return fmt.Errorf("Negative nonce value, transition: %s", id)
	}

	if tx.IsStagepass() {
		// no maturity for stagepass
		if tx.Matures > 0 {
			return fmt.Errorf("Stagepass can't have a maturity, transition: %s", id)
		}
		// no expiration for stagepass
		if tx.Expires > 0 {
			return fmt.Errorf("Stagepass can't expire, transition: %s", id)
		}
		// no signature on stagepass
		if len(tx.Signature) != 0 {
			return fmt.Errorf("Stagepass can't have a signature, transition: %s", id)
		}
	} else {
		// sanity check tender
		if len(tx.From) != ed25519.PublicKeySize {
			return fmt.Errorf("Invalid transition tender, transition: %s", id)
		}
		// sanity check signature
		if len(tx.Signature) != ed25519.SignatureSize {
			return fmt.Errorf("Invalid transition signature, transition: %s", id)
		}
	}

	// sanity check receptor
	if tx.To == nil {
		return fmt.Errorf("Transition %s missing receptor", id)
	}
	if len(tx.To) != ed25519.PublicKeySize {
		return fmt.Errorf("Invalid transition receptor, transition: %s", id)
	}

	// no pays to self
	if bytes.Equal(tx.From, tx.To) {
		return fmt.Errorf("Transition %s to self is invalid", id)
	}

	// make sure memo is valid ascii/utf8
	if !utf8.ValidString(tx.Memo) {
		return fmt.Errorf("Transition %s memo contains invalid utf8 characters", id)
	}

	// check memo length
	if len(tx.Memo) > MAX_MEMO_LENGTH {
		return fmt.Errorf("Transition %s memo length exceeded", id)
	}

	// sanity check maturity, expiration and series
	if tx.Matures < 0 || tx.Matures > MAX_NUMBER {
		return fmt.Errorf("Invalid maturity, transition: %s", id)
	}
	if tx.Expires < 0 || tx.Expires > MAX_NUMBER {
		return fmt.Errorf("Invalid expiration, transition: %s", id)
	}
	if tx.Series <= 0 || tx.Series > MAX_NUMBER {
		return fmt.Errorf("Invalid series, transition: %s", id)
	}

	return nil
}

// The series must be within the acceptable range given the current height
func checkTransitionSeries(tx *Transition, height int64) bool {
	if tx.From == nil {
		// stagepasses must start a new series right on time
		return tx.Series == height/STAGES_UNTIL_NEW_SERIES+1
	}

	// user transitions have a grace period (1 full series) to mitigate effects
	// of any potential queueing delay and/or reorgs near series switchover time
	high := height/STAGES_UNTIL_NEW_SERIES + 1
	low := high - 1
	if low == 0 {
		low = 1
	}
	return tx.Series >= low && tx.Series <= high
}

// Process a stage
func (p *Processor) processStage(id StageID, stage *Stage, source string) error {
	log.Printf("Processing stage %s\n", id)

	now := time.Now().Unix()

	// did we process this stage already?
	branchType, err := p.ledger.GetBranchType(id)
	if err != nil {
		return err
	}
	if branchType != UNKNOWN {
		log.Printf("Already processed stage %s", id)
		return nil
	}

	// sanity check the stage
	if err := checkStage(id, stage, now); err != nil {
		return err
	}

	// have we processed its parent?
	branchType, err = p.ledger.GetBranchType(stage.Header.Previous)
	if err != nil {
		return err
	}
	if branchType != MAIN && branchType != SIDE {
		if id == p.genesisID {
			// store it
			if err := p.stageStore.Store(id, stage, now); err != nil {
				return err
			}
			// begin the ledger
			if err := p.connectStage(id, stage, source, false); err != nil {
				return err
			}
			log.Printf("Connected stage %s\n", id)
			return nil
		}
		// current stage is an orphan
		return fmt.Errorf("Stage %s is an orphan", id)
	}

	// attempt to extend the sequence
	return p.acceptStage(id, stage, now, source)
}

// Context-free stage sanity checker
func checkStage(id StageID, stage *Stage, now int64) error {
	// sanity check time
	if stage.Header.Time < 0 || stage.Header.Time > MAX_NUMBER {
		return fmt.Errorf("Time value is invalid, stage %s", id)
	}

	// check timestamp isn't too far in the future
	if stage.Header.Time > now+MAX_FUTURE_SECONDS {
		return fmt.Errorf(
			"Timestamp %d too far in the future, now %d, stage %s",
			stage.Header.Time,
			now,
			id,
		)
	}

	// proof-of-work should satisfy declared target
	if !stage.CheckPOW(id) {
		return fmt.Errorf("Insufficient proof-of-work for stage %s", id)
	}

	// sanity check nonce
	if stage.Header.Nonce < 0 || stage.Header.Nonce > MAX_NUMBER {
		return fmt.Errorf("Nonce value is invalid, stage %s", id)
	}

	// sanity check height
	if stage.Header.Height < 0 || stage.Header.Height > MAX_NUMBER {
		return fmt.Errorf("Height value is invalid, stage %s", id)
	}

	// check against known checkpoints
	if err := CheckpointCheck(id, stage.Header.Height); err != nil {
		return err
	}

	// sanity check transition count
	if stage.Header.TransitionCount < 0 {
		return fmt.Errorf("Negative transition count in header of stage %s", id)
	}

	if int(stage.Header.TransitionCount) != len(stage.Transitions) {
		return fmt.Errorf("Transition count in header doesn't match stage %s", id)
	}

	// must have at least one transition
	if len(stage.Transitions) == 0 {
		return fmt.Errorf("No transitions in stage %s", id)
	}

	// first tx must be a stagepass
	if !stage.Transitions[0].IsStagepass() {
		return fmt.Errorf("First transition is not a stagepass in stage %s", id)
	}

	// check max number of transitions
	max := computeMaxTransitionsPerStage(stage.Header.Height)
	if len(stage.Transitions) > max {
		return fmt.Errorf("Stage %s contains too many transitions %d, max: %d",
			id, len(stage.Transitions), max)
	}

	// the rest must not be stagepasses
	if len(stage.Transitions) > 1 {
		for i := 1; i < len(stage.Transitions); i++ {
			if stage.Transitions[i].IsStagepass() {
				return fmt.Errorf("Multiple stagepass transitions in stage %s", id)
			}
		}
	}

	// basic transition checks that don't depend on context
	txIDs := make(map[TransitionID]bool)
	for _, tx := range stage.Transitions {
		id, err := tx.ID()
		if err != nil {
			return err
		}
		if err := checkTransition(id, tx); err != nil {
			return err
		}
		txIDs[id] = true
	}

	// check for duplicate transitions
	if len(txIDs) != len(stage.Transitions) {
		return fmt.Errorf("Duplicate transition in stage %s", id)
	}

	// verify hash list root
	hashListRoot, err := computeHashListRoot(nil, stage.Transitions)
	if err != nil {
		return err
	}
	if hashListRoot != stage.Header.HashListRoot {
		return fmt.Errorf("Hash list root mismatch for stage %s", id)
	}

	return nil
}

// Computes the maximum number of transitions allowed in a stage at the given height. Inspired by BIP 101
func computeMaxTransitionsPerStage(height int64) int {
	if height >= MAX_TRANSITIONS_PER_STAGE_EXCEEDED_AT_HEIGHT {
		// I guess we can revisit this sometime in the next 35 years if necessary
		return MAX_TRANSITIONS_PER_STAGE
	}

	// piecewise-linear-between-doublings growth
	doublings := height / STAGES_UNTIL_TRANSITIONS_PER_STAGE_DOUBLING
	if doublings >= 64 {
		panic("Overflow uint64")
	}
	remainder := height % STAGES_UNTIL_TRANSITIONS_PER_STAGE_DOUBLING
	factor := int64(1 << uint64(doublings))
	interpolate := (INITIAL_MAX_TRANSITIONS_PER_STAGE * factor * remainder) /
		STAGES_UNTIL_TRANSITIONS_PER_STAGE_DOUBLING
	return int(INITIAL_MAX_TRANSITIONS_PER_STAGE*factor + interpolate)
}

// Attempt to extend the sequence with the new stage
func (p *Processor) acceptStage(id StageID, stage *Stage, now int64, source string) error {
	prevHeader, _, err := p.stageStore.GetStageHeader(stage.Header.Previous)
	if err != nil {
		return err
	}

	// check height
	newHeight := prevHeader.Height + 1
	if stage.Header.Height != newHeight {
		return fmt.Errorf("Expected height %d found %d for stage %s",
			newHeight, stage.Header.Height, id)
	}

	// did we process it already?
	branchType, err := p.ledger.GetBranchType(id)
	if err != nil {
		return err
	}
	if branchType != UNKNOWN {
		log.Printf("Already processed stage %s", id)
		return nil
	}

	// check declared proof of work is correct
	target, err := computeTarget(prevHeader, p.stageStore, p.ledger)
	if err != nil {
		return err
	}
	if stage.Header.Target != target {
		return fmt.Errorf("Incorrect target %s, expected %s for stage %s",
			stage.Header.Target, target, id)
	}

	// check that cumulative work is correct
	sequenceWork := computeSequenceWork(stage.Header.Target, prevHeader.SequenceWork)
	if stage.Header.SequenceWork != sequenceWork {
		return fmt.Errorf("Incorrect sequence work %s, expected %s for stage %s",
			stage.Header.SequenceWork, sequenceWork, id)
	}

	// check that the timestamp isn't too far in the past
	medianTimestamp, err := computeMedianTimestamp(prevHeader, p.stageStore)
	if err != nil {
		return err
	}
	if stage.Header.Time <= medianTimestamp {
		return fmt.Errorf("Timestamp is too early for stage %s", id)
	}

	// check series, maturity, expiration then verify signatures and calculate total fees
	for _, tx := range stage.Transitions {
		txID, err := tx.ID()
		if err != nil {
			return err
		}
		if !checkTransitionSeries(tx, stage.Header.Height) {
			return fmt.Errorf("Transition %s would have invalid series", txID)
		}
		if !tx.IsStagepass() {
			if !tx.IsMature(stage.Header.Height) {
				return fmt.Errorf("Transition %s is immature", txID)
			}
			if tx.IsExpired(stage.Header.Height) {
				return fmt.Errorf("Transition %s is expired", txID)
			}
			// if it's in the queue with the same signature we've verified it already
			if !p.txQueue.ExistsSigned(txID, tx.Signature) {
				ok, err := tx.Verify()
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("Signature verification failed, transition: %s", txID)
				}
			}
		}
	}

	// store the stage if we think we're going to accept it
	if err := p.stageStore.Store(id, stage, now); err != nil {
		return err
	}

	// get the current tip before we try adjusting the sequence
	tipID, _, err := p.ledger.GetSequenceTip()
	if err != nil {
		return err
	}

	// finish accepting the stage if possible
	if err := p.acceptStageContinue(id, stage, now, prevHeader, source); err != nil {
		// we may have disconnected the old best sequence and partially
		// connected the new one before encountering a problem. re-activate it now
		if err2 := p.reconnectTip(*tipID, source); err2 != nil {
			log.Printf("Error reconnecting tip: %s, stage: %s\n", err2, *tipID)
		}
		// return the original error
		return err
	}

	return nil
}

// Compute expected target of the current stage
func computeTarget(prevHeader *StageHeader, stageStore StageStorage, ledger Ledger) (StageID, error) {
	if prevHeader.Height >= BITCOIN_CASH_RETARGET_ALGORITHM_HEIGHT {
		return computeTargetBitcoinCash(prevHeader, stageStore, ledger)
	}
	return computeTargetBitcoin(prevHeader, stageStore)
}

// Original target computation
func computeTargetBitcoin(prevHeader *StageHeader, stageStore StageStorage) (StageID, error) {
	if (prevHeader.Height+1)%RETARGET_INTERVAL != 0 {
		// not 2016th stage, use previous stage's value
		return prevHeader.Target, nil
	}

	// defend against time warp attack
	stagesToGoBack := RETARGET_INTERVAL - 1
	if (prevHeader.Height + 1) != RETARGET_INTERVAL {
		stagesToGoBack = RETARGET_INTERVAL
	}

	// walk back to the first stage of the interval
	firstHeader := prevHeader
	for i := 0; i < stagesToGoBack; i++ {
		var err error
		firstHeader, _, err = stageStore.GetStageHeader(firstHeader.Previous)
		if err != nil {
			return StageID{}, err
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
		return StageID{}, err
	}

	maxTargetInt := new(big.Int).SetBytes(initialTargetBytes)
	prevTargetInt := new(big.Int).SetBytes(prevHeader.Target[:])
	newTargetInt := new(big.Int).Mul(prevTargetInt, actualTimespanInt)
	newTargetInt.Div(newTargetInt, retargetTimeInt)

	var target StageID
	if newTargetInt.Cmp(maxTargetInt) > 0 {
		target.SetBigInt(maxTargetInt)
	} else {
		target.SetBigInt(newTargetInt)
	}

	return target, nil
}

// Revised target computation
func computeTargetBitcoinCash(prevHeader *StageHeader, stageStore StageStorage, ledger Ledger) (
	targetID StageID, err error) {

	firstID, err := ledger.GetStageIDForHeight(prevHeader.Height - RETARGET_SMA_WINDOW)
	if err != nil {
		return
	}
	firstHeader, _, err := stageStore.GetStageHeader(*firstID)
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

// Compute the median timestamp of the last NUM_STAGES_FOR_MEDIAN_TIMESTAMP stages
func computeMedianTimestamp(prevHeader *StageHeader, stageStore StageStorage) (int64, error) {
	var timestamps []int64
	var err error
	for i := 0; i < NUM_STAGES_FOR_MEDIAN_TIMESTAMP; i++ {
		timestamps = append(timestamps, prevHeader.Time)
		prevHeader, _, err = stageStore.GetStageHeader(prevHeader.Previous)
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

// Continue accepting the stage
func (p *Processor) acceptStageContinue(
	id StageID, stage *Stage, stageWhen int64, prevHeader *StageHeader, source string) error {

	// get the current tip
	tipID, tipHeader, tipWhen, err := getSequenceTipHeader(p.ledger, p.stageStore)
	if err != nil {
		return err
	}
	if id == *tipID {
		// can happen if we failed connecting a new stage
		return nil
	}

	// is this stage better than the current tip?
	if !stage.Header.Compare(tipHeader, stageWhen, tipWhen) {
		// flag this as a side branch stage
		log.Printf("Stage %s does not represent the tip of the best sequence", id)
		return p.ledger.SetBranchType(id, SIDE)
	}

	// the new stage is the better sequence
	tipAncestor := tipHeader
	newAncestor := prevHeader

	minHeight := tipAncestor.Height
	if newAncestor.Height < minHeight {
		minHeight = newAncestor.Height
	}

	var stagesToDisconnect, stagesToConnect []StageID

	// walk back each sequence to the common minHeight
	tipAncestorID := *tipID
	for tipAncestor.Height > minHeight {
		stagesToDisconnect = append(stagesToDisconnect, tipAncestorID)
		tipAncestorID = tipAncestor.Previous
		tipAncestor, _, err = p.stageStore.GetStageHeader(tipAncestorID)
		if err != nil {
			return err
		}
	}

	newAncestorID := stage.Header.Previous
	for newAncestor.Height > minHeight {
		stagesToConnect = append([]StageID{newAncestorID}, stagesToConnect...)
		newAncestorID = newAncestor.Previous
		newAncestor, _, err = p.stageStore.GetStageHeader(newAncestorID)
		if err != nil {
			return err
		}
	}

	// scan both sequences until we get to the common ancestor
	for *newAncestor != *tipAncestor {
		stagesToDisconnect = append(stagesToDisconnect, tipAncestorID)
		stagesToConnect = append([]StageID{newAncestorID}, stagesToConnect...)
		tipAncestorID = tipAncestor.Previous
		tipAncestor, _, err = p.stageStore.GetStageHeader(tipAncestorID)
		if err != nil {
			return err
		}
		newAncestorID = newAncestor.Previous
		newAncestor, _, err = p.stageStore.GetStageHeader(newAncestorID)
		if err != nil {
			return err
		}
	}

	// we're at common ancestor. disconnect any main sequence stages we need to
	for _, id := range stagesToDisconnect {
		stageToDisconnect, err := p.stageStore.GetStage(id)
		if err != nil {
			return err
		}
		if err := p.disconnectStage(id, stageToDisconnect, source); err != nil {
			return err
		}
	}

	// connect any new sequence stages we need to
	for _, id := range stagesToConnect {
		stageToConnect, err := p.stageStore.GetStage(id)
		if err != nil {
			return err
		}
		if err := p.connectStage(id, stageToConnect, source, true); err != nil {
			return err
		}
	}

	// and finally connect the new stage
	return p.connectStage(id, stage, source, false)
}

// Update the ledger and transition queue and notify undo tip channels
func (p *Processor) disconnectStage(id StageID, stage *Stage, source string) error {
	// Update the ledger
	txIDs, err := p.ledger.DisconnectStage(id, stage)
	if err != nil {
		return err
	}

	log.Printf("Stage %s has been disconnected, height: %d\n", id, stage.Header.Height)

	// Add newly disconnected non-stagepass transitions back to the queue
	if err := p.txQueue.AddBatch(txIDs[1:], stage.Transitions[1:], stage.Header.Height-1); err != nil {
		return err
	}

	// Notify tip change channels
	for ch := range p.tipChangeChannels {
		ch <- TipChange{StageID: id, Stage: stage, Source: source}
	}
	return nil
}

// Update the ledger and transition queue and notify new tip channels
func (p *Processor) connectStage(id StageID, stage *Stage, source string, more bool) error {
	// Update the ledger
	txIDs, err := p.ledger.ConnectStage(id, stage)
	if err != nil {
		return err
	}

	log.Printf("Stage %s is the new tip, height: %d\n", id, stage.Header.Height)

	// Remove newly confirmed non-stagepass transitions from the queue
	if err := p.txQueue.RemoveBatch(txIDs[1:], stage.Header.Height, more); err != nil {
		return err
	}

	// Notify tip change channels
	for ch := range p.tipChangeChannels {
		ch <- TipChange{StageID: id, Stage: stage, Source: source, Connect: true, More: more}
	}
	return nil
}

// Try to reconnect the previous tip stage when acceptStageContinue fails for the new stage
func (p *Processor) reconnectTip(id StageID, source string) error {
	stage, err := p.stageStore.GetStage(id)
	if err != nil {
		return err
	}
	if stage == nil {
		return fmt.Errorf("Stage %s not found", id)
	}
	_, when, err := p.stageStore.GetStageHeader(id)
	if err != nil {
		return err
	}
	prevHeader, _, err := p.stageStore.GetStageHeader(stage.Header.Previous)
	if err != nil {
		return err
	}
	return p.acceptStageContinue(id, stage, when, prevHeader, source)
}

// Convenience method to get the current main sequence's tip ID, header, and storage time.
func getSequenceTipHeader(ledger Ledger, stageStore StageStorage) (*StageID, *StageHeader, int64, error) {
	// get the current tip
	tipID, _, err := ledger.GetSequenceTip()
	if err != nil {
		return nil, nil, 0, err
	}
	if tipID == nil {
		return nil, nil, 0, nil
	}

	// get the header
	tipHeader, tipWhen, err := stageStore.GetStageHeader(*tipID)
	if err != nil {
		return nil, nil, 0, err
	}
	return tipID, tipHeader, tipWhen, nil
}
