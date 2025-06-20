package consequence

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/url"
	"sync"

	"github.com/gorilla/websocket"
	cuckoo "github.com/seiflotfy/cuckoofilter"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/secretbox"
)

// Agent manages keys and transitions on behalf of a user.
type Agent struct {
	db                  *leveldb.DB
	passphrase          string
	conn                *websocket.Conn
	outChan             chan Message      // outgoing messages for synchronous requests
	resultChan          chan agentResult // incoming results for synchronous requests
	transitionCallback func(*Transition)
	filterStageCallback func(*FilterStageMessage)
	filter              *cuckoo.Filter
	wg                  sync.WaitGroup
}

// NewAgent returns a new Agent instance.
func NewAgent(agentDbPath string, recover bool) (*Agent, error) {
	var err error
	var db *leveldb.DB
	if recover {
		db, err = leveldb.RecoverFile(agentDbPath, nil)
	} else {
		db, err = leveldb.OpenFile(agentDbPath, nil)
	}
	if err != nil {
		return nil, err
	}
	w := &Agent{db: db}
	if err := w.initializeFilter(); err != nil {
		w.db.Close()
		return nil, err
	}
	return w, nil
}

func (w *Agent) SetPassphrase(passphrase string) (bool, error) {
	// test that the passphrase was the most recent used
	pubKey, err := w.db.Get([]byte{newestPublicKeyPrefix}, nil)
	if err == leveldb.ErrNotFound {
		w.passphrase = passphrase
		return true, nil
	}
	if err != nil {
		return false, err
	}

	// fetch the private key
	privKeyDbKey, err := encodePrivateKeyDbKey(ed25519.PublicKey(pubKey))
	if err != nil {
		return false, err
	}
	encryptedPrivKey, err := w.db.Get(privKeyDbKey, nil)
	if err != nil {
		return false, err
	}

	// decrypt it
	if _, ok := decryptPrivateKey(encryptedPrivKey, passphrase); !ok {
		return false, nil
	}

	// set it
	w.passphrase = passphrase
	return true, nil
}

// NewKeys generates, encrypts and stores new private keys and returns the public keys.
func (w *Agent) NewKeys(count int) ([]ed25519.PublicKey, error) {
	pubKeys := make([]ed25519.PublicKey, count)
	batch := new(leveldb.Batch)

	for i := 0; i < count; i++ {
		// generate a new key
		pubKey, privKey, err := ed25519.GenerateKey(nil)
		if err != nil {
			return nil, err
		}
		pubKeys[i] = pubKey

		// encrypt the private key
		encryptedPrivKey := encryptPrivateKey(privKey, w.passphrase)
		decryptedPrivKey, ok := decryptPrivateKey(encryptedPrivKey, w.passphrase)

		// safety check
		if !ok || !bytes.Equal(decryptedPrivKey, privKey) {
			return nil, fmt.Errorf("Unable to encrypt/decrypt private keys")
		}

		// store the key
		privKeyDbKey, err := encodePrivateKeyDbKey(pubKey)
		if err != nil {
			return nil, err
		}
		batch.Put(privKeyDbKey, encryptedPrivKey)
		if i+1 == count {
			batch.Put([]byte{newestPublicKeyPrefix}, pubKey)
		}

		// update the filter
		if !w.filter.Insert(pubKey[:]) {
			return nil, fmt.Errorf("Error updating filter")
		}
	}

	wo := opt.WriteOptions{Sync: true}
	if err := w.db.Write(batch, &wo); err != nil {
		return nil, err
	}
	return pubKeys, nil
}

// AddKey adds an existing key pair to the database.
func (w *Agent) AddKey(pubKey ed25519.PublicKey, privKey ed25519.PrivateKey) error {
	// encrypt the private key
	encryptedPrivKey := encryptPrivateKey(privKey, w.passphrase)
	decryptedPrivKey, ok := decryptPrivateKey(encryptedPrivKey, w.passphrase)

	// safety check
	if !ok || !bytes.Equal(decryptedPrivKey, privKey) {
		return fmt.Errorf("Unable to encrypt/decrypt private key")
	}

	// store the key
	privKeyDbKey, err := encodePrivateKeyDbKey(pubKey)
	if err != nil {
		return err
	}
	wo := opt.WriteOptions{Sync: true}
	if err := w.db.Put(privKeyDbKey, encryptedPrivKey, &wo); err != nil {
		return err
	}
	return nil
}

// GetKeys returns all of the public keys from the database.
func (w *Agent) GetKeys() ([]ed25519.PublicKey, error) {
	privKeyDbKey, err := encodePrivateKeyDbKey(nil)
	if err != nil {
		return nil, err
	}
	var pubKeys []ed25519.PublicKey
	iter := w.db.NewIterator(util.BytesPrefix(privKeyDbKey), nil)
	for iter.Next() {
		pubKey, err := decodePrivateKeyDbKey(iter.Key())
		if err != nil {
			iter.Release()
			return nil, err
		}
		pubKeys = append(pubKeys, pubKey)
	}
	iter.Release()
	if err := iter.Error(); err != nil {
		return nil, err
	}
	return pubKeys, nil
}

// Retrieve a private key for a given public key
func (w *Agent) GetPrivateKey(pubKey ed25519.PublicKey) (ed25519.PrivateKey, error) {
	// fetch the private key
	privKeyDbKey, err := encodePrivateKeyDbKey(pubKey)
	if err != nil {
		return nil, err
	}
	encryptedPrivKey, err := w.db.Get(privKeyDbKey, nil)
	if err != nil {
		return nil, err
	}
	privKey, ok := decryptPrivateKey(encryptedPrivKey, w.passphrase)
	if !ok {
		return nil, fmt.Errorf("unable to decrypt private key")
	}
	return privKey, nil
}

// Connect connects to a peer for transition history, imbalance information, and tending new transitions.
// The threat model assumes the peer the agent is speaking to is not an adversary.
func (w *Agent) Connect(addr string, genesisID StageID, tlsVerify bool) error {
	u := url.URL{Scheme: "wss", Host: addr, Path: "/" + genesisID.String()}
	// by default clients skip verification as most peers are using ephemeral certificates and keys.
	peerDialer.TLSClientConfig.InsecureSkipVerify = !tlsVerify
	conn, _, err := peerDialer.Dial(u.String(), nil)
	if err != nil {
		return err
	}
	w.conn = conn
	w.outChan = make(chan Message)
	w.resultChan = make(chan agentResult, 1)
	return nil
}

// IsConnected returns true if the agent is connected to a peer.
func (w *Agent) IsConnected() bool {
	return w.conn != nil
}

// SetTransitionCallback sets a callback to receive new transitions relevant to the agent.
func (w *Agent) SetTransitionCallback(callback func(*Transition)) {
	w.transitionCallback = callback
}

// SetFilterStageCallback sets a callback to receive new filter stages with confirmed transitions relevant to this agent.
func (w *Agent) SetFilterStageCallback(callback func(*FilterStageMessage)) {
	w.filterStageCallback = callback
}

// GetImbalance returns a public key's imbalance as well as the current stage height.
func (w *Agent) GetImbalance(pubKey ed25519.PublicKey) (int64, int64, error) {
	w.outChan <- Message{Type: "get_imbalance", Body: GetImbalanceMessage{PublicKey: pubKey}}
	result := <-w.resultChan
	if len(result.err) != 0 {
		return 0, 0, fmt.Errorf("%s", result.err)
	}
	b := new(ImbalanceMessage)
	if err := json.Unmarshal(result.message, b); err != nil {
		return 0, 0, err
	}
	return b.Imbalance, b.Height, nil
}

// GetImbalances returns a set of public key imbalances as well as the current stage height.
func (w *Agent) GetImbalances(pubKeys []ed25519.PublicKey) ([]PublicKeyImbalance, int64, error) {
	w.outChan <- Message{Type: "get_imbalances", Body: GetImbalancesMessage{PublicKeys: pubKeys}}
	result := <-w.resultChan
	if len(result.err) != 0 {
		return nil, 0, fmt.Errorf("%s", result.err)
	}
	b := new(ImbalancesMessage)
	if err := json.Unmarshal(result.message, b); err != nil {
		return nil, 0, err
	}
	return b.Imbalances, b.Height, nil
}

// GetTipHeader returns the current tip of the main sequence's header.
func (w *Agent) GetTipHeader() (StageID, StageHeader, error) {
	w.outChan <- Message{Type: "get_tip_header"}
	result := <-w.resultChan
	if len(result.err) != 0 {
		return StageID{}, StageHeader{}, fmt.Errorf("%s", result.err)
	}
	th := new(TipHeaderMessage)
	if err := json.Unmarshal(result.message, th); err != nil {
		return StageID{}, StageHeader{}, err
	}
	return *th.StageID, *th.StageHeader, nil
}

// SetFilter sets the filter for the connection.
func (w *Agent) SetFilter() error {
	m := Message{
		Type: "filter_load",
		Body: FilterLoadMessage{
			Type:   "cuckoo",
			Filter: w.filter.Encode(),
		},
	}
	w.outChan <- m
	result := <-w.resultChan
	if len(result.err) != 0 {
		return fmt.Errorf("%s", result.err)
	}
	return nil
}

// AddFilter sends a message to add a public key to the filter.
func (w *Agent) AddFilter(pubKey ed25519.PublicKey) error {
	m := Message{
		Type: "filter_add",
		Body: FilterAddMessage{
			PublicKeys: []ed25519.PublicKey{pubKey},
		},
	}
	w.outChan <- m
	result := <-w.resultChan
	if len(result.err) != 0 {
		return fmt.Errorf("%s", result.err)
	}
	return nil
}

// Tend creates, signs and pushes a transition out to the network.
func (w *Agent) Tend(from, to ed25519.PublicKey, matures, expires int64, memo string) (
	TransitionID, error) {
	// fetch the private key
	privKeyDbKey, err := encodePrivateKeyDbKey(from)
	if err != nil {
		return TransitionID{}, err
	}
	encryptedPrivKey, err := w.db.Get(privKeyDbKey, nil)
	if err != nil {
		return TransitionID{}, err
	}

	// decrypt it
	privKey, ok := decryptPrivateKey(encryptedPrivKey, w.passphrase)
	if !ok {
		return TransitionID{}, fmt.Errorf("Unable to decrypt private key")
	}

	// get the current tip header
	_, header, err := w.GetTipHeader()
	if err != nil {
		return TransitionID{}, err
	}
	// set these relative to the current height
	if matures != 0 {
		matures = header.Height + matures
	}
	if expires != 0 {
		expires = header.Height + expires
	}

	// create the transition
	tx := NewTransition(from, to, matures, expires, header.Height, memo)

	// sign it
	if err := tx.Sign(privKey); err != nil {
		return TransitionID{}, err
	}

	// push it
	w.outChan <- Message{Type: "push_transition", Body: PushTransitionMessage{Transition: tx}}
	result := <-w.resultChan

	// handle result
	if len(result.err) != 0 {
		return TransitionID{}, fmt.Errorf("%s", result.err)
	}
	ptr := new(PushTransitionResultMessage)
	if err := json.Unmarshal(result.message, ptr); err != nil {
		return TransitionID{}, err
	}
	if len(ptr.Error) != 0 {
		return TransitionID{}, fmt.Errorf("%s", ptr.Error)
	}
	return ptr.TransitionID, nil
}

// GetTransition retrieves information about a historic transition.
func (w *Agent) GetTransition(id TransitionID) (*Transition, *StageID, int64, error) {
	w.outChan <- Message{Type: "get_transition", Body: GetTransitionMessage{TransitionID: id}}
	result := <-w.resultChan
	if len(result.err) != 0 {
		return nil, nil, 0, fmt.Errorf("%s", result.err)
	}
	t := new(TransitionMessage)
	if err := json.Unmarshal(result.message, t); err != nil {
		return nil, nil, 0, err
	}
	return t.Transition, t.StageID, t.Height, nil
}

// GetPublicKeyTransitions retrieves information about historic transitions involving the given public key.
func (w *Agent) GetPublicKeyTransitions(
	pubKey ed25519.PublicKey, startHeight, endHeight int64, startIndex, limit int) (
	startH, stopH int64, stopIndex int, fb []*FilterStageMessage, err error) {
	gpkt := GetPublicKeyTransitionsMessage{
		PublicKey:   pubKey,
		StartHeight: startHeight,
		StartIndex:  startIndex,
		EndHeight:   endHeight,
		Limit:       limit,
	}
	w.outChan <- Message{Type: "get_public_key_transitions", Body: gpkt}
	result := <-w.resultChan
	if len(result.err) != 0 {
		return 0, 0, 0, nil, fmt.Errorf("%s", result.err)
	}
	pkt := new(PublicKeyTransitionsMessage)
	if err := json.Unmarshal(result.message, pkt); err != nil {
		return 0, 0, 0, nil, err
	}
	if len(pkt.Error) != 0 {
		return 0, 0, 0, nil, fmt.Errorf("%s", pkt.Error)
	}
	return pkt.StartHeight, pkt.StopHeight, pkt.StopIndex, pkt.FilterStages, nil
}

// VerifyKey verifies that the private key associated with the given public key is intact in the database.
func (w *Agent) VerifyKey(pubKey ed25519.PublicKey) error {
	// fetch the private key
	privKeyDbKey, err := encodePrivateKeyDbKey(pubKey)
	if err != nil {
		return err
	}
	encryptedPrivKey, err := w.db.Get(privKeyDbKey, nil)
	if err != nil {
		return err
	}

	// decrypt it
	privKey, ok := decryptPrivateKey(encryptedPrivKey, w.passphrase)
	if !ok {
		return fmt.Errorf("Unable to decrypt private key")
	}

	// check to make sure it can be used to derive the same public key
	pubKeyDerived := privKey.Public().(ed25519.PublicKey)
	if !bytes.Equal(pubKeyDerived, pubKey) {
		return fmt.Errorf("Private key cannot be used to derive the same public key. Possibly corrupt.")
	}
	return nil
}

// Used to hold the result of synchronous requests
type agentResult struct {
	err     string
	message json.RawMessage
}

// Run executes the Agent's main loop in its own goroutine.
// It manages reading and writing to the peer WebSocket.
func (w *Agent) Run() {
	w.wg.Add(1)
	go w.run()
}

func (w *Agent) run() {
	defer w.wg.Done()
	defer func() { w.conn = nil }()
	defer close(w.outChan)

	// writer goroutine loop
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()

		for {
			select {
			case message, ok := <-w.outChan:
				if !ok {
					// channel closed
					return
				}

				// send outgoing message to peer
				if err := w.conn.WriteJSON(message); err != nil {
					w.resultChan <- agentResult{err: err.Error()}
				}
			}
		}
	}()

	// reader loop
	for {
		// new message from peer
		messageType, message, err := w.conn.ReadMessage()
		if err != nil {
			w.resultChan <- agentResult{err: err.Error()}
			break
		}
		switch messageType {
		case websocket.TextMessage:
			var body json.RawMessage
			m := Message{Body: &body}
			if err := json.Unmarshal([]byte(message), &m); err != nil {
				w.resultChan <- agentResult{err: err.Error()}
				break
			}
			switch m.Type {
			case "imbalance":
				w.resultChan <- agentResult{message: body}

			case "tip_header":
				w.resultChan <- agentResult{message: body}

			case "push_transition_result":
				w.resultChan <- agentResult{message: body}

			case "transition":
				w.resultChan <- agentResult{message: body}

			case "public_key_transitions":
				w.resultChan <- agentResult{message: body}

			case "filter_result":
				if len(body) != 0 {
					fr := new(FilterResultMessage)
					if err := json.Unmarshal(body, fr); err != nil {
						log.Printf("Error: %s, from: %s\n", err, w.conn.RemoteAddr())
						w.resultChan <- agentResult{err: err.Error()}
						break
					}
					w.resultChan <- agentResult{err: fr.Error}
				} else {
					w.resultChan <- agentResult{}
				}

			case "push_transition":
				pt := new(PushTransitionMessage)
				if err := json.Unmarshal(body, pt); err != nil {
					log.Printf("Error: %s, from: %s\n", err, w.conn.RemoteAddr())
					break
				}
				if w.transitionCallback != nil {
					w.transitionCallback(pt.Transition)
				}

			case "filter_stage":
				fb := new(FilterStageMessage)
				if err := json.Unmarshal(body, fb); err != nil {
					log.Printf("Error: %s, from: %s\n", err, w.conn.RemoteAddr())
					break
				}
				if w.filterStageCallback != nil {
					w.filterStageCallback(fb)
				}
			}

		case websocket.CloseMessage:
			fmt.Printf("Received close message from: %s\n", w.conn.RemoteAddr())
			break
		}
	}
}

// Shutdown is called to shutdown the agent synchronously.
func (w *Agent) Shutdown() error {
	var addr string
	if w.conn != nil {
		addr = w.conn.RemoteAddr().String()
		w.conn.Close()
	}
	w.wg.Wait()
	if len(addr) != 0 {
		log.Printf("Closed connection with %s\n", addr)
	}
	return w.db.Close()
}

// Initialize the filter
func (w *Agent) initializeFilter() error {
	var capacity int = 4096
	pubKeys, err := w.GetKeys()
	if err != nil {
		return err
	}
	if len(pubKeys) > capacity/2 {
		capacity = len(pubKeys) * 2
	}
	w.filter = cuckoo.NewFilter(uint(capacity))
	for _, pubKey := range pubKeys {
		if !w.filter.Insert(pubKey[:]) {
			return fmt.Errorf("Error building filter")
		}
	}
	return nil
}

// leveldb schema

// n         -> newest public key
// k{pubkey} -> encrypted private key

const newestPublicKeyPrefix = 'n'

const privateKeyPrefix = 'k'

func encodePrivateKeyDbKey(pubKey ed25519.PublicKey) ([]byte, error) {
	key := new(bytes.Buffer)
	if err := key.WriteByte(privateKeyPrefix); err != nil {
		return nil, err
	}
	if err := binary.Write(key, binary.BigEndian, pubKey); err != nil {
		return nil, err
	}
	return key.Bytes(), nil
}

func decodePrivateKeyDbKey(key []byte) (ed25519.PublicKey, error) {
	buf := bytes.NewBuffer(key)
	if _, err := buf.ReadByte(); err != nil {
		return nil, err
	}
	var pubKey [ed25519.PublicKeySize]byte
	if err := binary.Read(buf, binary.BigEndian, pubKey[:32]); err != nil {
		return nil, err
	}
	return ed25519.PublicKey(pubKey[:]), nil
}

// encryption utility functions

// NaCl secretbox encrypt a private key with an Argon2id key derived from passphrase
func encryptPrivateKey(privKey ed25519.PrivateKey, passphrase string) []byte {
	salt := generateSalt()
	key := stretchPassphrase(passphrase, salt)

	var secretKey [32]byte
	copy(secretKey[:], key)

	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic(err)
	}

	encrypted := secretbox.Seal(nonce[:], privKey[:], &nonce, &secretKey)

	// prepend the salt
	encryptedPrivKey := make([]byte, len(encrypted)+ArgonSaltLength)
	copy(encryptedPrivKey[:], salt)
	copy(encryptedPrivKey[ArgonSaltLength:], encrypted)

	return encryptedPrivKey
}

// NaCl secretbox decrypt a private key with an Argon2id key derived from passphrase
func decryptPrivateKey(encryptedPrivKey []byte, passphrase string) (ed25519.PrivateKey, bool) {
	salt := encryptedPrivKey[:ArgonSaltLength]
	key := []byte(stretchPassphrase(passphrase, salt))

	var secretKey [32]byte
	copy(secretKey[:], key)

	var nonce [24]byte
	copy(nonce[:], encryptedPrivKey[ArgonSaltLength:ArgonSaltLength+24])

	decryptedPrivKey, ok := secretbox.Open(nil, encryptedPrivKey[ArgonSaltLength+24:], &nonce, &secretKey)
	if !ok {
		return ed25519.PrivateKey{}, false
	}
	return ed25519.PrivateKey(decryptedPrivKey[:]), true
}

const ArgonSaltLength = 16

const ArgonTime = 1

const ArgonMemory = 64 * 1024

const ArgonThreads = 4

const ArgonKeyLength = 32

// Generate a suitable salt for use with Argon2id
func generateSalt() []byte {
	salt := make([]byte, ArgonSaltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		panic(err.Error())
	}
	return salt
}

// Strecth passphrase into a 32 byte key with Argon2id
func stretchPassphrase(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, ArgonTime, ArgonMemory, ArgonThreads, ArgonKeyLength)
}
