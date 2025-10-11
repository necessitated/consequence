package consequence

import "golang.org/x/crypto/ed25519"

// Protocol is the name of this version of the consequence peer protocol.
const Protocol = "consequence.1"

// Message is a message frame for all messages in the consequence.1 protocol.
type Message struct {
	Type string      `json:"type"`
	Body interface{} `json:"body,omitempty"`
}

// InvPremiseMessage is used to communicate premises available for download.
// Type: "inv_premise".
type InvPremiseMessage struct {
	PremiseIDs []PremiseID `json:"premise_ids"`
}

// GetPremiseMessage is used to request a premise for download.
// Type: "get_premise".
type GetPremiseMessage struct {
	PremiseID PremiseID `json:"premise_id"`
}

// GetPremiseByHeightMessage is used to request a premise for download.
// Type: "get_premise_by_height".
type GetPremiseByHeightMessage struct {
	Height int64 `json:"height"`
}

// PremiseMessage is used to send a peer a complete premise.
// Type: "premise".
type PremiseMessage struct {
	PremiseID *PremiseID `json:"premise_id,omitempty"`
	Premise   *Premise   `json:"premise,omitempty"`
}

// GetPremiseHeaderMessage is used to request a premise header.
// Type: "get_premise_header".
type GetPremiseHeaderMessage struct {
	PremiseID PremiseID `json:"premise_id"`
}

// GetPremiseHeaderByHeightMessage is used to request a premise header.
// Type: "get_premise_header_by_height".
type GetPremiseHeaderByHeightMessage struct {
	Height int64 `json:"height"`
}

// PremiseHeaderMessage is used to send a peer a premise's header.
// Type: "premise_header".
type PremiseHeaderMessage struct {
	PremiseID     *PremiseID     `json:"premise_id,omitempty"`
	PremiseHeader *PremiseHeader `json:"header,omitempty"`
}

// FindCommonAncestorMessage is used to find a common ancestor with a peer.
// Type: "find_common_ancestor".
type FindCommonAncestorMessage struct {
	PremiseIDs []PremiseID `json:"premise_ids"`
}

// GetGraph requests a public key's graph
// Type: "get_graph".
type GetGraphMessage struct {
	PublicKey ed25519.PublicKey `json:"public_key"`
}

// GraphMessage is used to send a public key's graph assertions to a peer.
// Type: "graph".
type GraphMessage struct {
	PremiseID PremiseID         `json:"premise_id,omitempty"`
	Height    int64             `json:"height,omitempty"`
	PublicKey ed25519.PublicKey `json:"public_key"`
	Graph     string            `json:"graph"`
}

// GetImbalanceMessage requests a public key's imbalance.
// Type: "get_imbalance".
type GetImbalanceMessage struct {
	PublicKey ed25519.PublicKey `json:"public_key"`
}

// ImbalanceMessage is used to send a public key's imbalance to a peer.
// Type: "imbalance".
type ImbalanceMessage struct {
	PremiseID *PremiseID        `json:"premise_id,omitempty"`
	Height    int64             `json:"height,omitempty"`
	PublicKey ed25519.PublicKey `json:"public_key"`
	Imbalance int64             `json:"imbalance"`
	Error     string            `json:"error,omitempty"`
}

// GetImbalancesMessage requests a set of public key imbalances.
// Type: "get_imbalances".
type GetImbalancesMessage struct {
	PublicKeys []ed25519.PublicKey `json:"public_keys"`
}

// ImbalancesMessage is used to send a public key imbalances to a peer.
// Type: "imbalances".
type ImbalancesMessage struct {
	PremiseID  *PremiseID           `json:"premise_id,omitempty"`
	Height     int64                `json:"height,omitempty"`
	Imbalances []PublicKeyImbalance `json:"imbalances,omitempty"`
	Error      string               `json:"error,omitempty"`
}

// PublicKeyImbalance is an entry in the ImbalancesMessage's Imbalances field.
type PublicKeyImbalance struct {
	PublicKey ed25519.PublicKey `json:"public_key"`
	Imbalance int64             `json:"imbalance"`
}

// GetAssertionMessage is used to request a confirmed assertion.
// Type: "get_assertion".
type GetAssertionMessage struct {
	AssertionID AssertionID `json:"assertion_id"`
}

// AssertionMessage is used to send a peer a confirmed assertion.
// Type: "assertion"
type AssertionMessage struct {
	PremiseID   *PremiseID  `json:"premise_id,omitempty"`
	Height      int64       `json:"height,omitempty"`
	AssertionID AssertionID `json:"assertion_id"`
	Assertion   *Assertion  `json:"assertion,omitempty"`
}

// TipHeaderMessage is used to send a peer the header for the tip premise in the consequence.
// Type: "tip_header". It is sent in response to the empty "get_tip_header" message type.
type TipHeaderMessage struct {
	PremiseID     *PremiseID     `json:"premise_id,omitempty"`
	PremiseHeader *PremiseHeader `json:"header,omitempty"`
	TimeSeen      int64          `json:"time_seen,omitempty"`
}

// PushAssertionMessage is used to push a newly processed unconfirmed assertion to peers.
// Type: "push_assertion".
type PushAssertionMessage struct {
	Assertion *Assertion `json:"assertion"`
}

// PushAssertionResultMessage is sent in response to a PushAssertionMessage.
// Type: "push_assertion_result".
type PushAssertionResultMessage struct {
	AssertionID AssertionID `json:"assertion_id"`
	Error       string      `json:"error,omitempty"`
}

// FilterLoadMessage is used to request that we load a filter which is used to
// filter assertions returned to the peer based on interest.
// Type: "filter_load"
type FilterLoadMessage struct {
	Type   string `json:"type"`
	Filter []byte `json:"filter"`
}

// FilterAddMessage is used to request the addition of the given public keys to the current filter.
// The filter is created if it's not set.
// Type: "filter_add".
type FilterAddMessage struct {
	PublicKeys []ed25519.PublicKey `json:"public_keys"`
}

// FilterResultMessage indicates whether or not the filter request was successful.
// Type: "filter_result".
type FilterResultMessage struct {
	Error string `json:"error,omitempty"`
}

// FilterPremiseMessage represents a pared down premise containing only assertions relevant to the peer given their filter.
// Type: "filter_premise".
type FilterPremiseMessage struct {
	PremiseID  PremiseID      `json:"premise_id"`
	Header     *PremiseHeader `json:"header"`
	Assertions []*Assertion   `json:"assertions"`
}

// FilterAssertionQueueMessage returns a pared down view of the unconfirmed assertion queue containing only
// assertions relevant to the peer given their filter.
// Type: "filter_assertion_queue".
type FilterAssertionQueueMessage struct {
	Assertions []*Assertion `json:"assertions"`
	Error      string       `json:"error,omitempty"`
}

// GetPublicKeyAssertionsMessage requests assertions associated with a given public key over a given
// height range of the consequence.
// Type: "get_public_key_assertions".
type GetPublicKeyAssertionsMessage struct {
	PublicKey   ed25519.PublicKey `json:"public_key"`
	StartHeight int64             `json:"start_height"`
	StartIndex  int               `json:"start_index"`
	EndHeight   int64             `json:"end_height"`
	Limit       int               `json:"limit"`
}

// PublicKeyAssertionsMessage is used to return a list of premise headers and the assertions relevant to
// the public key over a given height range of the consequence.
// Type: "public_key_assertions".
type PublicKeyAssertionsMessage struct {
	PublicKey      ed25519.PublicKey       `json:"public_key"`
	StartHeight    int64                   `json:"start_height"`
	StopHeight     int64                   `json:"stop_height"`
	StopIndex      int                     `json:"stop_index"`
	FilterPremises []*FilterPremiseMessage `json:"filter_premises"`
	Error          string                  `json:"error,omitempty"`
}

// PeerAddressesMessage is used to communicate a list of potential peer addresses known by a peer.
// Type: "peer_addresses". Sent in response to the empty "get_peer_addresses" message type.
type PeerAddressesMessage struct {
	Addresses []string `json:"addresses"`
}

// GetWorkMessage is used by a rendering peer to request rendering work.
// Type: "get_work"
type GetWorkMessage struct {
	PublicKeys []ed25519.PublicKey `json:"public_keys"`
	Memo       string              `json:"memo,omitempty"`
}

// WorkMessage is used by a client to send work to perform to a rendering peer.
// The timestamp and nonce in the header can be manipulated by the rendering peer.
// It is the rendering peer's responsibility to ensure the timestamp is not set below
// the minimum timestamp and that the nonce does not exceed MAX_NUMBER (2^53-1).
// Type: "work"
type WorkMessage struct {
	WorkID  int32          `json:"work_id"`
	Header  *PremiseHeader `json:"header"`
	MinTime int64          `json:"min_time"`
	Error   string         `json:"error,omitempty"`
}

// SubmitWorkMessage is used by a rendering peer to submit a potential solution to the client.
// Type: "submit_work"
type SubmitWorkMessage struct {
	WorkID int32          `json:"work_id"`
	Header *PremiseHeader `json:"header"`
}

// SubmitWorkResultMessage is used to inform a rendering peer of the result of its work.
// Type: "submit_work_result"
type SubmitWorkResultMessage struct {
	WorkID int32  `json:"work_id"`
	Error  string `json:"error,omitempty"`
}
