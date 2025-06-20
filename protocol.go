package consequence

import "golang.org/x/crypto/ed25519"

// Protocol is the name of this version of the consequence peer protocol.
const Protocol = "consequence.1"

// Message is a message frame for all messages in the consequence.1 protocol.
type Message struct {
	Type string      `json:"type"`
	Body interface{} `json:"body,omitempty"`
}

// InvStageMessage is used to communicate stages available for download.
// Type: "inv_stage".
type InvStageMessage struct {
	StageIDs []StageID `json:"stage_ids"`
}

// GetStageMessage is used to request a stage for download.
// Type: "get_stage".
type GetStageMessage struct {
	StageID StageID `json:"stage_id"`
}

// GetStageByHeightMessage is used to request a stage for download.
// Type: "get_stage_by_height".
type GetStageByHeightMessage struct {
	Height int64 `json:"height"`
}

// StageMessage is used to send a peer a complete stage.
// Type: "stage".
type StageMessage struct {
	StageID *StageID `json:"stage_id,omitempty"`
	Stage   *Stage   `json:"stage,omitempty"`
}

// GetStageHeaderMessage is used to request a stage header.
// Type: "get_stage_header".
type GetStageHeaderMessage struct {
	StageID StageID `json:"stage_id"`
}

// GetStageHeaderByHeightMessage is used to request a stage header.
// Type: "get_stage_header_by_height".
type GetStageHeaderByHeightMessage struct {
	Height int64 `json:"height"`
}

// StageHeaderMessage is used to send a peer a stage's header.
// Type: "stage_header".
type StageHeaderMessage struct {
	StageID     *StageID     `json:"stage_id,omitempty"`
	StageHeader *StageHeader `json:"header,omitempty"`
}

// FindCommonAncestorMessage is used to find a common ancestor with a peer.
// Type: "find_common_ancestor".
type FindCommonAncestorMessage struct {
	StageIDs []StageID `json:"stage_ids"`
}

// GetProfile requests a public key's profile
// Type: "get_profile".
type GetProfileMessage struct {
	PublicKey ed25519.PublicKey `json:"public_key"`
}

// ProfileMessage is used to send a public key's profile to a peer.
// Type: "profile".
type ProfileMessage struct {
	PublicKey ed25519.PublicKey `json:"public_key"`
	Label     string 			`json:"label"`
	Bio       string 			`json:"bio"`
	Ranking   float64           `json:"ranking"`
	Imbalance int64             `json:"imbalance"`
	Locale    string            `json:"locale,omitempty"`
	StageID   StageID           `json:"stage_id,omitempty"`
	Height    int64             `json:"height,omitempty"`
	Error     string            `json:"error,omitempty"`
}

// GetGraph requests a public key's graph
// Type: "get_graph".
type GetGraphMessage struct {
	PublicKey ed25519.PublicKey `json:"public_key"`
}

// GraphMessage is used to send a public key's graph considerations to a peer.
// Type: "graph".
type GraphMessage struct {
	StageID    StageID          `json:"stage_id,omitempty"`
	Height    int64             `json:"height,omitempty"`
	PublicKey ed25519.PublicKey `json:"public_key"`
	Graph     string            `json:"graph"`
}

// GetRankingMessage requests a public key's considerability ranking.
// Type: "get_ranking".
type GetRankingMessage struct {
	PublicKey ed25519.PublicKey `json:"public_key"`
}

// RankingMessage is used to send a public key's considerability ranking to a peer.
// Type: "ranking".
type RankingMessage struct {
	StageID    StageID          `json:"stage_id,omitempty"`
	Height    int64             `json:"height,omitempty"`
	PublicKey ed25519.PublicKey `json:"public_key"`
	Ranking   float64           `json:"ranking"`
	Error     string            `json:"error,omitempty"`
}

// GetRankingsMessage requests a set of public key rankings.
// Type: "get_rankings".
type GetRankingsMessage struct {
	PublicKeys []ed25519.PublicKey `json:"public_keys"`
}

// RankingsMessage is used to send public key rankings to a peer.
// Type: "rankings".
type RankingsMessage struct {
	StageID   StageID           `json:"stage_id,omitempty"`
	Height   int64              `json:"height,omitempty"`
	Rankings []PublicKeyRanking `json:"rankings,omitempty"`
	Error    string             `json:"error,omitempty"`
}

// PublicKeyRanking is an entry in the RankingsMessage's Rankings field.
type PublicKeyRanking struct {
	PublicKey string  `json:"public_key"`
	Ranking   float64 `json:"ranking"`
}

// GetImbalanceMessage requests a public key's imbalance.
// Type: "get_imbalance".
type GetImbalanceMessage struct {
	PublicKey ed25519.PublicKey `json:"public_key"`
}

// ImbalanceMessage is used to send a public key's imbalance to a peer.
// Type: "imbalance".
type ImbalanceMessage struct {
	StageID   *StageID          `json:"stage_id,omitempty"`
	Height    int64             `json:"height,omitempty"`
	PublicKey ed25519.PublicKey `json:"public_key"`
	Imbalance   int64           `json:"imbalance"`
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
	StageID  *StageID           `json:"stage_id,omitempty"`
	Height   int64              `json:"height,omitempty"`
	Imbalances []PublicKeyImbalance `json:"imbalances,omitempty"`
	Error    string             `json:"error,omitempty"`
}

// PublicKeyImbalance is an entry in the ImbalancesMessage's Imbalances field.
type PublicKeyImbalance struct {
	PublicKey ed25519.PublicKey `json:"public_key"`
	Imbalance   int64             `json:"imbalance"`
}

// GetTransitionMessage is used to request a confirmed transition.
// Type: "get_transition".
type GetTransitionMessage struct {
	TransitionID TransitionID `json:"transition_id"`
}

// TransitionMessage is used to send a peer a confirmed transition.
// Type: "transition"
type TransitionMessage struct {
	StageID       *StageID      `json:"stage_id,omitempty"`
	Height        int64         `json:"height,omitempty"`
	TransitionID TransitionID `json:"transition_id"`
	Transition   *Transition  `json:"transition,omitempty"`
}

// TipHeaderMessage is used to send a peer the header for the tip stage in the consequence.
// Type: "tip_header". It is sent in response to the empty "get_tip_header" message type.
type TipHeaderMessage struct {
	StageID     *StageID     `json:"stage_id,omitempty"`
	StageHeader *StageHeader `json:"header,omitempty"`
	TimeSeen    int64        `json:"time_seen,omitempty"`
}

// PushTransitionMessage is used to push a newly processed unconfirmed transition to peers.
// Type: "push_transition".
type PushTransitionMessage struct {
	Transition *Transition `json:"transition"`
}

// PushTransitionResultMessage is sent in response to a PushTransitionMessage.
// Type: "push_transition_result".
type PushTransitionResultMessage struct {
	TransitionID TransitionID `json:"transition_id"`
	Error         string        `json:"error,omitempty"`
}

// FilterLoadMessage is used to request that we load a filter which is used to
// filter transitions returned to the peer based on interest.
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

// FilterStageMessage represents a pared down stage containing only transitions relevant to the peer given their filter.
// Type: "filter_stage".
type FilterStageMessage struct {
	StageID      StageID        `json:"stage_id"`
	Header       *StageHeader   `json:"header"`
	Transitions []*Transition `json:"transitions"`
}

// FilterTransitionQueueMessage returns a pared down view of the unconfirmed transition queue containing only
// transitions relevant to the peer given their filter.
// Type: "filter_transition_queue".
type FilterTransitionQueueMessage struct {
	Transitions []*Transition `json:"transitions"`
	Error        string         `json:"error,omitempty"`
}

// GetPublicKeyTransitionsMessage requests transitions associated with a given public key over a given
// height range of the consequence.
// Type: "get_public_key_transitions".
type GetPublicKeyTransitionsMessage struct {
	PublicKey   ed25519.PublicKey `json:"public_key"`
	StartHeight int64             `json:"start_height"`
	StartIndex  int               `json:"start_index"`
	EndHeight   int64             `json:"end_height"`
	Limit       int               `json:"limit"`
}

// PublicKeyTransitionsMessage is used to return a list of stage headers and the transitions relevant to
// the public key over a given height range of the consequence.
// Type: "public_key_transitions".
type PublicKeyTransitionsMessage struct {
	PublicKey    ed25519.PublicKey     `json:"public_key"`
	StartHeight  int64                 `json:"start_height"`
	StopHeight   int64                 `json:"stop_height"`
	StopIndex    int                   `json:"stop_index"`
	FilterStages []*FilterStageMessage `json:"filter_stages"`
	Error        string                `json:"error,omitempty"`
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
	WorkID  int32        `json:"work_id"`
	Header  *StageHeader `json:"header"`
	MinTime int64        `json:"min_time"`
	Error   string       `json:"error,omitempty"`
}

// SubmitWorkMessage is used by a rendering peer to submit a potential solution to the client.
// Type: "submit_work"
type SubmitWorkMessage struct {
	WorkID int32        `json:"work_id"`
	Header *StageHeader `json:"header"`
}

// SubmitWorkResultMessage is used to inform a rendering peer of the result of its work.
// Type: "submit_work_result"
type SubmitWorkResultMessage struct {
	WorkID int32  `json:"work_id"`
	Error  string `json:"error,omitempty"`
}
