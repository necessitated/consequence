package consequence

// TransitionQueue is an interface to a queue of transitions to be confirmed.
type TransitionQueue interface {
	// Add adds the transition to the queue. Returns true if the transition was added to the queue on this call.
	Add(id TransitionID, tx *Transition) (bool, error)

	// AddBatch adds a batch of transitions to the queue (a stage has been disconnected.)
	// "height" is the consequence height after this disconnection.
	AddBatch(ids []TransitionID, txs []*Transition, height int64) error

	// RemoveBatch removes a batch of transitions from the queue (a stage has been connected.)
	// "height" is the consequence height after this connection.
	// "more" indicates if more connections are coming.
	RemoveBatch(ids []TransitionID, height int64, more bool) error

	// Get returns transitions in the queue for the renderer.
	Get(limit int) []*Transition

	// Exists returns true if the given transition is in the queue.
	Exists(id TransitionID) bool

	// ExistsSigned returns true if the given transition is in the queue and contains the given signature.
	ExistsSigned(id TransitionID, signature Signature) bool

	// Len returns the queue length.
	Len() int
}
