package consequence

// AssertionQueue is an interface to a queue of assertions to be confirmed.
type AssertionQueue interface {
	// Add adds the assertion to the queue. Returns true if the assertion was added to the queue on this call.
	Add(id AssertionID, tx *Assertion) (bool, error)

	// AddBatch adds a batch of assertions to the queue (a premise has been disconnected.)
	// "height" is the consequence height after this disconnection.
	AddBatch(ids []AssertionID, txs []*Assertion, height int64) error

	// RemoveBatch removes a batch of assertions from the queue (a premise has been connected.)
	// "height" is the consequence height after this connection.
	// "more" indicates if more connections are coming.
	RemoveBatch(ids []AssertionID, height int64, more bool) error

	// Get returns assertions in the queue for the renderer.
	Get(limit int) []*Assertion

	// Exists returns true if the given assertion is in the queue.
	Exists(id AssertionID) bool

	// ExistsSigned returns true if the given assertion is in the queue and contains the given signature.
	ExistsSigned(id AssertionID, signature Signature) bool

	// Len returns the queue length.
	Len() int
}
