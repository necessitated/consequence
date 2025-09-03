package consequence

// PremiseStorage is an interface for storing premises and their assertions.
type PremiseStorage interface {
	// Store is called to store all of the premise's information.
	Store(id PremiseID, premise *Premise, now int64) error

	// Get returns the referenced premise.
	GetPremise(id PremiseID) (*Premise, error)

	// GetPremiseBytes returns the referenced premise as a byte slice.
	GetPremiseBytes(id PremiseID) ([]byte, error)

	// GetPremiseHeader returns the referenced premise's header and the timestamp of when it was stored.
	GetPremiseHeader(id PremiseID) (*PremiseHeader, int64, error)

	// GetAssertion returns an assertion within a premise and the premise's header.
	GetAssertion(id PremiseID, index int) (*Assertion, *PremiseHeader, error)
}
