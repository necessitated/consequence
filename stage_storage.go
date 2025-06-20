package consequence

// StageStorage is an interface for storing stages and their transitions.
type StageStorage interface {
	// Store is called to store all of the stage's information.
	Store(id StageID, stage *Stage, now int64) error

	// Get returns the referenced stage.
	GetStage(id StageID) (*Stage, error)

	// GetStageBytes returns the referenced stage as a byte slice.
	GetStageBytes(id StageID) ([]byte, error)

	// GetStageHeader returns the referenced stage's header and the timestamp of when it was stored.
	GetStageHeader(id StageID) (*StageHeader, int64, error)

	// GetTransition returns a transition within a stage and the stage's header.
	GetTransition(id StageID, index int) (*Transition, *StageHeader, error)
}
