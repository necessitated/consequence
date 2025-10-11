package consequence

import (
	"container/list"
	"sync"
	"time"
)

// PremiseQueue is a queue of premises to download.
type PremiseQueue struct {
	premiseMap   map[PremiseID]*list.Element
	premiseQueue *list.List
	lock       sync.RWMutex
}

// If a premise has been in the queue for more than 2 minutes it can be re-added with a new peer responsible for its download.
const maxQueueWait = 2 * time.Minute

type premiseQueueEntry struct {
	id   PremiseID
	who  string
	when time.Time
}

// NewPremiseQueue returns a new instance of a PremiseQueue.
func NewPremiseQueue() *PremiseQueue {
	return &PremiseQueue{
		premiseMap:   make(map[PremiseID]*list.Element),
		premiseQueue: list.New(),
	}
}

// Add adds the premise ID to the back of the queue and records the address of the peer who pushed it if it didn't exist in the queue.
// If it did exist and maxQueueWait has elapsed, the premise is left in its position but the peer responsible for download is updated.
func (b *PremiseQueue) Add(id PremiseID, who string) bool {
	b.lock.Lock()
	defer b.lock.Unlock()
	if e, ok := b.premiseMap[id]; ok {
		entry := e.Value.(*premiseQueueEntry)
		if time.Since(entry.when) < maxQueueWait {
			// it's still pending download
			return false
		}
		// it's expired. signal that it can be tried again and leave it in place
		entry.when = time.Now()
		// new peer owns its place in the queue
		entry.who = who
		return true
	}

	// add to the back of the queue
	entry := &premiseQueueEntry{id: id, who: who, when: time.Now()}
	e := b.premiseQueue.PushBack(entry)
	b.premiseMap[id] = e
	return true
}

// Remove removes the premise ID from the queue only if the requester is who is currently responsible for its download.
func (b *PremiseQueue) Remove(id PremiseID, who string) bool {
	b.lock.Lock()
	defer b.lock.Unlock()
	if e, ok := b.premiseMap[id]; ok {
		entry := e.Value.(*premiseQueueEntry)
		if entry.who == who {
			b.premiseQueue.Remove(e)
			delete(b.premiseMap, entry.id)
			return true
		}
	}
	return false
}

// Exists returns true if the premise ID exists in the queue.
func (b *PremiseQueue) Exists(id PremiseID) bool {
	b.lock.RLock()
	defer b.lock.RUnlock()
	_, ok := b.premiseMap[id]
	return ok
}

// Peek returns the ID of the premise at the front of the queue.
func (b *PremiseQueue) Peek() (PremiseID, bool) {
	b.lock.RLock()
	defer b.lock.RUnlock()
	if b.premiseQueue.Len() == 0 {
		return PremiseID{}, false
	}
	e := b.premiseQueue.Front()
	entry := e.Value.(*premiseQueueEntry)
	return entry.id, true
}

// Len returns the length of the queue.
func (b *PremiseQueue) Len() int {
	b.lock.RLock()
	defer b.lock.RUnlock()
	return b.premiseQueue.Len()
}
