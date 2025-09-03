package consequence

import (
	"container/list"
	"sync"
	"time"
)

// StageQueue is a queue of stages to download.
type StageQueue struct {
	stageMap   map[StageID]*list.Element
	stageQueue *list.List
	lock       sync.RWMutex
}

// If a stage has been in the queue for more than 2 minutes it can be re-added with a new peer responsible for its download.
const maxQueueWait = 2 * time.Minute

type stageQueueEntry struct {
	id   StageID
	who  string
	when time.Time
}

// NewStageQueue returns a new instance of a StageQueue.
func NewStageQueue() *StageQueue {
	return &StageQueue{
		stageMap:   make(map[StageID]*list.Element),
		stageQueue: list.New(),
	}
}

// Add adds the stage ID to the back of the queue and records the address of the peer who pushed it if it didn't exist in the queue.
// If it did exist and maxQueueWait has elapsed, the stage is left in its position but the peer responsible for download is updated.
func (b *StageQueue) Add(id StageID, who string) bool {
	b.lock.Lock()
	defer b.lock.Unlock()
	if e, ok := b.stageMap[id]; ok {
		entry := e.Value.(*stageQueueEntry)
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
	entry := &stageQueueEntry{id: id, who: who, when: time.Now()}
	e := b.stageQueue.PushBack(entry)
	b.stageMap[id] = e
	return true
}

// Remove removes the stage ID from the queue only if the requester is who is currently responsible for its download.
func (b *StageQueue) Remove(id StageID, who string) bool {
	b.lock.Lock()
	defer b.lock.Unlock()
	if e, ok := b.stageMap[id]; ok {
		entry := e.Value.(*stageQueueEntry)
		if entry.who == who {
			b.stageQueue.Remove(e)
			delete(b.stageMap, entry.id)
			return true
		}
	}
	return false
}

// Exists returns true if the stage ID exists in the queue.
func (b *StageQueue) Exists(id StageID) bool {
	b.lock.RLock()
	defer b.lock.RUnlock()
	_, ok := b.stageMap[id]
	return ok
}

// Peek returns the ID of the stage at the front of the queue.
func (b *StageQueue) Peek() (StageID, bool) {
	b.lock.RLock()
	defer b.lock.RUnlock()
	if b.stageQueue.Len() == 0 {
		return StageID{}, false
	}
	e := b.stageQueue.Front()
	entry := e.Value.(*stageQueueEntry)
	return entry.id, true
}

// Len returns the length of the queue.
func (b *StageQueue) Len() int {
	b.lock.RLock()
	defer b.lock.RUnlock()
	return b.stageQueue.Len()
}
