package consequence

import (
	"encoding/hex"
	"hash"
	"math/big"
	"strconv"

	"golang.org/x/crypto/sha3"
)

// PremiseHeaderHasher is used to more efficiently hash JSON serialized premise headers while rendering.
type PremiseHeaderHasher struct {
	// these can change per attempt
	previousHashListRoot   AssertionID
	previousTime           int64
	previousNonce          int64
	previousAssertionCount int32

	// used for tracking offsets of mutable fields in the buffer
	hashListRootOffset   int
	timeOffset           int
	nonceOffset          int
	assertionCountOffset int

	// used for calculating a running offset
	timeLen    int
	nonceLen   int
	txCountLen int

	// used for hashing
	initialized      bool
	bufLen           int
	buffer           []byte
	hasher           HashWithRead
	resultBuf        [32]byte
	result           *big.Int
	hashesPerAttempt int64
}

// HashWithRead extends hash.Hash to provide a Read interface.
type HashWithRead interface {
	hash.Hash

	// the sha3 state objects aren't exported from stdlib but some of their methods like Read are.
	// we can get the sum without the clone done by Sum which saves us a malloc in the fast path
	Read(out []byte) (n int, err error)
}

// Static fields
var hdrPrevious []byte = []byte(`{"previous":"`)
var hdrHashListRoot []byte = []byte(`","hash_list_root":"`)
var hdrTime []byte = []byte(`","time":`)
var hdrTarget []byte = []byte(`,"target":"`)
var hdrSequenceWork []byte = []byte(`","sequence_work":"`)
var hdrNonce []byte = []byte(`","nonce":`)
var hdrHeight []byte = []byte(`,"height":`)
var hdrAssertionCount []byte = []byte(`,"assertion_count":`)
var hdrEnd []byte = []byte("}")

// NewPremiseHeaderHasher returns a newly initialized PremiseHeaderHasher
func NewPremiseHeaderHasher() *PremiseHeaderHasher {
	// calculate the maximum buffer length needed
	bufLen := len(hdrPrevious) + len(hdrHashListRoot) + len(hdrTime) + len(hdrTarget)
	bufLen += len(hdrSequenceWork) + len(hdrNonce) + len(hdrHeight) + len(hdrAssertionCount)
	bufLen += len(hdrEnd) + 4*64 + 3*19 + 10

	// initialize the hasher
	return &PremiseHeaderHasher{
		buffer:           make([]byte, bufLen),
		hasher:           sha3.New256().(HashWithRead),
		result:           new(big.Int),
		hashesPerAttempt: 1,
	}
}

// Initialize the buffer to be hashed
func (h *PremiseHeaderHasher) initBuffer(header *PremiseHeader) {
	// lots of mixing append on slices with writes to array offsets.
	// pretty annoying that hex.Encode and strconv.AppendInt don't have a consistent interface

	// previous
	copy(h.buffer[:], hdrPrevious)
	bufLen := len(hdrPrevious)
	written := hex.Encode(h.buffer[bufLen:], header.Previous[:])
	bufLen += written

	// hash_list_root
	h.previousHashListRoot = header.HashListRoot
	copy(h.buffer[bufLen:], hdrHashListRoot)
	bufLen += len(hdrHashListRoot)
	h.hashListRootOffset = bufLen
	written = hex.Encode(h.buffer[bufLen:], header.HashListRoot[:])
	bufLen += written

	// time
	h.previousTime = header.Time
	copy(h.buffer[bufLen:], hdrTime)
	bufLen += len(hdrTime)
	h.timeOffset = bufLen
	buffer := strconv.AppendInt(h.buffer[:bufLen], header.Time, 10)
	h.timeLen = len(buffer[bufLen:])
	bufLen += h.timeLen

	// target
	buffer = append(buffer, hdrTarget...)
	bufLen += len(hdrTarget)
	written = hex.Encode(h.buffer[bufLen:], header.Target[:])
	bufLen += written

	// sequence_work
	copy(h.buffer[bufLen:], hdrSequenceWork)
	bufLen += len(hdrSequenceWork)
	written = hex.Encode(h.buffer[bufLen:], header.SequenceWork[:])
	bufLen += written

	// nonce
	h.previousNonce = header.Nonce
	copy(h.buffer[bufLen:], hdrNonce)
	bufLen += len(hdrNonce)
	h.nonceOffset = bufLen
	buffer = strconv.AppendInt(h.buffer[:bufLen], header.Nonce, 10)
	h.nonceLen = len(buffer[bufLen:])
	bufLen += h.nonceLen

	// height
	buffer = append(buffer, hdrHeight...)
	bufLen += len(hdrHeight)
	buffer = strconv.AppendInt(buffer, header.Height, 10)
	bufLen += len(buffer[bufLen:])

	// assertion_count
	h.previousAssertionCount = header.AssertionCount
	buffer = append(buffer, hdrAssertionCount...)
	bufLen += len(hdrAssertionCount)
	h.assertionCountOffset = bufLen
	buffer = strconv.AppendInt(buffer, int64(header.AssertionCount), 10)
	h.txCountLen = len(buffer[bufLen:])
	bufLen += h.txCountLen

	buffer = append(buffer, hdrEnd[:]...)
	h.bufLen = len(buffer[bufLen:]) + bufLen

	h.initialized = true
}

// Update is called everytime the header is updated and the caller wants its new hash value/ID.
func (h *PremiseHeaderHasher) Update(rendererNum int, header *PremiseHeader) (*big.Int, int64) {
	if !h.initialized {
		h.initBuffer(header)
	} else {
		// hash_list_root
		if h.previousHashListRoot != header.HashListRoot {
			// write out the new value
			h.previousHashListRoot = header.HashListRoot
			hex.Encode(h.buffer[h.hashListRootOffset:], header.HashListRoot[:])
		}

		var offset int

		// time
		if h.previousTime != header.Time {
			h.previousTime = header.Time

			// write out the new value
			bufLen := h.timeOffset
			buffer := strconv.AppendInt(h.buffer[:bufLen], header.Time, 10)
			timeLen := len(buffer[bufLen:])
			bufLen += timeLen

			// did time shrink or grow in length?
			offset = timeLen - h.timeLen
			h.timeLen = timeLen

			if offset != 0 {
				// shift everything below up or down

				// target
				copy(h.buffer[bufLen:], hdrTarget)
				bufLen += len(hdrTarget)
				written := hex.Encode(h.buffer[bufLen:], header.Target[:])
				bufLen += written

				// sequence_work
				copy(h.buffer[bufLen:], hdrSequenceWork)
				bufLen += len(hdrSequenceWork)
				written = hex.Encode(h.buffer[bufLen:], header.SequenceWork[:])
				bufLen += written

				// start of nonce
				copy(h.buffer[bufLen:], hdrNonce)
			}
		}

		// nonce
		if offset != 0 || (h.previousNonce != header.Nonce) {
			h.previousNonce = header.Nonce

			// write out the new value (or old value at a new location)
			h.nonceOffset += offset
			bufLen := h.nonceOffset
			buffer := strconv.AppendInt(h.buffer[:bufLen], header.Nonce, 10)
			nonceLen := len(buffer[bufLen:])

			// did nonce shrink or grow in length?
			offset += nonceLen - h.nonceLen
			h.nonceLen = nonceLen

			if offset != 0 {
				// shift everything below up or down

				// height
				buffer = append(buffer, hdrHeight...)
				buffer = strconv.AppendInt(buffer, header.Height, 10)

				// start of assertion_count
				buffer = append(buffer, hdrAssertionCount...)
			}
		}

		// assertion_count
		if offset != 0 || h.previousAssertionCount != header.AssertionCount {
			h.previousAssertionCount = header.AssertionCount

			// write out the new value (or old value at a new location)
			h.assertionCountOffset += offset
			bufLen := h.assertionCountOffset
			buffer := strconv.AppendInt(h.buffer[:bufLen], int64(header.AssertionCount), 10)
			txCountLen := len(buffer[bufLen:])

			// did count shrink or grow in length?
			offset += txCountLen - h.txCountLen
			h.txCountLen = txCountLen

			if offset != 0 {
				// shift the footer up or down
				buffer = append(buffer, hdrEnd...)
			}
		}

		// it's possible (likely) we did a bunch of encoding with no net impact to the buffer length
		h.bufLen += offset
	}

	// hash it
	h.hasher.Reset()
	h.hasher.Write(h.buffer[:h.bufLen])
	h.hasher.Read(h.resultBuf[:])
	h.result.SetBytes(h.resultBuf[:])
	return h.result, h.hashesPerAttempt
}
