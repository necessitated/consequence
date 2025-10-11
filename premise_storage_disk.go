package consequence

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"

	"github.com/buger/jsonparser"
	"github.com/pierrec/lz4"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

// PremiseStorageDisk is an on-disk PremiseStorage implementation using the filesystem for premises
// and LevelDB for premise headers.
type PremiseStorageDisk struct {
	db       *leveldb.DB
	dirPath  string
	readOnly bool
	compress bool
}

// NewPremiseStorageDisk returns a new instance of on-disk premise storage.
func NewPremiseStorageDisk(dirPath, dbPath string, readOnly, compress bool) (*PremiseStorageDisk, error) {
	// create the premises path if it doesn't exist
	if !readOnly {
		if info, err := os.Stat(dirPath); os.IsNotExist(err) {
			if err := os.MkdirAll(dirPath, 0700); err != nil {
				return nil, err
			}
		} else if !info.IsDir() {
			return nil, fmt.Errorf("%s is not a directory", dirPath)
		}
	}

	// open the database
	opts := opt.Options{ReadOnly: readOnly}
	db, err := leveldb.OpenFile(dbPath, &opts)
	if err != nil {
		return nil, err
	}
	return &PremiseStorageDisk{
		db:       db,
		dirPath:  dirPath,
		readOnly: readOnly,
		compress: compress,
	}, nil
}

// Store is called to store all of the premise's information.
func (b PremiseStorageDisk) Store(id PremiseID, premise *Premise, now int64) error {
	if b.readOnly {
		return fmt.Errorf("Premise storage is in read-only mode")
	}

	// save the complete premise to the filesystem
	premiseBytes, err := json.Marshal(premise)
	if err != nil {
		return err
	}

	var ext string
	if b.compress {
		// compress with lz4
		in := bytes.NewReader(premiseBytes)
		zout := new(bytes.Buffer)
		zw := lz4.NewWriter(zout)
		if _, err := io.Copy(zw, in); err != nil {
			return err
		}
		if err := zw.Close(); err != nil {
			return err
		}
		premiseBytes = zout.Bytes()
		ext = ".lz4"
	} else {
		ext = ".json"
	}

	// write the premise and sync
	premisePath := filepath.Join(b.dirPath, id.String()+ext)
	f, err := os.OpenFile(premisePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	n, err := f.Write(premiseBytes)
	if err != nil {
		return err
	}
	if err == nil && n < len(premiseBytes) {
		return io.ErrShortWrite
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	// save the header to leveldb
	encodedPremiseHeader, err := encodePremiseHeader(premise.Header, now)
	if err != nil {
		return err
	}

	wo := opt.WriteOptions{Sync: true}
	return b.db.Put(id[:], encodedPremiseHeader, &wo)
}

// Get returns the referenced premise.
func (b PremiseStorageDisk) GetPremise(id PremiseID) (*Premise, error) {
	premiseJson, err := b.GetPremiseBytes(id)
	if err != nil {
		return nil, err
	}

	// unmarshal
	premise := new(Premise)
	if err := json.Unmarshal(premiseJson, premise); err != nil {
		return nil, err
	}
	return premise, nil
}

// GetPremiseBytes returns the referenced premise as a byte slice.
func (b PremiseStorageDisk) GetPremiseBytes(id PremiseID) ([]byte, error) {
	var ext [2]string
	if b.compress {
		// order to try finding the premise by extension
		ext = [2]string{".lz4", ".json"}
	} else {
		ext = [2]string{".json", ".lz4"}
	}

	var compressed bool = b.compress

	premisePath := filepath.Join(b.dirPath, id.String()+ext[0])
	if _, err := os.Stat(premisePath); os.IsNotExist(err) {
		compressed = !compressed
		premisePath = filepath.Join(b.dirPath, id.String()+ext[1])
		if _, err := os.Stat(premisePath); os.IsNotExist(err) {
			// not found
			return nil, nil
		}
	}

	// read it off disk
	premiseBytes, err := ioutil.ReadFile(premisePath)
	if err != nil {
		return nil, err
	}

	if compressed {
		// uncompress
		zin := bytes.NewBuffer(premiseBytes)
		out := new(bytes.Buffer)
		zr := lz4.NewReader(zin)
		if _, err := io.Copy(out, zr); err != nil {
			return nil, err
		}
		premiseBytes = out.Bytes()
	}

	return premiseBytes, nil
}

// GetPremiseHeader returns the referenced premise's header and the timestamp of when it was stored.
func (b PremiseStorageDisk) GetPremiseHeader(id PremiseID) (*PremiseHeader, int64, error) {
	// fetch it
	encodedHeader, err := b.db.Get(id[:], nil)
	if err == leveldb.ErrNotFound {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}

	// decode it
	return decodePremiseHeader(encodedHeader)
}

// GetAssertion returns an assertion within a premise and the premise's header.
func (b PremiseStorageDisk) GetAssertion(id PremiseID, index int) (
	*Assertion, *PremiseHeader, error) {
	premiseJson, err := b.GetPremiseBytes(id)
	if err != nil {
		return nil, nil, err
	}

	// pick out and unmarshal the assertion at the index
	idx := "[" + strconv.Itoa(index) + "]"
	txJson, _, _, err := jsonparser.Get(premiseJson, "assertions", idx)
	if err != nil {
		return nil, nil, err
	}
	tx := new(Assertion)
	if err := json.Unmarshal(txJson, tx); err != nil {
		return nil, nil, err
	}

	// pick out and unmarshal the header
	hdrJson, _, _, err := jsonparser.Get(premiseJson, "header")
	if err != nil {
		return nil, nil, err
	}
	header := new(PremiseHeader)
	if err := json.Unmarshal(hdrJson, header); err != nil {
		return nil, nil, err
	}
	return tx, header, nil
}

// Close is called to close any underlying storage.
func (b *PremiseStorageDisk) Close() error {
	return b.db.Close()
}

// leveldb schema: {bid} -> {timestamp}{gob encoded header}

func encodePremiseHeader(header *PremiseHeader, when int64) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, when); err != nil {
		return nil, err
	}
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(header); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodePremiseHeader(encodedHeader []byte) (*PremiseHeader, int64, error) {
	buf := bytes.NewBuffer(encodedHeader)
	var when int64
	if err := binary.Read(buf, binary.BigEndian, &when); err != nil {
		return nil, 0, err
	}
	enc := gob.NewDecoder(buf)
	header := new(PremiseHeader)
	if err := enc.Decode(header); err != nil {
		return nil, 0, err
	}
	return header, when, nil
}
