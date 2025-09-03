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

// StageStorageDisk is an on-disk StageStorage implementation using the filesystem for stages
// and LevelDB for stage headers.
type StageStorageDisk struct {
	db       *leveldb.DB
	dirPath  string
	readOnly bool
	compress bool
}

// NewStageStorageDisk returns a new instance of on-disk stage storage.
func NewStageStorageDisk(dirPath, dbPath string, readOnly, compress bool) (*StageStorageDisk, error) {
	// create the stages path if it doesn't exist
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
	return &StageStorageDisk{
		db:       db,
		dirPath:  dirPath,
		readOnly: readOnly,
		compress: compress,
	}, nil
}

// Store is called to store all of the stage's information.
func (b StageStorageDisk) Store(id StageID, stage *Stage, now int64) error {
	if b.readOnly {
		return fmt.Errorf("Stage storage is in read-only mode")
	}

	// save the complete stage to the filesystem
	stageBytes, err := json.Marshal(stage)
	if err != nil {
		return err
	}

	var ext string
	if b.compress {
		// compress with lz4
		in := bytes.NewReader(stageBytes)
		zout := new(bytes.Buffer)
		zw := lz4.NewWriter(zout)
		if _, err := io.Copy(zw, in); err != nil {
			return err
		}
		if err := zw.Close(); err != nil {
			return err
		}
		stageBytes = zout.Bytes()
		ext = ".lz4"
	} else {
		ext = ".json"
	}

	// write the stage and sync
	stagePath := filepath.Join(b.dirPath, id.String()+ext)
	f, err := os.OpenFile(stagePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	n, err := f.Write(stageBytes)
	if err != nil {
		return err
	}
	if err == nil && n < len(stageBytes) {
		return io.ErrShortWrite
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	// save the header to leveldb
	encodedStageHeader, err := encodeStageHeader(stage.Header, now)
	if err != nil {
		return err
	}

	wo := opt.WriteOptions{Sync: true}
	return b.db.Put(id[:], encodedStageHeader, &wo)
}

// Get returns the referenced stage.
func (b StageStorageDisk) GetStage(id StageID) (*Stage, error) {
	stageJson, err := b.GetStageBytes(id)
	if err != nil {
		return nil, err
	}

	// unmarshal
	stage := new(Stage)
	if err := json.Unmarshal(stageJson, stage); err != nil {
		return nil, err
	}
	return stage, nil
}

// GetStageBytes returns the referenced stage as a byte slice.
func (b StageStorageDisk) GetStageBytes(id StageID) ([]byte, error) {
	var ext [2]string
	if b.compress {
		// order to try finding the stage by extension
		ext = [2]string{".lz4", ".json"}
	} else {
		ext = [2]string{".json", ".lz4"}
	}

	var compressed bool = b.compress

	stagePath := filepath.Join(b.dirPath, id.String()+ext[0])
	if _, err := os.Stat(stagePath); os.IsNotExist(err) {
		compressed = !compressed
		stagePath = filepath.Join(b.dirPath, id.String()+ext[1])
		if _, err := os.Stat(stagePath); os.IsNotExist(err) {
			// not found
			return nil, nil
		}
	}

	// read it off disk
	stageBytes, err := ioutil.ReadFile(stagePath)
	if err != nil {
		return nil, err
	}

	if compressed {
		// uncompress
		zin := bytes.NewBuffer(stageBytes)
		out := new(bytes.Buffer)
		zr := lz4.NewReader(zin)
		if _, err := io.Copy(out, zr); err != nil {
			return nil, err
		}
		stageBytes = out.Bytes()
	}

	return stageBytes, nil
}

// GetStageHeader returns the referenced stage's header and the timestamp of when it was stored.
func (b StageStorageDisk) GetStageHeader(id StageID) (*StageHeader, int64, error) {
	// fetch it
	encodedHeader, err := b.db.Get(id[:], nil)
	if err == leveldb.ErrNotFound {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}

	// decode it
	return decodeStageHeader(encodedHeader)
}

// GetTransition returns a transition within a stage and the stage's header.
func (b StageStorageDisk) GetTransition(id StageID, index int) (
	*Transition, *StageHeader, error) {
	stageJson, err := b.GetStageBytes(id)
	if err != nil {
		return nil, nil, err
	}

	// pick out and unmarshal the transition at the index
	idx := "[" + strconv.Itoa(index) + "]"
	txJson, _, _, err := jsonparser.Get(stageJson, "transitions", idx)
	if err != nil {
		return nil, nil, err
	}
	tx := new(Transition)
	if err := json.Unmarshal(txJson, tx); err != nil {
		return nil, nil, err
	}

	// pick out and unmarshal the header
	hdrJson, _, _, err := jsonparser.Get(stageJson, "header")
	if err != nil {
		return nil, nil, err
	}
	header := new(StageHeader)
	if err := json.Unmarshal(hdrJson, header); err != nil {
		return nil, nil, err
	}
	return tx, header, nil
}

// Close is called to close any underlying storage.
func (b *StageStorageDisk) Close() error {
	return b.db.Close()
}

// leveldb schema: {bid} -> {timestamp}{gob encoded header}

func encodeStageHeader(header *StageHeader, when int64) ([]byte, error) {
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

func decodeStageHeader(encodedHeader []byte) (*StageHeader, int64, error) {
	buf := bytes.NewBuffer(encodedHeader)
	var when int64
	if err := binary.Read(buf, binary.BigEndian, &when); err != nil {
		return nil, 0, err
	}
	enc := gob.NewDecoder(buf)
	header := new(StageHeader)
	if err := enc.Decode(header); err != nil {
		return nil, 0, err
	}
	return header, when, nil
}
