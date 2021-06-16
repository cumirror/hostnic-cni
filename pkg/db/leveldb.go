package db

import (
	"encoding/json"
	"flag"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/yunify/hostnic-cni/pkg/constants"
	"github.com/yunify/hostnic-cni/pkg/log/logfields"
)

const (
	defaultDBPath = "/var/lib/hostnic"
)

var (
	log     = logrus.WithField(logfields.LogSubsys, "leveldb")
	LevelDB *leveldb.DB
)

type LevelDBOptions struct {
	dbpath string
}

func NewLevelDBOptions() *LevelDBOptions {
	return &LevelDBOptions{
		dbpath: defaultDBPath,
	}
}

func (opt *LevelDBOptions) AddFlags() {
	flag.StringVar(&opt.dbpath, "dbpath", defaultDBPath, "set leveldb path")
}

func SetupLevelDB(opt *LevelDBOptions) error {
	db, err := leveldb.OpenFile(opt.dbpath, nil)
	if err != nil {
		return fmt.Errorf("cannot open leveldb file %s : %v", opt.dbpath, err)
	}

	LevelDB = db

	return nil
}

func CloseDB() {
	err := LevelDB.Close()
	if err != nil {
		log.WithError(err).Error("failed to close leveldb")
	} else {
		log.Info("leveldb closed")
	}
}

func SetNetworkInfo(key string, info interface{}) error {
	value, _ := json.Marshal(info)
	return LevelDB.Put([]byte(key), value, nil)
}

func DeleteNetworkInfo(key string) error {
	err := LevelDB.Delete([]byte(key), nil)
	if err == leveldb.ErrNotFound {
		return constants.ErrNicNotFound
	}

	return err
}

func Iterator(fn func(info interface{}) error) error {
	iter := LevelDB.NewIterator(nil, nil)
	for iter.Next() {
		// Remember that the contents of the returned slice should not be modified, and
		// only valid until the next call to Next.
		fn(iter.Value())
	}
	iter.Release()

	return iter.Error()
}
