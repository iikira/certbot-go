package certcfg

import (
	"github.com/iikira/configdir"
	"github.com/iikira/iikira-go-utils/utils/converter"
	"github.com/syndtr/goleveldb/leveldb"
	"log"
)

const (
	AppName = "certbot-go"
)

var (
	DB *leveldb.DB
)

func init() {
	var err error
	DB, err = leveldb.OpenFile(configdir.ConfigDir(AppName), nil)
	if err != nil {
		log.Fatalln(err)
	}
}

func Get(key string) ([]byte, error) {
	return DB.Get(converter.ToBytes(key), nil)
}

func Put(key string, value []byte) error {
	return DB.Put(converter.ToBytes(key), value, nil)
}
