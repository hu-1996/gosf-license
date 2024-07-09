package store

import "io"

type Store interface {
	Store(name string, data []byte, overwrite bool) error
	Load(name string) ([]byte, error)
	Exist(name string) (bool, error)
	Writer(name string) (io.WriteCloser, error)
	Reader(name string) (io.ReadCloser, error)
}
