package store

import (
	"fmt"
	"io"
	"os"
)

var _ Store = (*EnvStore)(nil)

type EnvStore struct {
}

// Store 会压缩文本，如果是结构数据请使用.json
func (l *EnvStore) Store(name string, data []byte, overwrite bool) error {
	if !overwrite {
		env := os.Getenv(name)
		if env != "" {
			fmt.Printf("%s exist\n", name)
		}
	}

	err := os.Setenv(name, string(data))
	if err != nil {
		return err
	}

	fmt.Printf("export %s=%s\n", name, data)
	return nil
}

func (l *EnvStore) Load(name string) ([]byte, error) {
	return []byte(os.Getenv(name)), nil
}

func (l *EnvStore) Exist(name string) (bool, error) {
	env := os.Getenv(name)
	return env != "", nil
}

func (l *EnvStore) Writer(name string) (io.WriteCloser, error) {
	return nil, nil
}

func (l *EnvStore) Reader(name string) (io.ReadCloser, error) {
	return nil, nil
}
