package store

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

var _ Store = (*DiskStore)(nil)

type DiskStore struct {
}

func (l *DiskStore) Store(name string, data []byte, overwrite bool) error {
	if !overwrite {
		exist, err := l.Exist(name)
		if err != nil {
			return err
		}

		if exist {
			fmt.Printf("%s exist\n", name)
			return nil
		}
	}

	err := checkPath(filepath.Dir(name))
	if err != nil {
		return err
	}

	err = writeFile(name, data)
	if err != nil {
		return err
	}

	fmt.Printf("%s created successfully\n", name)
	return nil
}

func (l *DiskStore) Load(name string) ([]byte, error) {
	return os.ReadFile(name)
}

func (l *DiskStore) Exist(name string) (bool, error) {
	_, err := os.Stat(name)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func (l *DiskStore) Writer(name string) (io.WriteCloser, error) {
	err := checkPath(filepath.Dir(name))
	if err != nil {
		return nil, err
	}

	keystoreFile, err := os.Create(name)
	if err != nil {
		return nil, fmt.Errorf("failed to create keystore file: %v", err)
	}
	return keystoreFile, nil
}

func (l *DiskStore) Reader(name string) (io.ReadCloser, error) {
	ksFile, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("failed to open keystore file: %v", err)
	}

	return ksFile, nil
}

func checkPath(name string) error {
	stat, err := os.Stat(name)
	if err != nil {
		if os.IsNotExist(err) { // 目录不存在
			fmt.Printf("path: %s is not exist, preparing to create\n", name)
			err = os.MkdirAll(name, os.ModePerm) // 递归创建目录
			if err != nil {
				return err
			}

			fmt.Printf("path: %s created\n", name)
		} else {
			return err
		}
	} else if !stat.IsDir() {
		return fmt.Errorf("output path: %s is not a directory", name)
	}

	return nil
}

func writeFile(name string, data []byte) error {
	// 创建或打开文件
	file, err := os.Create(name)
	if err != nil {
		return fmt.Errorf("creating file err: %s", err)
	}
	defer file.Close()

	// 将 YAML 数据写入文件
	_, err = file.Write(data)
	if err != nil {
		return fmt.Errorf("writing file err: %s", err)
	}

	fmt.Println("file data written to file successfully, path: " + name)
	return nil
}
