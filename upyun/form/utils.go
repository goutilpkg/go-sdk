package form

import (
	"crypto/md5"
	"fmt"
	"io"
	"os"
)

func SumStrMd5(str string) (string, error) {
	return fmt.Sprintf("%x", md5.Sum([]byte(str))), nil
}

func SumFileMd5(filename string) (string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	h := md5.New()
	io.Copy(h, f)
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
