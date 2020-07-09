package goutil

import (
	"bytes"
	"crypto"
	_ "crypto/md5"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/hex"
	"hash/crc32"
	"io"
	"os"
	"strings"

	"github.com/pkg/errors"
)

type HashAlgo uint

const (
	MD5 HashAlgo = 1 + iota
	SHA1
	SHA224
	SHA256
	SHA384
	SHA512
	SHA512_224
	SHA512_256
)

var hashes = map[HashAlgo]crypto.Hash{
	MD5:        crypto.MD5,
	SHA1:       crypto.SHA1,
	SHA224:     crypto.SHA224,
	SHA256:     crypto.SHA256,
	SHA384:     crypto.SHA384,
	SHA512:     crypto.SHA512,
	SHA512_224: crypto.SHA512_224,
	SHA512_256: crypto.SHA512_256,
}

// Hash 计算哈希值，输入为byte slice
func Hash(algo HashAlgo, data []byte, rawOutput bool) ([]byte, error) {
	return HashReader(algo, bytes.NewReader(data), rawOutput)
}

// HashFile 计算文件的哈希值
func HashFile(algo HashAlgo, filename string, rawOutput bool) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer f.Close()
	return HashReader(algo, f, rawOutput)
}

// HashString 计算哈希值，输入为字符串
func HashString(algo HashAlgo, data string, rawOutput bool) (string, error) {
	res, err := HashReader(algo, strings.NewReader(data), rawOutput)
	return string(res), err
}

// HashReader 计算哈希值，输入为io.Reader
func HashReader(algo HashAlgo, rd io.Reader, rawOutput bool) ([]byte, error) {
	f, ok := hashes[algo]
	if !ok {
		return nil, errors.New("unknown hash function")
	}
	hash := f.New()
	_, err := io.Copy(hash, rd)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	result := hash.Sum(nil)
	if rawOutput {
		return result, nil
	}
	dst := make([]byte, hex.EncodedLen(len(result)))
	hex.Encode(dst, result)
	return dst, nil
}

// CRC32 计算CRC32
func CRC32(b []byte) uint32 {
	crc := crc32.NewIEEE()
	_, err := crc.Write(b)
	if err != nil {
		return 0
	}
	return crc.Sum32()
}
