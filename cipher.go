package goutil

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"github.com/pkg/errors"
)

// AesEncrypt AES加密
// text 为要加密的内容，key 为密钥，内部使用md5转为32字节的密钥（AES-256）
// 结果密文中，包含了16字节的CBC模式初始向量和32字节的HMAC-SHA256签名
// 结果: 16字节初始向量 + 密文 + 32字节签名
func AesEncrypt(text []byte, key []byte) ([]byte, error) {
	key, _ = Hash(MD5, key, false)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// 内容长度如果不是块大小的倍数，使用PKCS方式填充
	blockSize := block.BlockSize()
	text = pkcs5Padding(text, blockSize)

	// 第一个 blockSize 用于保存随机向量
	cipherText := make([]byte, blockSize+len(text))
	iv := cipherText[:blockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, errors.WithStack(err)
	}

	blockMode := cipher.NewCBCEncrypter(block, iv)
	blockMode.CryptBlocks(cipherText[blockSize:], text)

	// 末尾加上签名
	h := hmac.New(sha256.New, key)
	_, err = h.Write(cipherText)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return h.Sum(cipherText), nil
}

// AesDecrypt AES解密
// cipherText 密文，key 为加密使用的密钥
func AesDecrypt(cipherText []byte, key []byte) ([]byte, error) {
	key, _ = Hash(MD5, key, false)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	blockSize := block.BlockSize()

	if len(cipherText) < (sha256.Size + blockSize) {
		return nil, errors.New("cipher text invalid")
	}

	// 签名校验
	sign := cipherText[len(cipherText)-sha256.Size:]
	cipherText = cipherText[:len(cipherText)-sha256.Size]

	h := hmac.New(sha256.New, key)
	_, err = h.Write(cipherText)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if !hmac.Equal(sign, h.Sum(nil)) {
		return nil, errors.New("sign error")
	}

	iv := cipherText[:blockSize]
	cipherText = cipherText[blockSize:]
	text := make([]byte, len(cipherText))

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(text, cipherText)

	text = pkcs5UnPadding(text)
	return text, nil
}

func pkcs5Padding(text []byte, blockSize int) []byte {
	padding := blockSize - len(text)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(text, padText...)
}

func pkcs5UnPadding(cipherText []byte) []byte {
	length := len(cipherText)
	unPadding := int(cipherText[length-1])
	return cipherText[:(length - unPadding)]
}
